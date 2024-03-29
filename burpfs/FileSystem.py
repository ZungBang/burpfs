#! /usr/bin/env python

# BurpFS - Burp Filesystem in USErspace
# Copyright (C) 2012-2021 Avi Rozen <avi.rozen@gmail.com>
#
# This file is part of BurpFS.
#
# BurpFS is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

__version__ = '0.4.0'

import os
import sys
import subprocess
import stat
import errno
import copy
import tempfile
import shutil
import threading
import traceback
import fcntl
import time
import re
import json
import struct
import unicodedata
from datetime import datetime
from bisect import bisect_left, bisect_right

# incantation to avoid import errors
# https://stackoverflow.com/a/56120695
try:
    from .LogFile import logging, LOGGING_LEVELS, LogFile
except (ValueError, ImportError):
    from LogFile import logging, LOGGING_LEVELS, LogFile

import fuse
from fuse import Fuse, FuseOptParse

if not hasattr(fuse, '__version__'):
    raise RuntimeError(
        "your fuse-py doesn't know of fuse.__version__, probably it's too old")

fuse.fuse_python_api = (0, 2)

fuse.feature_assert('stateful_files', 'has_init')


def flag2mode(flags):
    '''
    taken from python-fuse xmp.py example
    '''
    md = {os.O_RDONLY: 'r', os.O_WRONLY: 'w', os.O_RDWR: 'w+'}
    m = md[flags & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR)]

    if flags | os.O_APPEND:
        m = m.replace('w', 'a', 1)

    return m


def makedirs(path):
    '''
    create path like mkdir -p
    taken from: http://stackoverflow.com/questions/600268/mkdir-p-functionality-in-python/600612#600612
    '''
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            pass
        else:
            raise


def totimestamp(dt, epoch=datetime(1970, 1, 1)):
    '''
    convert datetime to (UTC) timestamp
    adapted from: http://stackoverflow.com/a/8778548/27831
    '''
    td = dt - epoch
    return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 1e6


# _decode_list and _decode_dict below are used to convince the JSON
# parser (json.loads) to avoid coercing everything into unicode under
# Python 2.x
# taken from:
# http://stackoverflow.com/a/6633651

def _decode_list(data):
    rv = []
    for item in data:
        if isinstance(item, unicode):
            item = item.encode('utf-8')
        elif isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
        rv.append(item)
    return rv


def _decode_dict(data):
    rv = {}
    for key, value in data.items():
        if isinstance(key, unicode):
            key = key.encode('utf-8')
        if isinstance(value, unicode):
            value = value.encode('utf-8')
        elif isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value
    return rv


# cut unicode string to specific byte string length
# adapted from:
# https://stackoverflow.com/a/13665637

LENGTH_BY_PREFIX = [
    (0xC0, 2),  # first byte mask, total codepoint length
    (0xE0, 3),
    (0xF0, 4),
    (0xF8, 5),
    (0xFC, 6),
]


def codepoint_length(first_byte):
    for mask, length in LENGTH_BY_PREFIX:
        if first_byte & mask == mask:
            return length
    return 1  # ascii or invalid byte


def cut_unicode_to_bytes_length(unicode_text, byte_limit):
    utf8_bytes = unicode_text.encode('utf-8')
    cut_index = 0
    while cut_index < len(utf8_bytes):
        codepoint_1st = utf8_bytes[cut_index]
        if isinstance(codepoint_1st, str):
            codepoint_1st = ord(codepoint_1st)
        step = codepoint_length(codepoint_1st)
        if cut_index + step > byte_limit:
            # can't go a whole codepoint further, time to cut
            return utf8_bytes[:cut_index].decode('utf-8')
        else:
            cut_index += step
    # length limit is longer than our bytes strung, so no cutting
    return unicode_text


class FileSystem(Fuse):

    datetime_format = '%Y-%m-%d %H:%M:%S'

    null_stat = fuse.Stat(st_mode=stat.S_IFDIR | 0o755,
                          st_ino=0,
                          st_dev=0,
                          st_nlink=2,
                          st_uid=0,
                          st_gid=0,
                          st_size=0,
                          st_atime=0,
                          st_mtime=0,
                          st_ctime=0,
                          st_blksize=0,
                          st_rdev=0)

    fuse_stat_fields = [attr for attr in dir(null_stat)
                        if attr.startswith('st_')]

    xattr_prefix = 'user.burpfs.'

    xattr_fields = []

    xattr_fields_root = ['burp',
                         'conf',
                         'client',
                         'backup',
                         'datetime']

    xattr_fields_burp = ['regex',
                         'state',
                         'pending']

    xattr_fields_cache = ['prefix',
                          'num_files',
                          'max_num_files',
                          'total_size',
                          'max_total_size']

    burp_done = {'regex': None,
                 'state': 'idle'}

    vss_header_format = '<iiqi'

    vss_header_size = struct.calcsize(vss_header_format)  # 20

    class _Entry:
        def __init__(self,
                     fs,
                     path,
                     stat=None,
                     link_target=None,
                     under_root=False,
                     hardlink=False):
            self.path = path
            self.stat = stat if stat else copy.deepcopy(FileSystem.null_stat)
            self.link_target = link_target
            self.under_root = under_root
            self.hardlink = hardlink
            self.refcount = 0
            self.queued_for_removal = False
            self.vss_overhead = 0
            self.vss_offset = 0
            # zero negative timestamps
            for a in ['st_atime', 'st_mtime', 'st_ctime']:
                t = getattr(self.stat, a)
                if t < 0:
                    fs.logger.warning(
                        '%s has negative timestamp %s=%d, will use 0' %
                        (path, a, t))
                    setattr(self.stat, a, 0)

    class _Cache:
        '''
        Implementation of a file cache with LRU removal policy

        Files are restored to the cache when first opened for reading,
        and we impose a "soft" limit on both the number of cached
        files and their total size.

        By "soft" we mean that we allow files to be opened even if the
        cache limits have been exceeded, and we only attempt to impose
        the limits by removing closed files from the cache.
        '''

        path_regex_size_limit = 255

        def __init__(self, fs):
            self.fs = fs
            self.num_files = 0
            self.max_num_files = int(fs.cache_num_files)
            self.total_size = 0
            self.max_total_size = int(fs.cache_total_size) * 1024 * 1024
            self.queue = []
            self.prefix = tempfile.mkdtemp(prefix='burpfs-')
            self.path = os.path.normpath(self.prefix + '/files')
            makedirs(self.path)

        def __del__(self):
            self.fs.logger.debug('removing cache directory: %s' %
                                 self.prefix)
            shutil.rmtree(self.prefix, ignore_errors=True)

        def _path2regex(self, path):
            '''
            convert path to regex for burp to extract

            In order to specifically match just the given path we need
            only return ^path$ as the regex. But we also need to
            sanitize the path string for various reasons, so we run
            the risk that burp will extract more files than we intend.
            '''
            if sys.version_info.major < 3:
                # path should be valid utf-8 (encoded as such)
                upath = path.decode('utf-8')
            else:
                # python3: unicode to begin with
                upath = path

            # sanitation:
            #
            # 1) replace single quote/back-quote and control
            #    characters with '.' (regex wildcard character)
            #    because these characters do not seem to play well
            #    with Python's Popen
            #
            # 2) prevent path from being interpreted as regex
            #
            # 3) limit utf8 encoded regex length to 255 bytes

            # replace bad characters with new line characters
            r = u''.join(u'\n' if (c in u"'`" or
                                   unicodedata.category(c) == 'Cc')
                         else c for c in upath)
            # escape special characters to prevent path from being
            # interpreted itself as a (possibly invalid) regex
            r = re.escape(r)
            # replace escaped new lines with a dot (this dance allows
            # this logic to work with both Python2 and 3, since
            # re.escape has changed behavior, between versions)
            r = r.replace(u'\\\n', u'.')
            # now cut the path so that the regex fits into a byte
            # string of 255 bytes:
            # does it fit?
            if r != cut_unicode_to_bytes_length(r, self.path_regex_size_limit - 2):
                # no - remove two more characters to make room for the
                # wildcard '.*'
                r = cut_unicode_to_bytes_length(r, self.path_regex_size_limit - 4)
                # remove any trailing back-slashes, just in case we
                # removed part of an escape sequence that we
                # introduced with re.escape above
                r = r.rstrip(u'\\')
                # match whatever we removed
                r += u'.*'

            # finally make sure we match the whole path
            r = u'^' + r + u'$'
            if sys.version_info.major < 3:
                r = r.encode('utf-8')
            return r

        def find(self, path):
            '''
            return path in cache corresponding to input path and boolean
            that's true if the path was found in cache
            may return up to two paths in case path is a hard link
            '''
            realpath = os.path.normpath(self.path + '/' + path)
            head, tail = self.fs._split(path)
            # sanity check: path should not be a directory
            if tail == '':
                raise RuntimeError('trying to extract a directory %s' % path)
            # check that path exists in file list
            if head not in self.fs.dirs or tail not in self.fs.dirs[head]:
                return None, None, False
            # return if file has already been extracted
            bs = self.fs.getattr(path)
            if os.path.exists(realpath) or os.path.lexists(realpath):
                # make sure that stat info of realpath matches path
                s = os.lstat(realpath)
                conds = [getattr(s, attr) == getattr(bs, attr)
                         for attr in ['st_mode',
                                      'st_uid',
                                      'st_gid',
                                      'st_mtime']]
                if (all(conds) and
                    s.st_size == bs.st_size + self.fs.dirs[head][tail].vss_overhead):
                    return [realpath], None, True

            realpaths = [realpath]
            regexs = []
            # build regex for burp
            item_path = path if self.fs.dirs[head][tail].under_root else path[1:]
            regexs.append(self._path2regex(item_path))

            # we need to extract the file
            # but, if it's a hard-link we must also make sure the link target
            # exists or is extracted before
            if self.fs.dirs[head][tail].hardlink:
                link_path = self.fs.dirs[head][tail].link_target
                link_realpaths, link_regexs, link_found = self.find(link_path)
                if not link_found and link_regexs:
                    realpaths = link_realpaths + realpaths
                    regexs = link_regexs + regexs

            return realpaths, regexs, False

        def open(self, path):
            '''
            update file and cache reference counts and sizes
            '''
            head, tail = self.fs._split(path)
            self.fs.dirs[head][tail].refcount += 1
            # has this file just been extracted?
            if (self.fs.dirs[head][tail].refcount == 1 and
                not self.fs.dirs[head][tail].queued_for_removal):
                # yes: update cache
                self.num_files += 1
                self.total_size += self.fs.dirs[head][tail].stat.st_size
            # remove item from queue
            head_tail_pair = (head, tail)
            try:
                self.queue.remove(head_tail_pair)
            except ValueError:
                pass
            self.fs.dirs[head][tail].queued_for_removal = False

        def close(self, path):
            '''
            update files in cache and maybe remove least recently used
            files from cache if cache limits on number of files and/or
            total size have been exceeded
            '''
            self.fs._extract_lock.acquire()
            head, tail = self.fs._split(path)
            self.fs.dirs[head][tail].refcount -= 1
            assert(self.fs.dirs[head][tail].refcount >= 0)
            # are there any more references to this file?
            if self.fs.dirs[head][tail].refcount == 0:
                # ... no: add closed file to LRU queue
                head_tail_pair = (head, tail)
                # file may already be in the removal queue, so
                # we first attempt to remove it from the queue
                try:
                    self.queue.remove(head_tail_pair)
                except ValueError:
                    pass
                self.queue.append(head_tail_pair)
                self.fs.dirs[head][tail].queued_for_removal = True
                # evict closed files from cache until cache limits are met
                while (self.queue and
                       (self.num_files > self.max_num_files or
                        self.total_size > self.max_total_size)):
                    rm_head, rm_tail = self.queue.pop(0)
                    assert(self.fs.dirs[rm_head][rm_tail].queued_for_removal)
                    self.fs.dirs[rm_head][rm_tail].queued_for_removal = False
                    # can we evict this file from the cache?
                    if self.fs.dirs[rm_head][rm_tail].refcount == 0:
                        # ... yes: delete the file from disk
                        realpath = os.path.normpath('/'.join([self.path, rm_head, rm_tail]))
                        try:
                            os.remove(realpath)
                        except:
                            pass
                        # we update counters even if we failed to remove the file
                        self.num_files -= 1
                        self.total_size -= self.fs.dirs[rm_head][rm_tail].stat.st_size
            assert(self.num_files >= 0)
            assert(self.total_size >= 0)
            self.fs._extract_lock.release()

    def __init__(self, *args, **kw):
        '''
        Initialize filesystem
        '''

        self._extract_lock = threading.Lock()
        self._burp_status_lock = threading.Lock()
        self._initialized = False

        # default option values
        self.logging = 'info'
        self.syslog = False
        self.burp = 'burp'
        self.conf = '/etc/burp/burp.conf'
        self.client = ''
        self.backup = None
        self.datetime = None
        self.diff = False
        self.cache = None
        self.cache_num_files = 768
        self.cache_total_size = 100
        self.move_root = False
        self.use_ino = False
        self.max_ino = 0
        self.dirs = {'/': {'': FileSystem._Entry(self, '/')}}

        self._burp_status = copy.deepcopy(FileSystem.burp_done)
        self._burp_status['pending'] = 0

        class File (FileSystem._File):
            def __init__(self2, *a, **kw):
                FileSystem._File.__init__(self2, self, *a, **kw)

        self.file_class = File

        Fuse.__init__(self, *args, **kw)

    def _split(self, path):
        '''
        os.path.split wrapper
        '''
        head, tail = os.path.split(path)
        if head and not head.endswith('/'):
            head += '/'
        return head, tail

    def _add_parent_dirs(self, path):
        '''
        add parent directories of path to dirs dictionary
        '''
        head, tail = self._split(path[:-1])
        if not head or head == path:
            return
        if head not in self.dirs:
            self.dirs[head] = {tail: FileSystem._Entry(self, path)}
        elif tail not in self.dirs[head]:
            self.dirs[head][tail] = FileSystem._Entry(self, path)
        self._add_parent_dirs(head)

    def _update_inodes(self, head):
        '''
        generate unique st_ino for each missing st_ino
        '''
        for tail in self.dirs[head]:
            if self.dirs[head][tail].stat.st_ino == 0:
                self.max_ino += 1
                self.dirs[head][tail].stat.st_ino = self.max_ino
            subdir = '%s%s/' % (head, tail)
            if subdir in self.dirs:
                self._update_inodes(subdir)

    def _vss_parse(self, realpath, path):
        '''
        parse vss headers of realpath, cache results,
        return base offset and size overhead

        vss headers are win32 stream id structures
        https://msdn.microsoft.com/en-us/library/windows/desktop/aa362667.aspx
        '''
        head, tail = self._split(path)
        if head not in self.dirs or tail not in self.dirs[head]:
            return 0, 0
        if (not self.dirs[head][tail].under_root and
            self.dirs[head][tail].vss_overhead == 0 and
            self.dirs[head][tail].vss_offset == 0 and
            os.path.exists(realpath)):
            s = os.lstat(realpath)
            bs = self.getattr(path)
            if (s.st_size >= FileSystem.vss_header_size and
                s.st_size > bs.st_size):
                self.logger.debug('parsing vss headers of "%s"' % path)
                with open(realpath, 'rb') as f:
                    offset = 0
                    overhead = 0
                    while True:
                        vss_header = f.read(FileSystem.vss_header_size)
                        if len(vss_header) < FileSystem.vss_header_size:
                            break
                        offset += FileSystem.vss_header_size
                        overhead += FileSystem.vss_header_size
                        (sid, sattr, ssize, sname_size) = struct.unpack(FileSystem.vss_header_format, vss_header)
                        self.logger.debug('vss header at offset %d: id=%d attr=%d size=%d, name size=%d' %
                                          (offset - FileSystem.vss_header_size, sid, sattr, ssize, sname_size))
                        offset += sname_size
                        overhead += sname_size
                        if (self.dirs[head][tail].vss_offset == 0 and
                            sid == 1 and
                            ssize == bs.st_size and
                            offset + ssize <= s.st_size):
                            self.logger.debug('setting offset of file data as %d' % offset)
                            self.dirs[head][tail].vss_offset = offset
                            overhead -= ssize
                        offset += ssize
                        overhead += ssize
                        if offset <= 0 or offset > s.st_size:
                            self.logger.debug('bad offset %d - bailing out' % offset)
                            self.dirs[head][tail].vss_offset = 0
                            break
                        f.seek(offset)
                    if self.dirs[head][tail].vss_offset > 0:
                        if overhead + bs.st_size == s.st_size:
                            self.logger.debug('setting vss header size overhead as %d' % overhead)
                            self.dirs[head][tail].vss_overhead = overhead
                        else:
                            self.logger.debug('bad overhead %d - offset set to 0' % overhead)
                            self.dirs[head][tail].vss_offset = 0
        return self.dirs[head][tail].vss_offset, self.dirs[head][tail].vss_overhead

    def _extract(self, path_list):
        '''
        extract path list from storage, returns path list of extracted files
        '''

        nitems = len(path_list)
        self._burp_increment_counter('pending', nitems)

        # serialize extractions
        self._extract_lock.acquire()

        items = []
        realpath_list = []

        for path in path_list:
            realpaths, path_regexs, found = self.cache.find(path)
            if not realpaths:
                continue
            realpath_list.extend(realpaths)
            self.cache.open(path)
            if not found:
                items.extend(path_regexs)

        if len(items) > 0:
            self._burp(items)

        self._extract_lock.release()
        self._burp_increment_counter('pending', -nitems)

        return realpath_list

    def _burp_set_status(self, status):
        '''
        thread safe modification of burp status dict
        '''
        self._burp_status_lock.acquire()
        for key in status:
            self._burp_status[key] = status[key]
        self._burp_status_lock.release()

    def _burp_increment_counter(self, counter, n):
        '''
        thread safe modification of burp counters
        '''
        self._burp_status_lock.acquire()
        self._burp_status[counter] += n
        self._burp_status_lock.release()

    def _burp_get_status(self):
        '''
        thread safe access to burp status dict
        '''
        self._burp_status_lock.acquire()
        status = copy.deepcopy(self._burp_status)
        self._burp_status_lock.release()
        return status

    def _burp_flock(self):
        '''
        lock the storage daemon configuration file
        '''
        # we allow locking to fail, so as to allow
        # at least a single instance of burpfs,
        # even if we can't lock the conf file
        try:
            f = open(self.conf, 'r')
            fcntl.flock(f, fcntl.LOCK_EX)
            return f
        except:
            self.logger.warning(traceback.format_exc())
            return None

    def _burp_funlock(self, f):
        '''
        unlock the file f
        '''
        if not f:
            return
        try:
            fcntl.flock(f, fcntl.LOCK_UN)
            f.close()
        except:
            self.logger.warning(traceback.format_exc())

    def _burp(self, items):
        '''
        restore list of items from Burp backup
        '''
        # we serialize calls to burp across instances of burpfs
        # by locking the configuration file
        # (note that this may not work over NFS)
        f = self._burp_flock()
        cmd_prefix = [self.burp, '-c', self.conf]
        if self.client:
            cmd_prefix += ['-C', self.client]
        cmd_prefix += ['-a', 'r', '-f', '-b', str(self.backup), '-d', self.cache.path, '-r']
        for item in items:
            cmd = cmd_prefix + [item]
            self.logger.debug('$ %s' % ' '.join(cmd))
            self._burp_set_status({'regex': item,
                                   'state': 'run'})
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            if sys.version_info.major >= 3:
                stdout = stdout.decode('utf-8')
                stderr = stderr.decode('utf-8')
            self.logger.debug('%s%s' % (stdout, stderr))
        self._burp_set_status(FileSystem.burp_done)
        # unlock the configuration file
        self._burp_funlock(f)

    def _setup_logging(self):
        '''
        initialize logging facility
        '''
        # log messages are sent to both console and syslog
        # use -o logging=level to set the log level
        # use -o syslog to enable logging to syslog
        self.logger = logging.getLogger('BurpFS')
        self.loglevel = LOGGING_LEVELS.get(self.logging, logging.NOTSET)
        self.logger.setLevel(self.loglevel)
        h = logging.StreamHandler()
        h.setLevel(self.loglevel)
        formatter = logging.Formatter("%(message)s")
        h.setFormatter(formatter)
        self.logger.addHandler(h)
        if self.syslog:
            try:
                h = logging.handlers.SysLogHandler('/dev/log')
                h.setLevel(self.loglevel)
                formatter = logging.Formatter(
                    "%(name)s[%(process)d]: %(levelname)-8s - %(message)s")
                h.setFormatter(formatter)
                self.logger.addHandler(h)
            except:
                self.logger.warning(traceback.format_exc())
        self.logfile = LogFile(self.logger, logging.DEBUG)

    def _list_files(self, client, backup, timespec):
        '''
        get list of files in backup
        '''
        cmd_prefix = [self.burp, '-c', self.conf]
        if client:
            cmd_prefix += ['-C', client]
        elif self.parser.burp_version() >= '2':
            # deduce client name
            with open(self.conf, 'r') as conf:
                for line in conf:
                    match = re.search(r'^\s*cname\s*=\s*([^\s]*)', line)
                    if match:
                        client = '%s' % match.group(1)
                        break

        cmd = cmd_prefix + ['-a', 'l']
        self.logger.debug('Getting list of backups with: %s' % ' '.join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        if sys.version_info.major >= 3:
            stdout = stdout.decode('utf-8')
            stderr = stderr.decode('utf-8')
        self.logger.debug('%s' % stdout)
        matches = re.finditer((r'^Backup: ([0-9]{7}) ' +
                               r'([0-9]{4})-([0-9]{2})-([0-9]{2}) ' +
                               r'([0-9]{2}):([0-9]{2}):([0-9]{2})' +
                               r'(?! .*\(working\))'),
                              stdout, re.MULTILINE)
        if matches:
            available_backups = [
                (int(match.group(1)),
                 datetime.strptime(
                        '%s-%s-%s %s:%s:%s' % (match.group(2),
                                               match.group(3),
                                               match.group(4),
                                               match.group(5),
                                               match.group(6),
                                               match.group(7)),
                        FileSystem.datetime_format)) for match in matches
                ]

        if not matches or not available_backups:
            self.logger.error('%s%s' % (stdout, stderr))
            raise RuntimeError('cannot determine list of available backups')

        backup_ids, backup_dates = list(zip(*available_backups))
        ibackup = None
        nbackup = None

        if backup:
            ibackup = int(backup)
            nbackup = bisect_left(backup_ids, ibackup)
            if nbackup == len(backup_ids) or backup_ids[nbackup] != ibackup:
                raise ValueError('backup must be one of %s' % repr(backup_ids))
        else:
            ibackup = backup_ids[-1]  # latest (assume list is sorted by date)
            nbackup = -1
            if timespec:
                query_date = datetime.strptime(timespec, FileSystem.datetime_format)
                nbackup = bisect_right(backup_dates, query_date)
                if not nbackup:
                    raise RuntimeError('no backup found upto %s' % query_date)
                nbackup -= 1
                ibackup = backup_ids[nbackup]

        if not ibackup:
            raise RuntimeError('could not determine backup number')

        backup_date = datetime.strftime(backup_dates[nbackup], FileSystem.datetime_format)
        self.logger.info('Backup: %07d %s' % (ibackup, backup_date))

        if self.parser.burp_version() >= '2':
            cmd = cmd_prefix + ['-a', 'm']
            self.logger.debug('Querying burp monitor for list of files in backup with: %s' % ' '.join(cmd))
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            inp = 'j:pretty-print-off'
            self.logger.debug(inp)
            p.stdin.write(('%s\n' % inp).encode('utf-8'))
            p.stdin.flush()
            ready = False
            while p.poll() is None and not ready:
                line = p.stdout.readline().decode('utf-8').rstrip('\n')
                self.logger.debug(line)
                ready = 'pretty print off' in line.lower()
            if not ready:
                raise RuntimeError('burp monitor terminated - please verify that the server is configured to allow remote status monitor (hint: "status_address=::")')
            inp = 'c:%s:b:%d:p:*' % (client, ibackup)
            self.logger.debug(inp)
            p.stdin.write(('%s\n' % inp).encode('utf-8'))
            p.stdin.flush()
            json_string = p.stdout.readline().decode('utf-8')
            p.stdin.close()
        else:
            cmd = cmd_prefix + ['-b', '%d' % ibackup, '-a', 'L', '-j']
            self.logger.debug('Getting list of files in backup with: %s' % ' '.join(cmd))
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            json_string = '\n'.join(
                [line for line in stdout.splitlines()
                 if not re.match(('^([0-9]{4})-([0-9]{2})-([0-9]{2}) ' +
                                  '([0-9]{2}):([0-9]{2}):([0-9]{2}):.*'), line)])

        if sys.version_info.major < 3:
            backup = json.loads(json_string, object_hook=_decode_dict, strict=False)
        else:
            backup = json.loads(json_string, strict=False)
        if self.parser.burp_version() >= '2':
            # burp 2.x.x
            files = backup['clients'][0]['backups'][0]['browse']['entries']
        elif 'backups' in backup:
            # burp 1.4.x
            files = backup['backups'][0]['items']
        else:
            # burp 1.3.x
            files = backup['items']

        diff_epoch = 0
        if nbackup != 0 and len(backup_dates) > 1:
            diff_epoch = time.mktime(backup_dates[nbackup - 1].timetuple())

        return files, ibackup, backup_date, diff_epoch

    def _json_to_stat(self, item):
        '''
        convert JSON file entry tokens into file stat structure
        '''
        st = fuse.Stat(st_mode=item[self.stat_field_prefix + 'mode'],
                       st_ino=item[self.stat_field_prefix + 'ino'],
                       st_dev=item[self.stat_field_prefix + 'dev'],
                       st_nlink=item[self.stat_field_prefix + 'nlink'],
                       st_uid=item[self.stat_field_prefix + 'uid'],
                       st_gid=item[self.stat_field_prefix + 'gid'],
                       st_size=item[self.stat_field_prefix + 'size'],
                       st_atime=item[self.stat_field_prefix + 'atime'],
                       st_mtime=item[self.stat_field_prefix + 'mtime'],
                       st_ctime=item[self.stat_field_prefix + 'ctime'],
                       st_blksize=0,
                       st_rdev=0)
        return st

    def _create_file_entry(self, item):
        '''
        create file entry tuple from a JSON file entry
        also splits file path into head and tail
        '''
        path = item['name']
        if not path.startswith('/'):
            path = '/' + path
            under_root = False
        else:
            under_root = True
        head, tail = self._split(path)
        target = item['link'] if len(item['link']) > 0 else None
        hardlink = (target is not None) and (not stat.S_ISLNK(item[self.stat_field_prefix + 'mode']))
        entry = FileSystem._Entry(self,
                                  path,
                                  stat=self._json_to_stat(item),
                                  link_target=target,
                                  under_root=under_root,
                                  hardlink=hardlink)
        return head, tail, entry

    def initialize(self):
        '''
        initialize file list
        '''

        self._setup_logging()

        self.logger.info('Populating file system ... ')
        self.cache = FileSystem._Cache(self)
        self.stat_field_prefix = '' if self.parser.burp_version() >= '2' else 'st_'

        # test access to burp conf file
        open(self.conf, 'r').close()

        # get list of files in backup
        files, backup, timespec, diff_epoch = self._list_files(self.client,
                                                               self.backup,
                                                               self.datetime)
        # validated values
        self.backup = backup
        self.datetime = timespec

        # are we using inode numbers
        self.use_ino = 'use_ino' in self.fuse_args.optlist

        # build dirs data structure
        num_entries = 0
        for file in files:
            head, tail, entry = self._create_file_entry(file)
            path = head + tail
            # find max st_ino
            if self.use_ino:
                if entry.stat.st_ino > self.max_ino:
                    self.max_ino = entry.stat.st_ino
            # new directory
            if head not in self.dirs:
                self.dirs[head] = {}
            # is entry a directory itself?
            isdirectory = stat.S_ISDIR(entry.stat.st_mode)
            if (isdirectory and
                path + '/' not in self.dirs):
                self.dirs[path + '/'] = {}
            # add parent directories
            self._add_parent_dirs(head)
            # maybe skip unmodified files
            if (self.diff and
                not isdirectory and
                entry.stat.st_mtime < diff_epoch):
                continue
            # and finally
            self.dirs[head][tail] = entry
            if entry.stat.st_mtime >= diff_epoch:
                num_entries += 1

        # fix st_ino
        if self.use_ino:
            self._update_inodes('/')

        self.logger.debug('Cache directory is: %s' % self.cache.prefix)
        if not self.diff:
            self.logger.info('BurpFS ready (%d items).' % len(files))
        else:
            self.logger.info('BurpFS ready (%d modified items out of %d).' % (num_entries, len(files)))

        self._initialized = True

    def shutdown(self):
        '''
        remove cache directory if required
        '''
        if self.cache:
            del self.cache

    def setxattr(self, path, name, value, flags):
        '''
        set value of extended attribute
        '''
        return -errno.EOPNOTSUPP

    def getxattr(self, path, name, size):
        '''
        get value of extended attribute
        burpfs exposes some filesystem attributes for the root directory
        (e.g. backup number, cache prefix - see FileSystem.xattr_fields_root)
        and may also expose several other attributes for each file/directory
        in the future (see FileSystem.xattr_fields)
        '''
        head, tail = self._split(path)
        val = None
        n = name.replace(FileSystem.xattr_prefix, '')
        if path == '/':
            if n in FileSystem.xattr_fields_root:
                val = str(getattr(self, n))
            elif n.startswith('burp.'):
                n = n.replace('burp.', '')
                if n in FileSystem.xattr_fields_burp:
                    val = str(self._burp_get_status()[n])
            elif n.startswith('cache.'):
                n = n.replace('cache.', '')
                if n in FileSystem.xattr_fields_cache:
                    val = str(getattr(self.cache, n))
        if (not val and head in self.dirs and tail in self.dirs[head] and
            n in FileSystem.xattr_fields):
            # place holder in case we add xattrs
            pass
        # attribute not found
        if val is None:
            return -errno.ENODATA
        # We are asked for size of the value.
        if size == 0:
            return len(val)
        return val

    def listxattr(self, path, size):
        '''
        list extended attributes
        '''
        head, tail = self._split(path)
        xattrs = []
        if path == '/':
            xattrs += [FileSystem.xattr_prefix +
                       a for a in FileSystem.xattr_fields_root]
            xattrs += [FileSystem.xattr_prefix + 'burp.' +
                       a for a in FileSystem.xattr_fields_burp]
            xattrs += [FileSystem.xattr_prefix + 'cache.' +
                       a for a in FileSystem.xattr_fields_cache]
        if head in self.dirs and tail in self.dirs[head]:
            xattrs += [FileSystem.xattr_prefix +
                       a for a in FileSystem.xattr_fields]
        # We are asked for size of the attr list, ie. joint size of attrs
        # plus null separators.
        if size == 0:
            return len("".join(xattrs)) + len(xattrs)
        return xattrs

    def getattr(self, path):
        '''
        Retrieve file attributes.
        '''
        head, tail = self._split(path)
        if head in self.dirs and tail in self.dirs[head]:
            return self.dirs[head][tail].stat
        else:
            return -errno.ENOENT

    def readdir(self, path, offset):
        '''
        read directory entries
        '''
        path = path if path.endswith('/') else path + '/'
        for key in ['.', '..']:
            yield fuse.Direntry(key)
        for key in list(self.dirs[path].keys()):
            if len(key) > 0:
                if self.use_ino:
                    bs = self.getattr(path + key)
                    ino = bs.st_ino
                else:
                    ino = 0
                yield fuse.Direntry(key, ino=ino)

    def readlink(self, path):
        '''
        read link contents
        '''
        head, tail = self._split(path)
        link = self.dirs[head][tail].link_target
        if link:
            if self.move_root and link.startswith('/'):
                link = os.path.normpath(self.fuse_args.mountpoint + link)
            return link
        return -errno.ENOENT

    class _File(object):
        def __init__(self, fs, path, flags, *mode):
            self.fs = fs
            accmode = os.O_RDONLY | os.O_WRONLY | os.O_RDWR
            if (flags & accmode) != os.O_RDONLY:
                raise IOError(errno.EACCES, '')
            self.path = path
            self.realpath = fs._extract([path])[0]
            self.vss_offset, self.vss_overhead = fs._vss_parse(self.realpath, path)
            self.file = os.fdopen(os.open(self.realpath, flags, *mode),
                                  flag2mode(flags)+'b')
            self.fd = self.file.fileno()
            self.direct_io = False
            self.keep_cache = True

        def read(self, length, offset):
            self.file.seek(offset + self.vss_offset)
            return self.file.read(length)

        def release(self, flags):
            self.file.close()
            self.fs.cache.close(self.path)


class BurpFuseOptParse(FuseOptParse):
    '''
    We subclass FuseOptParse just so that we can honor the -o burp
    command line option
    '''
    def __init__(self, *args, **kw):
        self._burp_version = None
        FuseOptParse.__init__(self, *args, **kw)

    def get_version(self):
        return ("BurpFS version: %s\nburp version: %s\n"
                "Python FUSE version: %s" %
                (__version__, self.burp_version(), fuse.__version__))

    def burp_version(self):
        '''
        return version string of burp,
        return None if not runnable or version cannot be parsed
        '''
        if not self._burp_version:
            try:
                # burp version command line option changed from -v to
                # -V on 2.2.12 so we try both ...
                for version_opt in ['v', 'V']:
                    cmd = [self.values.burp, '-c', self.values.conf, '-%s' % version_opt]
                    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = p.communicate()
                    if sys.version_info.major >= 3:
                        stdout = stdout.decode('utf-8')
                        stderr = stderr.decode('utf-8')
                    match = re.search('burp-(.*)\n$', stdout)
                    if match:
                        self._burp_version = '%s' % match.group(1)
                        break
            except:
                # traceback.print_exc()
                pass
        return self._burp_version


def main():

    usage = """
BurpFS: exposes the Burp backup storage as a Filesystem in USErspace

""" + Fuse.fusage

    # force -o sync_read
    sys.argv.extend(['-o', 'sync_read'])

    server = FileSystem(
        version=__version__,
        parser_class=BurpFuseOptParse,
        usage=usage)

    server.multithreaded = True

    server.parser.add_option(mountopt="burp",
                             metavar="PATH",
                             default=server.burp,
                             help=("path to burp executable "
                                   "[default: %default]"))
    server.parser.add_option(mountopt="conf",
                             metavar="PATH",
                             default=server.conf,
                             help=("client configuration file "
                                   "[default: %default]"))
    server.parser.add_option(mountopt="client",
                             metavar="CNAME",
                             default=server.client,
                             help=("client cname "
                                   "[default: local client]"))
    server.parser.add_option(mountopt="backup",
                             metavar="BACKUP",
                             default=server.backup,
                             help=("backup number "
                                   "[default: the most recent backup]"))
    server.parser.add_option(mountopt="datetime",
                             metavar="'YYYY-MM-DD hh:mm:ss'",
                             default=server.datetime,
                             help="backup snapshot date/time [default: now]")
    server.parser.add_option(mountopt="diff",
                             action="store_true",
                             default=server.diff,
                             help=("populate file system only with "
                                   "modified/new files [default: %default]"))
    server.parser.add_option(mountopt="cache_num_files",
                             metavar="N",
                             default=server.cache_num_files,
                             help=("maximal number of files in cache "
                                   "[default: %default]"))
    server.parser.add_option(mountopt="cache_total_size",
                             metavar="MB",
                             default=server.cache_total_size,
                             help=("maximal total size (MB) of files in cache "
                                   "[default: %default]"))
    server.parser.add_option(mountopt="move_root",
                             action="store_true",
                             default=server.move_root,
                             help=("make absolute path symlinks point to path "
                                   "under mount point  [default: %default]"))
    server.parser.add_option(mountopt="logging",
                             choices=list(LOGGING_LEVELS.keys()),
                             metavar='|'.join(list(LOGGING_LEVELS.keys())),
                             default=server.logging,
                             help="logging level [default: %default]")
    server.parser.add_option(mountopt="syslog",
                             action="store_true",
                             default=server.syslog,
                             help=("log to both syslog and console [default: "
                                   "%default]"))

    server.parse(values=server, errex=1)

    if server.fuse_args.mount_expected():
        if not server.parser.burp_version():
            raise RuntimeError('cannot determine burp version - '
                               'is it installed?')
        else:
            # we initialize before main (i.e. not in fsinit) so that
            # any failure here aborts the mount
            try:
                server.initialize()
            except:
                server.shutdown()
                raise

    server.main()

    # we shutdown after main, i.e. not in fsshutdown, because
    # calling fsshutdown with multithreaded==True seems to cause
    # the python fuse process to hang waiting for the python GIL
    if server.fuse_args.mount_expected():
        server.shutdown()
