#! /usr/bin/env python

# BurpFS - Burp Filesystem in USErspace
# Copyright (C) 2012 Avi Rozen <avi.rozen@gmail.com>
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

__version__ = '0.0.1'

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
from datetime import datetime
from bisect import bisect_left, bisect_right

from LogFile import *

# pull in some spaghetti to make this stuff work
# without fuse-py being installed
try:
    import _find_fuse_parts
except ImportError:
    pass

import fuse
from fuse import Fuse

if not hasattr(fuse, '__version__'):
    raise RuntimeError(\
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
    except OSError, exc:
        if exc.errno == errno.EEXIST:
            pass
        else:
            raise

def totimestamp(dt, epoch=datetime(1970,1,1)):
    '''
    convert datetime to (UTC) timestamp
    adapted from: http://stackoverflow.com/a/8778548/27831
    '''
    td = dt - epoch
    return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 1e6


'''
_decode_list and _decode_dict below are used to convince the JSON
parser (json.loads) to avoid coercing everything into unicode because
FUSE doesn't seem to like unicode strings (a simple eval instead of
json.loads works, but it's not considered safe)

taken from:
http://stackoverflow.com/a/6633651
'''
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
    for key, value in data.iteritems():
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


class FileSystem(Fuse):
    ITEM_STAT=0
    ITEM_LINK=1
    ITEM_ROOT=2
    ITEM_HARD=3
        
    datetime_format = '%Y-%m-%d %H:%M:%S'

    null_stat = fuse.Stat(st_mode=stat.S_IFDIR | 0755,
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

    xattr_fields_root = ['conf',
                         'client',
                         'backup',
                         'datetime',
                         'cache_prefix']

    xattr_fields_burp = ['path',
                         'state',
                         'pending']

    burp_done = {'path': None,
                 'state': 'idle'}

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
        self.cache_prefix = None
        self.move_root = False
        self.use_ino = False
        self.max_ino = 0
        self.dirs = {'/': {'': (FileSystem.null_stat, None)}}

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
        if not head in self.dirs:
            self.dirs[head] = {tail: (FileSystem.null_stat,)}
        elif not tail in self.dirs[head]:
            self.dirs[head][tail] = (FileSystem.null_stat,)
        self._add_parent_dirs(head)

    def _update_inodes(self, head):
        '''
        generate unique st_ino for each missing st_ino
        '''
        for tail in self.dirs[head]:
            if self.dirs[head][tail][FileSystem.ITEM_STAT].st_ino == 0:
                self.max_ino += 1
                self.dirs[head][tail][FileSystem.ITEM_STAT].st_ino = self.max_ino
            subdir = '%s%s/' % (head, tail)
            if subdir in self.dirs:
                self._update_inodes(subdir)

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
            realpaths, path_regexs, found = self._find_in_cache(path)
            if not realpaths:
                continue
            realpath_list.extend(realpaths)
            if not found:
                items.extend(path_regexs)
        

        # FIXME: implement LRU cache policy
        if len(items) > 0:
            self._burp(items)

        self._extract_lock.release()
        self._burp_increment_counter('pending', -nitems)

        return realpath_list

    def _find_in_cache(self, path):
        '''
        return path in cache corresponding to input path and boolean
        that's true if the path was found in cache
        may return up to two paths in case path is a hard link
        '''
        realpath = os.path.normpath(self.cache_path + '/' + path)
        self.logger.debug('realpath=%s' % realpath)
        head, tail = self._split(path)
        # sanity check: path should not be a directory
        if tail == '':
            raise RuntimeError('trying to extract a directory %s' % path)
        # check that path exists in file list
        if head not in self.dirs or tail not in self.dirs[head]:
            return None, None, False
        # return if file has already been extracted
        bs = self.getattr(path)
        if os.path.exists(realpath) or os.path.lexists(realpath):
            # make sure that stat info of realpath matches path
            s = os.lstat(realpath)
            conds = [getattr(s, attr) == getattr(bs, attr)
                     for attr in ['st_mode',
                                  'st_uid',
                                  'st_gid',
                                  'st_size',
                                  'st_mtime']]
            if all(conds):
                return [realpath], None, True

        realpaths = [realpath]
        regexs = []
        # build regex for burp
        item_path = path if self.dirs[head][tail][FileSystem.ITEM_ROOT] else path[1:]
        regexs.append(r'^' + re.escape(item_path) + r'$')

        # we need to extract the file
        # but, if it's a hard-link we must also make sure the link target
        # exists or is extracted before
        if self.dirs[head][tail][FileSystem.ITEM_HARD]:
            link_path = self.dirs[head][tail][FileSystem.ITEM_LINK]
            link_realpaths, link_regexs, link_found = self._find_in_cache(link_path)
            if not link_found and link_regexs:
                realpaths = link_realpaths + realpaths
                regexs = link_regexs + regexs
                
        return realpaths, regexs, False

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
        # even if we can't lock the sd conf file
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
        cmd_prefix = [self.burp]
        if self.client:
            cmd_prefix += ['-C', self.client]
        cmd_prefix += ['-a', 'r', '-f', '-b', str(self.backup), '-d', self.cache_path, '-r']
        for item in items:
            cmd = cmd_prefix + [item]
            self.logger.debug('$ %s' % ' '.join(cmd))
            self._burp_set_status({'path': item,
                                   'state': 'run'})
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            self.logger.debug('%s%s' % (stdout, stderr))
            # wait a bit before next restore
            if len(items) > 1:
                time.sleep(0.01)
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
        self.logger = logging.getLogger('Burpfs')
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
                    "%(name)s: %(levelname)-8s - %(message)s")
                h.setFormatter(formatter)
                self.logger.addHandler(h)
            except:
                self.logger.warning(traceback.format_exc())
        self.logfile = LogFile(self.logger, logging.DEBUG)

    def _list_files(self, client, backup, timespec):
        '''
        get list of files in backup
        '''
        cmd_prefix = [self.burp]
        if client:
            cmd_prefix += ['-C', client]
            
        cmd = cmd_prefix + ['-a', 'l']
        self.logger.debug('Getting list of backups with: %s' % ' '.join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        self.logger.debug('%s' % stdout)
        matches = re.finditer(('^Backup: ([0-9]{7}) ' +
                               '([0-9]{4})-([0-9]{2})-([0-9]{2}) ' +
                               '([0-9]{2}):([0-9]{2}):([0-9]{2})'),
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
            # FIXME: handle burp errors (lock, etc)
            self.logger.debug('%s%s' % (stdout, stderr))
            raise RuntimeError('cannot determine list of available backups')

        backup_ids, backup_dates = zip(*available_backups)
        ibackup = None
        nbackup = None
        
        if backup:
            ibackup = int(backup)
            nbackup = bisect_left(backup_ids, ibackup)
            if nbackup == len(backup_ids) or backup_ids[nbackup] != ibackup:
                raise ValueError('backup must be one of %s' % repr(backup_ids))
        else:
            ibackup = backup_ids[-1] # latest (we assume list is sorted by date)
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
        
        cmd = cmd_prefix + ['-b', '%d' % ibackup, '-a', 'L', '-j']
        self.logger.debug('Getting list of files in backup with: %s' % ' '.join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        json_string = '\n'.join(
            [line for line in stdout.splitlines()
             if not re.match(('^([0-9]{4})-([0-9]{2})-([0-9]{2}) ' +
                              '([0-9]{2}):([0-9]{2}):([0-9]{2}):.*'), line)])
        backup = json.loads(json_string, object_hook=_decode_dict)
        files = backup['items']
        return files, ibackup, backup_date


    def _json_to_stat(self, item):
        '''
        convert JSON file entry tokens into file stat structure
        '''
        st = fuse.Stat(st_mode=item['st_mode'],
                       st_ino=item['st_ino'],
                       st_dev=item['st_dev'],
                       st_nlink=item['st_nlink'],
                       st_uid=item['st_uid'],
                       st_gid=item['st_gid'],
                       st_size=item['st_size'],
                       st_atime=item['st_atime'],
                       st_mtime=item['st_mtime'],
                       st_ctime=item['st_ctime'],
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
        target = item['link'] if item['type'] in ['l', 'L'] else None
        hardlink = item['type'] == 'L'
        entry = (self._json_to_stat(item), target, under_root, hardlink)
        return head, tail, entry
        
    def initialize(self, version):
        '''
        initialize file list
        '''

        self._setup_logging()

        self.logger.info('Populating file system ... ')
        self.cache_prefix = tempfile.mkdtemp(prefix='burpfs-')
        self.cache_path = os.path.normpath(self.cache_prefix + '/files')
        makedirs(self.cache_path)

        # test access to burp conf file
        open(self.conf, 'r').close()

        # get list of files in backup
        files, backup, timespec = self._list_files(self.client,
                                                   self.backup,
                                                   self.datetime)
        # validated values
        self.backup = backup
        self.datetime = timespec

        # are we using inode numbers
        self.use_ino = 'use_ino' in self.fuse_args.optlist
        
        # build dirs data structure
        for file in files:
            head, tail, entry = self._create_file_entry(file)
            # find max st_ino
            if self.use_ino:
                if entry[FileSystem.ITEM_STAT].st_ino > self.max_ino:
                    self.max_ino = entry[FileSystem.ITEM_STAT].st_ino
            # new directory
            if head not in self.dirs:
                self.dirs[head] = {}
            # add parent directories
            self._add_parent_dirs(head)
            # and finally
            self.dirs[head][tail] = entry
        
        # fix st_ino
        if self.use_ino:
            self._update_inodes('/')

        self.logger.debug('Cache directory is: %s' % self.cache_prefix)
        self.logger.info('BurpFS ready (%d items).' % len(files))

        self._initialized = True

    def shutdown(self):
        '''
        remove cache directory if required
        '''
        if self.cache_prefix:
            self.logger.info('removing cache directory: %s' %
                             self.cache_prefix)
            shutil.rmtree(self.cache_prefix, ignore_errors=True)

    def setxattr(self, path, name, value, flags):
        '''
        set value of extended attribute
        '''
        return -errno.EOPNOTSUPP

    def getxattr(self, path, name, size):
        '''
        get value of extended attribute
        burpfs exposes some filesystem attributes for the root directory
        (e.g. backup number, cache_prefix - see FileSystem.xattr_fields_root)
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
        if (not val and head in self.dirs and tail in self.dirs[head] and
            n in FileSystem.xattr_fields):
            # place holder in case we add xattrs
            pass
        # attribute not found
        if val == None:
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
            attrs = self.dirs[head][tail][FileSystem.ITEM_STAT]
            # zero negative timestamps
            # FIXME: move to dirs generation 
            for a in ['st_atime', 'st_mtime', 'st_ctime']:
                t = getattr(attrs, a)
                if t < 0:
                    self.logger.warning(
                        '%s has negative timestamp %s=%d, will use 0' %
                        (path, a, t))
                    setattr(attrs, a, 0)
            return attrs
        else:
            return -errno.ENOENT

    def readdir(self, path, offset):
        '''
        read directory entries
        '''
        path = path if path.endswith('/') else path + '/'
        for key in ['.', '..']:
            yield fuse.Direntry(key)
        for key in self.dirs[path].keys():
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
        link = self.dirs[head][tail][FileSystem.ITEM_LINK]
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
            self.file = os.fdopen(os.open(self.realpath, flags, *mode),
                                  flag2mode(flags))
            self.fd = self.file.fileno()
            self.direct_io = False
            self.keep_cache = True

        def read(self, length, offset):
            self.file.seek(offset)
            return self.file.read(length)

        def release(self, flags):
            self.file.close()


def _burp_version():
    '''
    return version string of burp,
    return None if not runnable or version cannot be parsed
    '''
    version = None
    try:
        cmd = ['burp', '-v']
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        match = re.search('burp-(.*)\n$', stdout)
        if match:
            version = '%s' % match.group(1)
    except:
        traceback.print_exc()
        pass
    return version


def main():

    usage = """
BurpFS: exposes the Burp backup storage as a Filesystem in USErspace

""" + Fuse.fusage

    burp_version = _burp_version()

    # force -o sync_read
    sys.argv.extend(['-o', 'sync_read'])
    
    server = FileSystem(
        version=(
            "BurpFS version: %s\nburp version: %s\n"
            "Python FUSE version: %s" %
            (__version__, burp_version, fuse.__version__)),
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
    server.parser.add_option(mountopt="move_root",
                             action="store_true",
                             default=server.move_root,
                             help=("make absolute path symlinks point to path "
                                   "under mount point  [default: %default]"))
    server.parser.add_option(mountopt="logging",
                             choices=LOGGING_LEVELS.keys(),
                             metavar='|'.join(LOGGING_LEVELS.keys()),
                             default=server.logging,
                             help="logging level [default: %default]")
    server.parser.add_option(mountopt="syslog",
                             action="store_true",
                             default=server.syslog,
                             help=("log to both syslog and console [default: "
                                   "%default]"))

    server.parse(values=server, errex=1)

    if server.fuse_args.mount_expected():
        if not burp_version:
            raise RuntimeError('cannot determine burp version - '
                               'is it installed?')
        else:
            # we initialize before main (i.e. not in fsinit) so that
            # any failure here aborts the mount
            try:
                server.initialize(burp_version)
            except:
                server.shutdown()
                raise

    server.main()
    
    # we shutdown after main, i.e. not in fsshutdown, because
    # calling fsshutdown with multithreaded==True seems to cause
    # the python fuse process to hang waiting for the python GIL
    if server.fuse_args.mount_expected():
        server.shutdown()
