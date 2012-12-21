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

# Convert file stat(2) mode to/from string representation
# 
# This module provides a few functions for conversion between
# binary and literal representations of file mode bits,
# including file type.
# 
# Adapted from original perl module ModeString.pm.
# http://cpansearch.perl.org/src/FEDOROV/File-Stat-ModeString-1.00/ModeString.pm
# Copyright (C) 2003 Dmitry Fedorov <dm.fedorov@gmail.com>
 
import stat
import re

# regular expression to match mode string
MODE_STRING_RE = r'[-dcbpls]([r-][w-][xsS-]){2}?[r-][w-][xtT-]'

type_to_char = dict([
        (stat.S_IFDIR, 'd'),
        (stat.S_IFCHR, 'c'),
        (stat.S_IFBLK, 'b'),
        (stat.S_IFREG, '-'),
        (stat.S_IFIFO, 'p'),
        (stat.S_IFLNK, 'l'),
        (stat.S_IFSOCK, 's')])

perms_clnid = ['---', '--x', '-w-', '-wx', 'r--', 'r-x', 'rw-', 'rwx']
perms_setid = ['--S', '--s', '-wS', '-ws', 'r-S', 'r-s', 'rwS', 'rws']
perms_stick = ['--T', '--t', '-wT', '-wt', 'r-T', 'r-t', 'rwT', 'rwt']

char_to_typemode = dict([
        ('d', stat.S_IFDIR),
        ('c', stat.S_IFCHR),
        ('b', stat.S_IFBLK),
        ('-', stat.S_IFREG),
        ('p', stat.S_IFIFO),
        ('l', stat.S_IFLNK),
        ('s', stat.S_IFSOCK)])


ugorw_to_mode = dict([
        ('u--', 0),
        ('ur-', stat.S_IRUSR),
        ('u-w', stat.S_IWUSR),
        ('urw', stat.S_IRUSR|stat.S_IWUSR),

        ('g--', 0),
        ('gr-', stat.S_IRGRP),
        ('g-w', stat.S_IWGRP),
        ('grw', stat.S_IRGRP|stat.S_IWGRP),

        ('o--', 0),
        ('or-', stat.S_IROTH),
        ('o-w', stat.S_IWOTH),
        ('orw', stat.S_IROTH|stat.S_IWOTH)])

ugox_to_mode = dict([
        ('u-', 0),
        ('ux', stat.S_IXUSR),
        ('us', stat.S_IXUSR|stat.S_ISUID),
        ('uS', stat.S_ISUID),

        ('g-', 0),
        ('gx', stat.S_IXGRP),
        ('gs', stat.S_IXGRP|stat.S_ISGID),
        ('gS', stat.S_ISGID),

        ('o-', 0),
        ('ox', stat.S_IXOTH),
        ('ot', stat.S_IXOTH|stat.S_ISVTX),
        ('oT', stat.S_ISVTX)])


def mode_to_string(mode):
    '''
    Converts binary mode value to string representation.
    '?' in file type field on unknown file type.
    '''
    string = mode_to_typechar(mode)

    # user
    perms = perms_setid if (mode & stat.S_ISUID) else perms_clnid
    string += perms[(mode & stat.S_IRWXU) >> 6]

    # group
    perms = perms_setid if (mode & stat.S_ISGID) else perms_clnid
    string += perms[(mode & stat.S_IRWXG) >> 3]

    # other
    perms = perms_stick if (mode & stat.S_ISVTX) else perms_clnid
    string += perms[(mode & stat.S_IRWXO)]

    return string


def string_to_mode(string):
    '''
    Converts string representation of file mode to binary one.
    '''
    mode = 0
    # type
    mode |= char_to_typemode[string[0]];
    # user read | write
    mode |= ugorw_to_mode['u' + string[1:3]]
    # user execute
    mode |= ugox_to_mode['u' + string[3]]
    # group read | write
    mode |= ugorw_to_mode['g' + string[4:6]]
    # group execute
    mode |= ugox_to_mode['g' + string[6]]
    # others read | write
    mode |= ugorw_to_mode['o' + string[7:9]]
    # others execute
    mode |= ugox_to_mode['o' + string[9]]

    return mode


def mode_to_typechar(mode):
    '''
    Returns file type character of binary mode, '?' on unknown file type.
    '''
    return type_to_char.get(stat.S_IFMT(mode), '?')


def is_mode_string_valid(string):
    '''
    Returns true if argument matches mode string pattern.
    '''
    return re.match(MODE_STRING_RE, string) != None

