#! /usr/bin/env python

# BurpFS - Burp Filesystem in USErspace
# Copyright (C) 2012, 2013 Avi Rozen <avi.rozen@gmail.com>
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

from setuptools import setup, find_packages
from burpfs import __version__

author='Avi Rozen'
author_email='avi.rozen@gmail.com'

setup(
    name='BurpFS',
    version=__version__,
    description='Burp Filesystem in USErspace',
    long_description=open('README.rst').read(),
    author=author,
    author_email=author_email,
    maintainer=author,
    maintainer_email=author_email,
    url='https://github.com/ZungBang/burpfs',
    entry_points = { 'console_scripts': [ 'burpfs = burpfs:main' ] },
    packages = find_packages(),
    license='GPL',
    platforms=['Linux'],
    install_requires=['fuse-python>=0.2'],
    classifiers = [
        "Development Status :: 3 - Alpha",
        "Topic :: System :: Filesystems",
        "Topic :: System :: Archiving :: Backup",
        "Intended Audience :: System Administrators",
        "Environment :: No Input/Output (Daemon)",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        ],
    )

