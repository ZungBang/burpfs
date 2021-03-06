======
BurpFS
======

BurpFS_ - Exposes the Burp_ backup storage as a Filesystem in
USErspace (FUSE_).

.. _BurpFS: https://github.com/ZungBang/burpfs
.. _Burp: http://burp.grke.net/
.. _FUSE: https://github.com/libfuse/libfuse

Copyright |(C)| 2012-2020 Avi Rozen <avi.rozen@gmail.com>

.. contents:: 

Introduction
------------

**BurpFS** is a tool, developed independently of Burp, that represents
the Burp backup storage as a read-only filesystem in userspace.

**BurpFS** is specifically designed to cater for the following
use-cases:

- maintaining a remote snapshot of the files in the backup storage
  using `rsync`_ 
- auditing the contents of backup jobs at the client side
- comparing backup jobs (using several mount points)
- easier restore from backup

.. _rsync: https://rsync.samba.org


Installation
------------

There's no official release at this point, so please clone the public
**BurpFS** Git repository_ and run ``burpfs`` as ``root`` from the
``burpfs`` directory.

**BurpFS** requires Burp 1.3.22 and up, Python_ 2.7 and up, FUSE_ 2.x
(note that Python FUSE bindings_ 1.0.0 and up is *reuqired* for Python
3.x). 

You must set the client machine that you mount the filesystem on as a
``restore-client`` at the server side.

With Burp 2.x **BurpFS** uses the burp monitor to browse the backup
manifest, so you need to be able to run ``burp -a m`` on the same
machine you try to mount the filesystem on.


.. _repository: https://github.com/ZungBang/burpfs.git
.. _Python: https://www.python.org
.. _FUSE: https://github.com/libfuse/libfuse
.. _bindings: https://github.com/libfuse/python-fuse


Usage Examples
--------------

Mount the most recent backup snapshot for the local machine:

::

        burpfs /path/to/mount/point

Mount the contents of the backup #50 for client ``dumbo`` (the local
client must be configured as a ``restore_client`` for ``dumbo`` at the
``burp`` server side):

::

        burpfs -o backup=50,client=dumbo /path/to/mount/point

Mount only the *modified* contents of the backup #50 for client
``dumbo``, compared with the backup preceding it:

::

        burpfs -o diff,backup=50,client=dumbo /path/to/mount/point

Mount the contents of the backup job before the specified date/time:

::

        burpfs -o datetime='2012-08-23 00:00:00' /path/to/mount/point
        
Allow other users to access filesystem, set logging level to ``debug``
and stay in foreground, so that Burp messages may be examined:

::

        burpfs -f -o allow_other,logging=debug /path/to/mount/point

                 
Limitations
-----------
**BurpFS** is in its rough-around-the-edges alpha stage. Expect
breakage. Please report Bugs_.

**BurpFS** queries the Burp server for the files list only once, when
the filesystem is initialized. There's nothing to prevent the backup
being represented from being deleted at the server side while the
filesystem is mounted. **BurpFS** is liable to fail in interesting
ways in this case.


Changelog
---------
**Version 0.3.8 (2020-09-14)**

- do not try to open backup in 'working' state

**Version 0.3.7 (2020-04-19)**

- added support for burp 2.2.12 and up

**Version 0.3.6 (2019-11-16)**

- fixed handling of new lines in file names

**Version 0.3.5 (2019-11-16)**

- fixed path regex sanitation code

**Version 0.3.4 (2019-11-12)**

- Python 3 transition

**Version 0.3.3 (2018-10-25)**

- workaround: access to files with back-quotes in their name

**Version 0.3.2 (2016-09-13)**

- tweaked VSS headers parser

**Version 0.3.1 (2016-09-11)**

- auto strip VSS headers

**Version 0.3.0 (2016-09-08)**

- added support for Burp 2.x

**Version 0.2.4 (2016-09-05)**

- issue error when trying to mount Burp 2.x backup

**Version 0.2.3 (2015-12-14)**

- added new diff mode to mount modified/added files only
- fixed restore of files with very long path string
  
**Version 0.2.2 (2013-11-11)**

- added support for Burp 1.4.x

**Version 0.2.1 (2013-01-13)**

- fixed **BurpFS** version
  
**Version 0.2.0 (2013-01-13)**

- implemented LRU (Least Recently Used) cache policy
- workaround: access to files with single quotes in their name
- provide options to specify the path to the Burp executable
  ``-o burp`` and a path to the Burp client configuration file
  ``-o conf``

**Version 0.1.0 (2013-01-03)**

- switched to burp JSON long listing format (requires Burp 1.3.22 and
  up):
  
  + fixed ``-o use_ino`` so that files can have their original inode
    numbers
  + fixed file timestamps
  + fixed handling of hardlinks

- fixed handling of Windows paths
- fixed handling of empty directories
- several stability workarounds

**Version 0.0.1 (2012-12-21-End of The World Release)**

- initial public release

Source Code
-----------

**BurpFS** development source code may be cloned from its public Git
repository at `<https://github.com/ZungBang/burpfs.git>`_


Bugs
----

Please report problems via the **BurpFS** issue tracking system:
`<https://github.com/ZungBang/burpfs/issues>`_


License
-------

**BurpFS** is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at
your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see
`<http://www.gnu.org/licenses/>`_.

.. |(C)| unicode:: 0xA9 .. copyright sign

