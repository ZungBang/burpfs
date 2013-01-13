======
BurpFS
======

BurpFS_ - Exposes the Burp_ backup storage as a Filesystem in
USErspace (FUSE_).

.. _BurpFS: https://github.com/ZungBang/burpfs
.. _Burp: http://burp.grke.net/
.. _FUSE: http://fuse.sourceforge.net/

Copyright |(C)| 2012, 2013 Avi Rozen <avi.rozen@gmail.com>

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

.. _rsync: http://rsync.samba.org/


Installation
------------

There's no official release at this point, so please clone the public
**BurpFS** Git repository_ and run ``burpfs`` as ``root`` from the
``burpfs`` directory.

**BurpFS** requires Burp 1.3.22 and up, Python_ 2.7 and Python FUSE_.

.. _repository: https://github.com/ZungBang/burpfs.git
.. _Python: http://www.python.org
.. _FUSE: http://fuse.sourceforge.net/


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

If you intend to mount a Windows backup file set with **BurpFS**,
you'll need to set ``split_vss=1`` in the Windows client configuration
file, or else all files will contain extra bytes (the VSS
header/footer).

**BurpFS** queries the Burp server for the files list only once, as
the the filesystem is initialized. There's nothing to prevent the
backup being represented from being deleted at the server side while
the filesystem is mounted. **BurpFS** is liable to fail in interesting
ways in this case.


Changelog
---------
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

