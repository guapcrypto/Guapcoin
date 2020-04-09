
Debian
====================
This directory contains files used to package guapcoind/guapcoin-qt
for Debian-based Linux systems. If you compile guapcoind/guapcoin-qt yourself, there are some useful files here.

## guapcoin: URI support ##


guapcoin-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install guapcoin-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your guapcoin-qt binary to `/usr/bin`
and the `../../share/pixmaps/guapcoin128.png` to `/usr/share/pixmaps`

guapcoin-qt.protocol (KDE)

