# libusb

[![Build Status](https://travis-ci.org/libusb/libusb.svg?branch=master)](https://travis-ci.org/libusb/libusb)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/2180/badge.svg)](https://scan.coverity.com/projects/libusb-libusb)

libusb is a library for USB device access from Linux, Mac OS X,
Windows, OpenBSD/NetBSD and Haiku userspace.
It is written in C (Haiku backend in C++) and licensed under the GNU
Lesser General Public License version 2.1 or, at your option, any later
version (see [COPYING](COPYING)).

libusb is abstracted internally in such a way that it can hopefully
be ported to other operating systems. Please see the [PORTING](PORTING)
file for more information.

libusb homepage:
http://libusb.info/

Developers will wish to consult the API documentation:
http://api.libusb.info

Use the mailing list for questions, comments, etc:
http://mailing-list.libusb.info

- Pete Batard <pete@akeo.ie>
- Hans de Goede <hdegoede@redhat.com>
- Xiaofan Chen <xiaofanc@gmail.com>
- Ludovic Rousseau <ludovic.rousseau@gmail.com>
- Nathan Hjelm <hjelmn@users.sourceforge.net>
- Chris Dickens <christopher.a.dickens@gmail.com>

(Please use the mailing list rather than mailing developers directly)

Custom modifications
====================

This repository contains custom modifications to libusb to provide some 
additional functionality out of the box on several specific platforms.

1) Android OS:

libusb_fdopen() API is provided which allows to open USB device and supply 
to the Linux back-end an existing file descriptor which was previously 
obtained from Android APIs, e.g.:

UsbDevice device ...
UsbDeviceConnection connection = getSystemService(Context.USB_SERVICE).openDevice(device);
int fd = connection.getFileDescriptor();
...
pass fd via JINI to libusb_fdopen() to native code in order to open device 
sucessfully.

2) Windows OS:

Implemented support for isochronous transfers if libusbK is used as device 
driver back-end. The implementation is tested (audio output) on Windows 7 
using several USB DAC devices with isochronous transfer capability. Device 
driver can be installed by Zadig tool - http://zadig.akeo.ie.
