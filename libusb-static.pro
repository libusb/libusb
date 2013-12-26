# Copyright 2013 (C) Butterfly Network, Inc.

TARGET = libusbx

TEMPLATE = lib
CONFIG += staticlib
CONFIG -= qt
CONFIG -= debug_and_release

# Include libusb sources
include($$PWD/libusb.pri)
