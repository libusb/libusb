# Copyright 2013-2014 (C) Butterfly Network, Inc.

TARGET = libusb

TEMPLATE = lib
CONFIG += staticlib
CONFIG -= qt
CONFIG -= debug_and_release

# Include libusb sources
include($$PWD/libusb.pri)
