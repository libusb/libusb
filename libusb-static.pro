# Copyright 2012-2019 (C) Butterfly Network, Inc.

TARGET = libusb

TEMPLATE = lib
CONFIG += staticlib
CONFIG -= qt
CONFIG -= debug_and_release

# Include libusb sources
include($$PWD/libusb.pri)
