CMAKE_MINIMUM_REQUIRED(VERSION 3.5.0)

PROJECT(libusb)

SET(CMAKE_CXX_STANDARD 11)

#IF (OS_DARWIN)
    INCLUDE_DIRECTORIES(../Xcode/)
#ENDIF()

ADD_SUBDIRECTORY(os)

# 查找当前目录下的所有源文件
# 并将名称保存到 DIR_LIB_SRCS 变量
AUX_SOURCE_DIRECTORY(. DIR_LIB_SRCS)

#SET(DIR_LIB_SRCS core.c descriptor.c hotplug.c hotplug.h io.c libusbi.h libusbi.h strerror.c sync.c version.h version_nano.h)

ADD_LIBRARY(usb SHARED ${DIR_LIB_SRCS} ${OS_SRC_LIST})
