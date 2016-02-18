libusb test_app for Android
===========================

Building:
---------

To build libusb test_app for Android do the following:


 1. Download the latest SDK from:
    [http://developer.android.com/sdk/index.html](http://developer.android.com/sdk/index.html#Other)

 2. Install the SDK.

 3. Download the latest NDK from:
    [http://developer.android.com/tools/sdk/ndk/index.html](http://developer.android.com/tools/sdk/ndk/index.html)

 4. Extract the NDK.

 5. Open a shell and make sure there exist an `NDK` global variable
    set to the directory where you extracted the NDK.
    If not exist, run command:

		export NDK=<absolute path to the NDK dir>

 6. Change directory to libusb's top folder

 7. Run `android/autogen.sh`

		android/autogen.sh

 8. Change to `android/test_app dir`

		cd android/test_app

 9. Create `local.properties` file with locations of NDK and SDK:

		echo ndk.dir=<absolute path to the NDK dir> > local.properties
		echo sdk.dir=<absolute path to the SDK dir> >> local.properties

 10. Run the ant build:

		ant debug

 The apk can then be found in:

		android/test_app/bin

libftdi examples:
-----------------

To build and run libftdi examples, shared by intra2net, do the following:

 1. Obtain copy of intra2net's libftdi

	git clone git://developer.intra2net.com/libftdi

 2. export LIBFTDI_ROOT variable

	export LIBFTDI_ROOT=`pwd`/libftdi

 3. Apply patch

	cd libftdi
	patch -p1 < <path to libusb dir>/android/test_app/jni/patches/0001-Added-ftdi_transfer_data_cancel.patch

 4. Configure libftdi for android

	<path to libusb dir>/android/autogen.h
	
 5. Change to android test_app dir
 
	cd 	<path to libusb dir>/android/test_app

 6. Run the ant build:

		ant debug

FTDI D2XX examples:
-------------------

To build and run FTDI D2XX examples, shared by FTDI, do the following:

 1. export LIBFTD2XX variable
 
	export LIBFTD2XX=1

 2. Run the ant build:

		ant debug

Note: FTDI publishes libftd2xx library in binary format, prebuild for certain
 ABI. Only four of them are suitable for Android: armeabi armeabi-v7a x86 x86_64 

Installing:
-----------

###Installing test_app via adb:
To install the apk connect to the and execute:

		adb install bin/test_app-debug.apk

To run the application via adb, execute:

		adb shell am start -n info.libusb.test_app/info.libusb.test_app.Main

###Note
On some phones phones USB devices attached the the phone are not detected 
by Android automatically but require a explicit action carried by the user.

###Installing libusb tests and examples with the test app:
The test_app provides an easy way for deploying and running test binaries
 on Android phones. Build the test_app as described above.
 Then build libusb tests and examples as described in `../README`

run `install2testapp` script from the android directory:

		./install2testapp 

This script renames all executables to lib_*.so to make the Android package
manager extracting them from apk, and copies them to test_app/lib directory. 

Build the test_app again with flag `skip-ndk-build`

		ant debug -Dskip-ndk-build=1

Install the app as described earlier. After installation of test_app, 
the libusb binaries will be available in `/data/data/info.libusb.test_app/lib`

To run the libsub tests via adb, obtain root permissions and execute the 
following sequence of commands:

		export LD_LIBRARY_PATH=/system/lib:/data/data/info.libusb.test_app/lib

and then run the tests/examples as the following

		cd /data/data/info.libusb.test_app/lib
		./lib_listdevs.so

