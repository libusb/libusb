# libusb for Android

## Building

To build libusb for Android, do the following:

1. Download the latest NDK from:  
   [Android NDK](http://developer.android.com/tools/sdk/ndk/index.html)

2. Extract the NDK.

3. Open a shell and make sure there exists an `NDK` global variable set to the directory where you extracted the NDK.

4. Change directory to libusb's `android/jni`.

5. Run `$NDK/ndk-build`.

The libusb library, examples, and tests can then be found in:  
`android/libs/$ARCH`

Where `$ARCH` is one of:

- armeabi  
- armeabi-v7a  
- mips  
- mips64  
- x86  
- x86_64  

---

## Installing

If you wish to use libusb from native code in your Android application, add the following line to your `Android.mk` file:

```make
include $(PATH_TO_LIBUSB_SRC)/android/jni/libusb.mk
```

You will then need to add the following lines to the build configuration for each native binary which uses libusb:

```make
LOCAL_C_INCLUDES += $(LIBUSB_ROOT_ABS)
LOCAL_SHARED_LIBRARIES += libusb1.0
```

The Android build system will correctly include libusb in the application package (APK) file, provided `ndk-build` is invoked before the package is built.

---

## Runtime Permissions

The runtime permissions on Android can be transferred from Java to native over the following approach:

### Java

1. Obtain USB permissions using the `android.hardware.usb.UsbManager` class:

    ```java
    usbManager = (UsbManager) getSystemService(Context.USB_SERVICE);
    HashMap<String, UsbDevice> deviceList = usbManager.getDeviceList();
    for (UsbDevice usbDevice : deviceList.values()) {
        usbManager.requestPermission(usbDevice, mPermissionIntent);
    }
    ```

2. Get the native `FileDescriptor` of the `UsbDevice` and transfer it to native over JNI or JNA:

    ```java
    UsbDeviceConnection usbDeviceConnection = usbManager.openDevice(camDevice);
    int fileDescriptor = usbDeviceConnection.getFileDescriptor();
    ```

3. JNA sample method:

    ```java
    JNA.INSTANCE.set_the_native_Descriptor(fileDescriptor);
    ```

### Native

1. Initialize libusb on Android:

    ```c
    #include "libusb.h"
    
    void set_the_native_Descriptor(int fileDescriptor) {
        libusb_context *ctx;
        libusb_device_handle *devh;
        libusb_set_option(NULL, LIBUSB_OPTION_NO_DEVICE_DISCOVERY, NULL);
        libusb_init(&ctx);
        libusb_wrap_sys_device(NULL, (intptr_t)fileDescriptor, &devh);
    }
    ```

    From this point, you can regularly use all libusb functions as usual.

#### About `LIBUSB_OPTION_NO_DEVICE_DISCOVERY`

The method `libusb_set_option(NULL, LIBUSB_OPTION_NO_DEVICE_DISCOVERY, NULL)` does not affect the `ctx`. It allows initializing libusb on unrooted Android devices by skipping device enumeration.

---

## Rooted Devices

For rooted devices, the code using libusb could be executed as root using the `su` command. Alternatively, use the `su` command to change permissions on the appropriate `/dev/bus/usb/` files.

Users have reported success in using `android.hardware.usb.UsbManager` to request permission to use the `UsbDevice` and then opening the device. However, this method has challenges:

- No guarantee it will work in future Android versions.
- Requires invoking Java APIs and matching `android.hardware.usb.UsbDevice` to a `libusb_device`.

### Installing libusb in System Image

For rooted devices, libusb can be installed into the system image:

1. Enable ADB on the device.

2. Connect the device to a machine running ADB.

3. Execute the following commands on the machine running ADB:

    ```bash
    # Make the system partition writable
    adb shell su -c "mount -o remount,rw /system"

    # Install libusb
    adb push obj/local/armeabi/libusb1.0.so /sdcard/
    adb shell su -c "cat > /system/lib/libusb1.0.so < /sdcard/libusb1.0.so"
    adb shell rm /sdcard/libusb1.0.so

    # Install the samples and tests
    for B in listdevs fxload xusb sam3u_benchmark hotplugtest stress
    do
      adb push "obj/local/armeabi/$B" /sdcard/
      adb shell su -c "cat > /system/bin/$B < /sdcard/$B"
      adb shell su -c "chmod 0755 /system/bin/$B"
      adb shell rm "/sdcard/$B"
    done

    # Make the system partition read-only again
    adb shell su -c "mount -o remount,ro /system"

    # Run listdevs to verify
    adb shell su -c "listdevs"
    ```

4. If your device only has a single OTG port, ADB can generally be switched to WiFi using the following commands when connected via USB:

    ```bash
    adb shell netcfg
    # Note the WiFi IP address of the phone
    adb tcpip 5555
    # Use the IP address from netcfg
    adb connect 192.168.1.123:5555
    ```

---

## Building with Android Studio and CMake

To build libusb with Android Studio and CMake, follow these steps:

1. Ensure you have the Android NDK and CMake installed in Android Studio.
2. clone libusb in app/src/main/cpp/libusb (or use a custom path and update the CMakeLists.txt file accordingly)
3. Create a CMake build script (`CMakeLists.txt`) in your project directory.

Below is a sample `CMakeLists.txt` file:

```cmake
# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

cmake_minimum_required(VERSION 3.22.1)

project("nativeproject")

# Set up libusb using its own build system
# First, create a custom target that will represent the actual build output
include(ExternalProject)
ExternalProject_Add(libusb_build
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libusb
        CONFIGURE_COMMAND ""  # No configure step needed
        BUILD_COMMAND "${ANDROID_NDK}/ndk-build"
        "-C" "${CMAKE_CURRENT_SOURCE_DIR}/libusb/android/jni"
        "APP_ABI=${ANDROID_ABI}"
        INSTALL_COMMAND ""  # No install step needed
        BUILD_ALWAYS 1
        BUILD_BYPRODUCTS ${CMAKE_CURRENT_SOURCE_DIR}/libusb/android/libs/${ANDROID_ABI}/libusb1.0.so
)

# Create an imported target for libusb
add_library(usb-1.0 STATIC IMPORTED GLOBAL)
add_dependencies(usb-1.0 libusb_build)

set_target_properties(usb-1.0 PROPERTIES
        IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libusb/android/libs/${ANDROID_ABI}/libusb1.0.so
)

# Creates the native shared library
add_library(nativeproject SHARED
        main.cpp
)

# Configure libraries CMake uses to link your target library.
target_link_libraries(nativeproject
        usb-1.0
        android
        log
)
```
