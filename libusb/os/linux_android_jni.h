/*
 * android_jni interface
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LIBUSB_ANDROID_JNI_H
#define LIBUSB_ANDROID_JNI_H

#include "libusbi.h"

struct android_jni_context;
struct android_jni_devices;

/* from jni.h */
typedef const struct JNINativeInterface *JNIEnv;
typedef const struct JNIInvokeInterface *JavaVM;
typedef void *jobject;

/* All the functions in this file return a libusb error code. */

/* Converts a jni_env pointer to a javavm pointer, for utility. */
int android_jnienv_javavm(JNIEnv *jni_env, JavaVM **javavm);

/* Prepares to use android jni calls.
 *
 * The jni structure should be freed with android_jni_free().
 *
 * It's possible to automatically find a running java vm without the user
 * providing one, but it appears unreasonably difficult to do this until an ndk
 * issue is resolved: https://github.com/android/ndk/issues/1320
 */
int android_jni(JavaVM *javavm, struct android_jni_context **jni);

/* Frees this android jni structure. */
int android_jni_free(struct android_jni_context *jni);

/* Detects whether or not the platform supports usb host mode. */
int android_jni_detect_usbhost(struct android_jni_context *jni,
                               int *has_usbhost);

/* Prepares to iterate all connected devices. */
int android_jni_devices_alloc(struct android_jni_context *jni,
                              struct android_jni_devices **devices);

/* Iterates through connected devices.
 *
 * The device jobject should be freed with android_jni_globalunref().
 *
 * Returns LIBUSB_ERROR_NOT_FOUND when all devices have been enumerated.
 */
int android_jni_devices_next(struct android_jni_devices *devices,
                             jobject *device, uint8_t *busnum, uint8_t *devaddr);

/* Frees a device iteration structure. */
void android_jni_devices_free(struct android_jni_devices *devices);

/* Generates descriptors for a device witout connecting to it.  The descriptors
 * are generated from the information available in the android api, which
 * itself is generated from the real descriptors but does not quite include
 * everything.
 *
 * The descriptors buffers should be freed with free().
 */
int android_jni_gen_descriptors(struct android_jni_context *jni, jobject device,
                                uint8_t **descriptors, size_t *descriptors_len);

/* Detects whether or not the application has permission to connect to a device. */
int android_jni_detect_permission(struct android_jni_context *jni, jobject device,
                                  int *has_permission);

/* Requests permission from the user to connect to a device.
 *
 * This calls UsbManager.requestPermission, which pauses the running activity
 * and pops up a system dialogue asking for permission, then resumes the
 * activity and broadcasts an intent with the device and the user's response.
 * The intent will have action "libusb.android.USB_PERMISSION".
 *
 * For further information on this intent, see:
 * https://developer.android.com/guide/topics/connectivity/usb/host#permission-d
 */
int android_jni_request_permission(struct android_jni_context *jni, jobject device);

/* Connects to a device.
 *
 * The connection jobject should be freed with android_jni_disconnect().
 *
 * The descriptors buffer should be freed with free().
 *
 * If permission is needed, LIBUSB_ERROR_ACCESS is returned.
 */
int android_jni_connect(struct android_jni_context *jni, jobject device, jobject *connection,
                        int *fd, uint8_t **descriptors, size_t *descriptors_len);

/* Disconnects from a device and frees connection object. */
int android_jni_disconnect(struct android_jni_context *jni, jobject connection);

/* Frees a global reference to an object. */
void android_jni_globalunref(struct android_jni_context *jni, jobject object);

#endif
