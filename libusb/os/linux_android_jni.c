/* -*- Mode: C; c-basic-offset:8 ; indent-tabs-mode:t -*- */
/*
 * Android jni interface for libusb
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

#include "linux_android_jni.h"
#include "libusb.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include <jni.h>

static int android_jni_env(struct android_jni_context *jni, JNIEnv **jni_env);
static int android_jni_fill_ctx_ids(struct android_jni_context *jni,
                                    JNIEnv *jni_env);
static int android_jni_gen_epoint(struct android_jni_context *jni,
                                  JNIEnv *jni_env, jobject endpoint,
                                  uint8_t **descriptors, size_t *descriptors_len);
static int android_jni_gen_iface(struct android_jni_context *jni, JNIEnv *jni_env,
                                 jobject interface, uint8_t *num_ifaces,
                                 uint8_t **descriptors, size_t *descriptors_len);
static int android_jni_gen_config(struct android_jni_context *jni,
                                  JNIEnv *jni_env, jobject config,
                                  uint8_t **descriptors, size_t *descriptors_len);

struct android_jni_context
{
	JavaVM *javavm;
	pthread_key_t detach_pthread_key;

	/* jobjects need global references */
	jclass Intent, PendingIntent;

	jobject PackageManager__FEATURE_USB_HOST;

	jobject application_context;
	jobject package_manager;
	jobject usb_manager;

	jstring permission_action;

	/* ids do not need global references */
	jmethodID Collection_iterator;
	jmethodID HashMap_values;
	jmethodID Iterator_hasNext, Iterator_next;

	int Build__VERSION__SDK_INT;
	int Build__VERSION_CODES__P;
	jmethodID Intent_init;
	jmethodID PackageManager_hasSystemFeature;
	jmethodID PendingIntent__getBroadcast;
	jmethodID UsbConfiguration_getInterfaceCount, UsbConfiguration_getId,
	          UsbConfiguration_getName, UsbConfiguration_isSelfPowered,
	          UsbConfiguration_isRemoteWakeup, UsbConfiguration_getMaxPower,
	          UsbConfiguration_getInterface;
	jmethodID UsbDevice_getDeviceId, UsbDevice_getConfigurationCount,
	          UsbDevice_getVersion, UsbDevice_getDeviceClass,
	          UsbDevice_getDeviceSubclass, UsbDevice_getDeviceProtocol,
	          UsbDevice_getVendorId, UsbDevice_getProductId,
	          UsbDevice_getManufacturerName, UsbDevice_getProductName,
	          UsbDevice_getSerialNumber, UsbDevice_getConfiguration;
	jmethodID UsbDeviceConnection_close, UsbDeviceConnection_getFileDescriptor,
	          UsbDeviceConnection_getRawDescriptors;
	jmethodID UsbEndpoint_getAddress, UsbEndpoint_getAttributes,
	          UsbEndpoint_getMaxPacketSize, UsbEndpoint_getInterval;
	jmethodID UsbInterface_getEndpointCount, UsbInterface_getId,
	          UsbInterface_getAlternateSetting, UsbInterface_getInterfaceClass,
	          UsbInterface_getInterfaceSubclass, UsbInterface_getInterfaceProtocol,
	          UsbInterface_getName, UsbInterface_getEndpoint;
	jmethodID UsbManager_getDeviceList, UsbManager_hasPermission,
	          UsbManager_openDevice, UsbManager_requestPermission;
};

int android_jnienv_javavm(JNIEnv *jni_env, JavaVM **javavm)
{
	if (jni_env == NULL) {
		*javavm = NULL;
		return LIBUSB_SUCCESS;
	}
	return (*jni_env)->GetJavaVM(jni_env, javavm) == JNI_OK ?
		LIBUSB_SUCCESS : LIBUSB_ERROR_OTHER;
}

int android_jni(JavaVM *javavm, struct android_jni_context **jni)
{
	int r;
	JNIEnv *jni_env;

	jclass ActivityThread, Context;
	jmethodID ActivityThread__currentActivityThread, ActivityThread_getApplication;
	jmethodID Context_getPackageManager, Context_getSystemService;
	jobject activity_thread, Context__USB_SERVICE;
	jobject local_context, local_pkg_mgr, local_usb_mgr;
	jstring local_perm_act;

	*jni = malloc(sizeof(struct android_jni_context));
	if (*jni == NULL)
		return LIBUSB_ERROR_NO_MEM;

	(*jni)->javavm = javavm;

	r = pthread_key_create(
		&(*jni)->detach_pthread_key,
		(void(*)(void*))(*javavm)->DetachCurrentThread);
	if (r != 0) {
		free(*jni);
		return r == ENOMEM ? LIBUSB_ERROR_NO_MEM : LIBUSB_ERROR_OTHER;
	}

	r = android_jni_env(*jni, &jni_env);
	if (r != LIBUSB_SUCCESS) {
		free(*jni);
		return r;
	}

	r = android_jni_fill_ctx_ids(*jni, jni_env);
	if (r != LIBUSB_SUCCESS) {
		free(*jni);
		return r;
	}

	/* ActivityThread activity_thread = ActivityThread.currentActivityThread(); */
	ActivityThread = (*jni_env)->FindClass(jni_env, "android/app/ActivityThread");
	ActivityThread__currentActivityThread =
		(*jni_env)->GetStaticMethodID(jni_env,
			ActivityThread, "currentActivityThread",
			"()Landroid/app/ActivityThread;");
	ActivityThread_getApplication =
		(*jni_env)->GetMethodID(jni_env,
			ActivityThread, "getApplication", "()Landroid/app/Application;");
	activity_thread =
		(*jni_env)->CallStaticObjectMethod(jni_env,
			ActivityThread, ActivityThread__currentActivityThread);

	/* Context local_context = activity_thread.getApplication(); */
	local_context =
		(*jni_env)->CallObjectMethod(jni_env,
			activity_thread, ActivityThread_getApplication);

	(*jni)->application_context = (*jni_env)->NewGlobalRef(jni_env, local_context);


	Context = (*jni_env)->FindClass(jni_env, "android/content/Context");
	Context__USB_SERVICE =
		(*jni_env)->GetStaticObjectField(jni_env,
			Context,
			(*jni_env)->GetStaticFieldID(jni_env,
				Context, "USB_SERVICE", "Ljava/lang/String;"));
	Context_getPackageManager =
		(*jni_env)->GetMethodID(jni_env,
			Context, "getPackageManager",
			"()Landroid/content/pm/PackageManager;");
	Context_getSystemService =
		(*jni_env)->GetMethodID(jni_env,
			Context, "getSystemService",
			"(Ljava/lang/String;)Ljava/lang/Object;");

	/* PackageManager local_pkg_mgr = application_context.getPackageManager(); */
	local_pkg_mgr =
		(*jni_env)->CallObjectMethod(jni_env,
			(*jni)->application_context, Context_getPackageManager);

	(*jni)->package_manager = (*jni_env)->NewGlobalRef(jni_env, local_pkg_mgr);

	/* UsbManager local_usb_mgr =
		application_context.getSystemService(Context.USB_SERVICE); */
	local_usb_mgr =
		(*jni_env)->CallObjectMethod(jni_env,
			(*jni)->application_context, Context_getSystemService,
			Context__USB_SERVICE);

	(*jni)->usb_manager = (*jni_env)->NewGlobalRef(jni_env, local_usb_mgr);

	/* String local_perm_act = "libusb.android.USB_PERMISSION"; */
	local_perm_act = (*jni_env)->NewStringUTF(jni_env,
		"libusb.android.USB_PERMISSION");

	(*jni)->permission_action = (*jni_env)->NewGlobalRef(jni_env, local_perm_act);

	(*jni_env)->DeleteLocalRef(jni_env, local_perm_act);
	(*jni_env)->DeleteLocalRef(jni_env, local_usb_mgr);
	(*jni_env)->DeleteLocalRef(jni_env, local_pkg_mgr);
	(*jni_env)->DeleteLocalRef(jni_env, local_context);

	(*jni_env)->DeleteLocalRef(jni_env, Context);
	(*jni_env)->DeleteLocalRef(jni_env, Context__USB_SERVICE);
	(*jni_env)->DeleteLocalRef(jni_env, ActivityThread);

	return LIBUSB_SUCCESS;
}

int android_jni_free(struct android_jni_context *jni)
{
	int r;
	JNIEnv *jni_env;
	JavaVM *javavm = jni->javavm;

	r = android_jni_env(jni, &jni_env);
	if (r != LIBUSB_SUCCESS) {
		goto out;
	}

	(*jni_env)->DeleteGlobalRef(jni_env, jni->Intent);
	(*jni_env)->DeleteGlobalRef(jni_env, jni->PendingIntent);

	(*jni_env)->DeleteGlobalRef(jni_env, jni->PackageManager__FEATURE_USB_HOST);

	(*jni_env)->DeleteGlobalRef(jni_env, jni->application_context);
	(*jni_env)->DeleteGlobalRef(jni_env, jni->package_manager);
	(*jni_env)->DeleteGlobalRef(jni_env, jni->usb_manager);

	(*jni_env)->DeleteGlobalRef(jni_env, jni->permission_action);

out:
	if (pthread_getspecific(jni->detach_pthread_key) == javavm) {
		(*javavm)->DetachCurrentThread(javavm);
	}
	pthread_key_delete(jni->detach_pthread_key);

	free(jni);
	return r;
}

int android_jni_detect_usbhost(struct android_jni_context *jni, int *has_usbhost)
{
	int r;
	JNIEnv *jni_env;

	r = android_jni_env(jni, &jni_env);
	if (r != LIBUSB_SUCCESS)
		return r;

	/* has_usbhost =
		package_manager.hasSystemFeature(PackageManager.FEATURE_USB_HOST); */
	*has_usbhost =
		(*jni_env)->CallBooleanMethod(jni_env,
			jni->package_manager, jni->PackageManager_hasSystemFeature,
			jni->PackageManager__FEATURE_USB_HOST);

	return LIBUSB_SUCCESS;
}

struct android_jni_devices
{
	struct android_jni_context *jni;
	jobject iterator;
};

int android_jni_devices_alloc(struct android_jni_context *jni,
	struct android_jni_devices **devices)
{
	int r;
	JNIEnv *jni_env;
	jobject deviceMap, deviceCollection, deviceIterator;

	r = android_jni_env(jni, &jni_env);
	if (r != LIBUSB_SUCCESS)
		return r;

	/* HashMap<String, UsbDevice> deviceMap = usb_manager.getDeviceList(); */
	deviceMap = (*jni_env)->CallObjectMethod(jni_env,
		jni->usb_manager, jni->UsbManager_getDeviceList);

	/* Collection<UsbDevice> deviceCollection = deviceMap.values(); */
	deviceCollection = (*jni_env)->CallObjectMethod(jni_env,
		deviceMap, jni->HashMap_values);

	(*jni_env)->DeleteLocalRef(jni_env, deviceMap);

	/* Iterator<UsbDevice> deviceIterator = deviceCollection.iterator(); */
	deviceIterator = (*jni_env)->CallObjectMethod(jni_env,
		deviceCollection, jni->Collection_iterator);

	(*jni_env)->DeleteLocalRef(jni_env, deviceCollection);

	*devices = malloc(sizeof(struct android_jni_devices));
	if (*devices == NULL)
		return LIBUSB_ERROR_NO_MEM;
	(*devices)->jni = jni;
	(*devices)->iterator = (*jni_env)->NewGlobalRef(jni_env, deviceIterator);

	(*jni_env)->DeleteLocalRef(jni_env, deviceIterator);

	return LIBUSB_SUCCESS;
}

int android_jni_devices_next(struct android_jni_devices *devices,
	jobject *device, uint8_t *busnum, uint8_t *devaddr)
{
	struct android_jni_context *jni = devices->jni;
	JNIEnv *jni_env;
	jobject deviceIterator = devices->iterator;
	jobject local_device;
	uint16_t deviceid;
	int r;

	r = android_jni_env(jni, &jni_env);
	if (r != LIBUSB_SUCCESS)
		return r;

	/* if (!deviceIterator.hasNext()) */
	if (!(*jni_env)->CallBooleanMethod(jni_env,
			deviceIterator, jni->Iterator_hasNext))

		return LIBUSB_ERROR_NOT_FOUND;

	/* UsbDevice local_device = deviceIterator.next(); */
	local_device =
		(*jni_env)->CallObjectMethod(jni_env,
			deviceIterator, jni->Iterator_next);

	/* int deviceid = device.getDeviceId(); */
	deviceid =
		(*jni_env)->CallIntMethod(jni_env,
			local_device, jni->UsbDevice_getDeviceId);

	*device = (*jni_env)->NewGlobalRef(jni_env, local_device);
	(*jni_env)->DeleteLocalRef(jni_env, local_device);

	/* https://android.googlesource.com/platform/system/core/+/master/libusbhost/usbhost.c */
	*busnum = deviceid / 1000;
	*devaddr = deviceid % 1000;

	return LIBUSB_SUCCESS;
}

void android_jni_devices_free(struct android_jni_devices *devices)
{
	struct android_jni_context *jni = devices->jni;
	int r;
	JNIEnv *jni_env;

	r = android_jni_env(jni, &jni_env);
	if (r == LIBUSB_SUCCESS)
		(*jni_env)->DeleteGlobalRef(jni_env, devices->iterator);

	free(devices);
}

int android_jni_gen_descriptors(struct android_jni_context *jni, jobject device,
	uint8_t **descriptors, size_t *descriptors_len)
{
	int r, num_configs, idx, version, tens, ones, tenths, hundredths;
	JNIEnv *jni_env;
	jobject config;
	jstring jversion;
	const char *sversion;
	struct usbi_device_descriptor desc;

	r = android_jni_env(jni, &jni_env);
	if (r != LIBUSB_SUCCESS)
		return r;

	/* int num_configs = device.getConfigurationCount(); */
	num_configs =
		(*jni_env)->CallIntMethod(jni_env,
			device, jni->UsbDevice_getConfigurationCount);

	*descriptors_len = LIBUSB_DT_DEVICE_SIZE;
	*descriptors = malloc(*descriptors_len);
	if (!*descriptors)
		return LIBUSB_ERROR_NO_MEM;

	/* parse binary coded decimal version */
	/* String jversion = device.getVersion(); */
	jversion =
		(*jni_env)->CallObjectMethod(jni_env,
			device, jni->UsbDevice_getVersion);

	sversion = (*jni_env)->GetStringUTFChars(jni_env, jversion, NULL);
	sscanf(sversion, "%d.%d", &ones, &hundredths);
	(*jni_env)->ReleaseStringUTFChars(jni_env, jversion, sversion);

	/* Android usb version bug was fixed in commit 608ec66d62647f60c3988922fead33fd7e07755e in Pie */
	if (jni->Build__VERSION__SDK_INT < jni->Build__VERSION_CODES__P) {
		/* undo pre-pie bug */
		tenths = hundredths / 16;
		hundredths = hundredths % 16;
	} else {
		/* bug has been fixed */
		tenths = hundredths / 10;
		hundredths = hundredths % 10;
	}
	tens = ones / 10;
	ones = ones % 10;

	version = hundredths | (tenths << 4) | (ones << 8) | (tens << 12);

	desc = (struct usbi_device_descriptor){
		.bLength = LIBUSB_DT_DEVICE_SIZE,
		.bDescriptorType = LIBUSB_DT_DEVICE,
		.bcdUSB = libusb_cpu_to_le16(version),
		.bDeviceClass =
			 (*jni_env)->CallIntMethod(jni_env,
				device, jni->UsbDevice_getDeviceClass),
		.bDeviceSubClass =
			(*jni_env)->CallIntMethod(jni_env,
				device, jni->UsbDevice_getDeviceSubclass),
		.bDeviceProtocol =
			(*jni_env)->CallIntMethod(jni_env,
				device, jni->UsbDevice_getDeviceProtocol),
		.bMaxPacketSize0 = 8,
		.idVendor = libusb_cpu_to_le16(
			(*jni_env)->CallIntMethod(jni_env,
				device, jni->UsbDevice_getVendorId)),
		.idProduct = libusb_cpu_to_le16(
			(*jni_env)->CallIntMethod(jni_env,
				device, jni->UsbDevice_getProductId)),
		.bcdDevice = 0xFFFF,
		.iManufacturer = 0,
		.iProduct = 0,
		.iSerialNumber = 0,
		.bNumConfigurations = num_configs,
	};
	*(struct usbi_device_descriptor *)*descriptors = desc;

	for (idx = 0; idx < num_configs; idx ++) {
		/* UsbConfiguration config = device.getConfiguration(i); */
		config =
			(*jni_env)->CallObjectMethod(jni_env,
				device, jni->UsbDevice_getConfiguration, idx);

		r =
			android_jni_gen_config(jni, jni_env, config,
				descriptors, descriptors_len);

		(*jni_env)->DeleteLocalRef(jni_env, config);

		if (r != LIBUSB_SUCCESS)
			return r;
	}

	return LIBUSB_SUCCESS;
}

int android_jni_detect_permission(struct android_jni_context *jni, jobject device,
	int *has_permission)
{
	int r;
	JNIEnv *jni_env;

	r = android_jni_env(jni, &jni_env);
	if (r != LIBUSB_SUCCESS)
		return r;

	/* boolean has_permission = usb_manager.hasPermission(device); */
	*has_permission =
		(*jni_env)->CallBooleanMethod(jni_env,
			jni->usb_manager, jni->UsbManager_hasPermission, device);

	return LIBUSB_SUCCESS;
}

int android_jni_request_permission(struct android_jni_context *jni,
	jobject device)
{
	int r;
	JNIEnv *jni_env;
	jobject intent, permission_intent;

	r = android_jni_env(jni, &jni_env);
	if (r != LIBUSB_SUCCESS)
		return r;

	/* Intent intent = new Intent(permission_action); */
	intent =
		(*jni_env)->NewObject(jni_env,
			jni->Intent, jni->Intent_init,
			jni->permission_action);

	/* PendingIntent permission_intent =
		PendingIntent.getBroadcast(application_context, 0, intent, 0); */
	permission_intent =
		(*jni_env)->CallStaticObjectMethod(jni_env,
			jni->PendingIntent, jni->PendingIntent__getBroadcast,
			jni->application_context, 0, intent, 0);

	(*jni_env)->DeleteLocalRef(jni_env, intent);

	/* usb_manager.requestPermission(device, permission_intent); */
	(*jni_env)->CallVoidMethod(jni_env,
		jni->usb_manager, jni->UsbManager_requestPermission,
		device, permission_intent);

	(*jni_env)->DeleteLocalRef(jni_env, permission_intent);

	return LIBUSB_SUCCESS;
}

int android_jni_connect(struct android_jni_context *jni,
	jobject device, jobject *connection,
	int *fd, uint8_t **descriptors, size_t *descriptors_len)
{
	int has_permission, r;
	JNIEnv *jni_env;
	jobject local_connection;
	jbyteArray local_descriptors;
	jbyte * local_descriptors_ptr;

	r = android_jni_env(jni, &jni_env);
	if (r != LIBUSB_SUCCESS)
		return r;

	r = android_jni_detect_permission(jni, device, &has_permission);

	if (r != LIBUSB_SUCCESS)
		return r;

	if (!has_permission)
		return LIBUSB_ERROR_ACCESS;

	/* UsbDeviceConnection local_connection = usb_manager.openDevice(device); */
	local_connection =
		(*jni_env)->CallObjectMethod(jni_env,
			jni->usb_manager, jni->UsbManager_openDevice, device);

	/* fd output */
	/* fd = local_connection.getFileDescriptor(); */
	*fd =
		(*jni_env)->CallIntMethod(jni_env,
			local_connection, jni->UsbDeviceConnection_getFileDescriptor);

	if (*fd == -1) {
		(*jni_env)->DeleteLocalRef(jni_env, local_connection);
		return LIBUSB_ERROR_IO;
	}

	/* byte[] local_descriptors = local_connection.getRawDescriptors(); */
	local_descriptors =
		(*jni_env)->CallObjectMethod(jni_env,
			local_connection, jni->UsbDeviceConnection_getRawDescriptors);

	/* descriptors buffer output */
	*descriptors_len = (*jni_env)->GetArrayLength(jni_env, local_descriptors);
	*descriptors = malloc(*descriptors_len);
	if (!*descriptors) {
		(*jni_env)->DeleteLocalRef(jni_env, local_descriptors);
		(*jni_env)->DeleteLocalRef(jni_env, local_connection);
		return LIBUSB_ERROR_NO_MEM;
	}

	/* jni buffer copy */
	local_descriptors_ptr =
		(*jni_env)->GetPrimitiveArrayCritical(jni_env, local_descriptors, NULL);
	memcpy(*descriptors, local_descriptors_ptr, *descriptors_len);
	(*jni_env)->ReleasePrimitiveArrayCritical(jni_env,
		local_descriptors, local_descriptors_ptr, JNI_ABORT);

	/* connection jobject output */
	*connection = (*jni_env)->NewGlobalRef(jni_env, local_connection);

	(*jni_env)->DeleteLocalRef(jni_env, local_descriptors);
	(*jni_env)->DeleteLocalRef(jni_env, local_connection);

	return LIBUSB_SUCCESS;
}

int android_jni_disconnect(struct android_jni_context *jni, jobject connection)
{
	int r;
	JNIEnv *jni_env;

	r = android_jni_env(jni, &jni_env);
	if (r != LIBUSB_SUCCESS)
		return r;

	/* connection.close(); */
	(*jni_env)->CallVoidMethod(jni_env,
		connection, jni->UsbDeviceConnection_close);

	(*jni_env)->DeleteGlobalRef(jni_env, connection);
	return LIBUSB_SUCCESS;
}

void android_jni_globalunref(struct android_jni_context *jni, jobject object)
{
	int r;
	JNIEnv *jni_env;

	r = android_jni_env(jni, &jni_env);
	if (r != LIBUSB_SUCCESS)
		return;

	(*jni_env)->DeleteGlobalRef(jni_env, object);
}

static int android_jni_gen_config(struct android_jni_context *jni,
	JNIEnv *jni_env, jobject config,
	uint8_t **descriptors, size_t *descriptors_len)
{
	int r;
	size_t num_ifaces, offset, idx;
	struct usbi_configuration_descriptor desc;

	/* int num_ifaces = config.getInterfaceCount(); */
	num_ifaces =
		(*jni_env)->CallIntMethod(jni_env,
			config, jni->UsbConfiguration_getInterfaceCount);

	offset = *descriptors_len;
	*descriptors_len = offset + LIBUSB_DT_CONFIG_SIZE;
	*descriptors = usbi_reallocf(*descriptors, *descriptors_len);
	if (!*descriptors)
		return LIBUSB_ERROR_NO_MEM;

	desc = (struct usbi_configuration_descriptor){
		.bLength = LIBUSB_DT_CONFIG_SIZE,
		.bDescriptorType = LIBUSB_DT_CONFIG,
		.wTotalLength = 0, /* assigned below */
		.bNumInterfaces = 0, /* assigned within interfaces */
		.bConfigurationValue =
			(*jni_env)->CallIntMethod(jni_env,
				config, jni->UsbConfiguration_getId),
		.iConfiguration = 0,
		.bmAttributes = 0x80 |
			((*jni_env)->CallBooleanMethod(jni_env,
				config, jni->UsbConfiguration_isSelfPowered)
			 ? 0x40 : 0) |
			((*jni_env)->CallBooleanMethod(jni_env,
				config, jni->UsbConfiguration_isRemoteWakeup)
			 ? 0x20 : 0),
		.bMaxPower =
			(*jni_env)->CallIntMethod(jni_env,
				config, jni->UsbConfiguration_getMaxPower) / 2
	};
	if (desc.iConfiguration < 0)
		return desc.iConfiguration;

	for (idx = 0; idx < num_ifaces; ++ idx) {
		/* UsbInterface interface = config.getInterface(idx); */
		jobject interface = (*jni_env)->CallObjectMethod(jni_env,
			config, jni->UsbConfiguration_getInterface, idx);

		r = android_jni_gen_iface(jni,
			jni_env, interface, &desc.bNumInterfaces,
			descriptors, descriptors_len);

		(*jni_env)->DeleteLocalRef(jni_env, interface);

		if (r != LIBUSB_SUCCESS)
			return r;
	}

	desc.wTotalLength = libusb_cpu_to_le16(*descriptors_len - offset);
	*(struct usbi_configuration_descriptor *)(*descriptors + offset) = desc;

	return LIBUSB_SUCCESS;
}

int android_jni_gen_iface(struct android_jni_context *jni,
	JNIEnv *jni_env, jobject interface, uint8_t *num_ifaces,
	uint8_t **descriptors, size_t *descriptors_len)
{
	int r;
	size_t num_epoints, offset, idx;
	struct usbi_interface_descriptor desc;

	/* int num_epoints = interface.getEndpointCount(); */
	num_epoints =
		(*jni_env)->CallIntMethod(jni_env,
			interface, jni->UsbInterface_getEndpointCount);

	offset = *descriptors_len;
	*descriptors_len = offset + LIBUSB_DT_INTERFACE_SIZE;
	*descriptors = usbi_reallocf(*descriptors, *descriptors_len);
	if (!*descriptors)
		return LIBUSB_ERROR_NO_MEM;

	desc = (struct usbi_interface_descriptor){
		.bLength = LIBUSB_DT_INTERFACE_SIZE,
		.bDescriptorType = LIBUSB_DT_INTERFACE,
		.bInterfaceNumber =
			(*jni_env)->CallIntMethod(jni_env,
				interface, jni->UsbInterface_getId),
		.bAlternateSetting =
			(*jni_env)->CallIntMethod(jni_env,
				interface, jni->UsbInterface_getAlternateSetting),
		.bNumEndpoints = num_epoints,
		.bInterfaceClass =
			(*jni_env)->CallIntMethod(jni_env,
				interface, jni->UsbInterface_getInterfaceClass),
		.bInterfaceSubClass =
			(*jni_env)->CallIntMethod(jni_env,
				interface, jni->UsbInterface_getInterfaceSubclass),
		.bInterfaceProtocol =
			(*jni_env)->CallIntMethod(jni_env,
				interface, jni->UsbInterface_getInterfaceProtocol),
		.iInterface = 0
	};
	*(struct usbi_interface_descriptor *)(*descriptors + offset) = desc;

	if (desc.bInterfaceNumber >= *num_ifaces)
		*num_ifaces = desc.bInterfaceNumber + 1;

	for (idx = 0; idx < num_epoints; idx ++) {
		/* UsbEndpoint endpoint = interface.getEndpoint(idx); */
		jobject endpoint =
			(*jni_env)->CallObjectMethod(jni_env,
				interface, jni->UsbInterface_getEndpoint, idx);

		r =
			android_jni_gen_epoint(jni,
				jni_env, endpoint,
				descriptors, descriptors_len);

		(*jni_env)->DeleteLocalRef(jni_env, endpoint);

		if (r != LIBUSB_SUCCESS)
			return r;
	}
	return LIBUSB_SUCCESS;
}

static int android_jni_gen_epoint(struct android_jni_context *jni,
	JNIEnv *jni_env, jobject endpoint,
	uint8_t **descriptors, size_t *descriptors_len)
{
	size_t offset;
	struct usbi_endpoint_descriptor desc;

	offset = *descriptors_len;
	*descriptors_len = offset + LIBUSB_DT_ENDPOINT_SIZE;
	*descriptors = usbi_reallocf(*descriptors, *descriptors_len);
	if (!*descriptors)
		return LIBUSB_ERROR_NO_MEM;

	desc = (struct usbi_endpoint_descriptor){
		.bLength = LIBUSB_DT_ENDPOINT_SIZE,
		.bDescriptorType = LIBUSB_DT_ENDPOINT,
		.bEndpointAddress =
			(*jni_env)->CallIntMethod(jni_env,
				endpoint, jni->UsbEndpoint_getAddress),
		.bmAttributes =
			(*jni_env)->CallIntMethod(jni_env,
				endpoint, jni->UsbEndpoint_getAttributes),
		.wMaxPacketSize = libusb_cpu_to_le16(
			(*jni_env)->CallIntMethod(jni_env,
				endpoint, jni->UsbEndpoint_getMaxPacketSize)),
		.bInterval =
			(*jni_env)->CallIntMethod(jni_env,
				endpoint, jni->UsbEndpoint_getInterval)
	};
	*(struct usbi_endpoint_descriptor *)(*descriptors + offset) = desc;

	return LIBUSB_SUCCESS;
}

static int android_jni_fill_ctx_ids(struct android_jni_context *jni,
	JNIEnv *jni_env)
{
	jclass Collection, HashMap, Iterator;
	jclass Build__VERSION, Intent, PackageManager, PendingIntent,
		UsbConfiguration, UsbDevice, UsbDeviceConnection, UsbEndpoint,
		UsbInterface, UsbManager;

	jobject PackageManager__FEATURE_USB_HOST;

	Collection = (*jni_env)->FindClass(jni_env, "java/util/Collection");
	jni->Collection_iterator =
		(*jni_env)->GetMethodID(jni_env,
			Collection, "iterator", "()Ljava/util/Iterator;");

	HashMap = (*jni_env)->FindClass(jni_env, "java/util/HashMap");
	jni->HashMap_values =
		(*jni_env)->GetMethodID(jni_env,
			HashMap, "values", "()Ljava/util/Collection;");

	Iterator = (*jni_env)->FindClass(jni_env, "java/util/Iterator");
	jni->Iterator_hasNext =
		(*jni_env)->GetMethodID(jni_env, Iterator, "hasNext", "()Z");
	jni->Iterator_next =
		(*jni_env)->GetMethodID(jni_env,
			Iterator, "next", "()Ljava/lang/Object;");

	Build__VERSION = (*jni_env)->FindClass(jni_env, "android/os/Build$VERSION");
	jni->Build__VERSION__SDK_INT =
		(*jni_env)->GetStaticIntField(jni_env,
			Build__VERSION,
			(*jni_env)->GetStaticFieldID(jni_env,
				Build__VERSION, "SDK_INT", "I"));
	jni->Build__VERSION_CODES__P = 28;

	Intent = (*jni_env)->FindClass(jni_env, "android/content/Intent");
	jni->Intent = (*jni_env)->NewGlobalRef(jni_env, Intent);
	jni->Intent_init =
		(*jni_env)->GetMethodID(jni_env,
			jni->Intent, "<init>", "(Ljava/lang/String;)V");

	PackageManager =
		(*jni_env)->FindClass(jni_env, "android/content/pm/PackageManager");
	PackageManager__FEATURE_USB_HOST =
		(*jni_env)->GetStaticObjectField(jni_env,
			PackageManager,
			(*jni_env)->GetStaticFieldID(jni_env,
				PackageManager, "FEATURE_USB_HOST", "Ljava/lang/String;"));
	jni->PackageManager__FEATURE_USB_HOST =
		(*jni_env)->NewGlobalRef(jni_env, PackageManager__FEATURE_USB_HOST);
	jni->PackageManager_hasSystemFeature =
		(*jni_env)->GetMethodID(jni_env,
			PackageManager, "hasSystemFeature", "(Ljava/lang/String;)Z");

	PendingIntent =
		(*jni_env)->FindClass(jni_env, "android/app/PendingIntent");
	jni->PendingIntent = (*jni_env)->NewGlobalRef(jni_env, PendingIntent);
	jni->PendingIntent__getBroadcast =
		(*jni_env)->GetStaticMethodID(jni_env,
			jni->PendingIntent, "getBroadcast",
			"(Landroid/content/Context;ILandroid/content/Intent;I)" /**/
			"Landroid/app/PendingIntent;");

	UsbConfiguration =
		(*jni_env)->FindClass(jni_env, "android/hardware/usb/UsbConfiguration");
	jni->UsbConfiguration_getInterfaceCount =
		(*jni_env)->GetMethodID(jni_env,
			UsbConfiguration, "getInterfaceCount", "()I");
	jni->UsbConfiguration_getId =
		(*jni_env)->GetMethodID(jni_env,
			UsbConfiguration, "getId", "()I");
	jni->UsbConfiguration_getName =
		(*jni_env)->GetMethodID(jni_env,
			UsbConfiguration, "getName", "()Ljava/lang/String;");
	jni->UsbConfiguration_isSelfPowered =
		(*jni_env)->GetMethodID(jni_env,
			UsbConfiguration, "isSelfPowered", "()Z");
	jni->UsbConfiguration_isRemoteWakeup =
		(*jni_env)->GetMethodID(jni_env,
			UsbConfiguration, "isRemoteWakeup", "()Z");
	jni->UsbConfiguration_getMaxPower =
		(*jni_env)->GetMethodID(jni_env,
			UsbConfiguration, "getMaxPower", "()I");
	jni->UsbConfiguration_getInterface =
		(*jni_env)->GetMethodID(jni_env,
			UsbConfiguration, "getInterface",
			"(I)Landroid/hardware/usb/UsbInterface;");

	UsbDevice =
		(*jni_env)->FindClass(jni_env, "android/hardware/usb/UsbDevice");
	jni->UsbDevice_getDeviceId =
		(*jni_env)->GetMethodID(jni_env, UsbDevice, "getDeviceId", "()I");
	jni->UsbDevice_getConfigurationCount =
		(*jni_env)->GetMethodID(jni_env,
			UsbDevice, "getConfigurationCount", "()I");
	jni->UsbDevice_getVersion =
		(*jni_env)->GetMethodID(jni_env,
			UsbDevice, "getVersion", "()Ljava/lang/String;");
	jni->UsbDevice_getDeviceClass =
		(*jni_env)->GetMethodID(jni_env,
			UsbDevice, "getDeviceClass", "()I");
	jni->UsbDevice_getDeviceSubclass =
		(*jni_env)->GetMethodID(jni_env,
			UsbDevice, "getDeviceSubclass", "()I");
	jni->UsbDevice_getDeviceProtocol =
		(*jni_env)->GetMethodID(jni_env,
			UsbDevice, "getDeviceProtocol", "()I");
	jni->UsbDevice_getVendorId =
		(*jni_env)->GetMethodID(jni_env,
			UsbDevice, "getVendorId", "()I");
	jni->UsbDevice_getProductId =
		(*jni_env)->GetMethodID(jni_env,
			UsbDevice, "getProductId", "()I");
	jni->UsbDevice_getManufacturerName =
		(*jni_env)->GetMethodID(jni_env,
			UsbDevice, "getManufacturerName", "()Ljava/lang/String;");
	jni->UsbDevice_getProductName =
		(*jni_env)->GetMethodID(jni_env,
			UsbDevice, "getProductName", "()Ljava/lang/String;");
	jni->UsbDevice_getSerialNumber =
		(*jni_env)->GetMethodID(jni_env,
			UsbDevice, "getSerialNumber", "()Ljava/lang/String;");
	jni->UsbDevice_getConfiguration =
		(*jni_env)->GetMethodID(jni_env,
			UsbDevice, "getConfiguration",
			"(I)Landroid/hardware/usb/UsbConfiguration;");

	UsbDeviceConnection =
		(*jni_env)->FindClass(jni_env,
			"android/hardware/usb/UsbDeviceConnection");
	jni->UsbDeviceConnection_close =
		(*jni_env)->GetMethodID(jni_env,
			UsbDeviceConnection, "close", "()V");
	jni->UsbDeviceConnection_getFileDescriptor =
		(*jni_env)->GetMethodID(jni_env,
			UsbDeviceConnection, "getFileDescriptor", "()I");
	jni->UsbDeviceConnection_getRawDescriptors =
		(*jni_env)->GetMethodID(jni_env,
			UsbDeviceConnection, "getRawDescriptors", "()[B");

	UsbEndpoint =
		(*jni_env)->FindClass(jni_env, "android/hardware/usb/UsbEndpoint");
	jni->UsbEndpoint_getAddress =
		(*jni_env)->GetMethodID(jni_env, UsbEndpoint, "getAddress", "()I");
	jni->UsbEndpoint_getAttributes =
		(*jni_env)->GetMethodID(jni_env, UsbEndpoint, "getAttributes", "()I");
	jni->UsbEndpoint_getMaxPacketSize =
		(*jni_env)->GetMethodID(jni_env, UsbEndpoint, "getMaxPacketSize", "()I");
	jni->UsbEndpoint_getInterval =
		(*jni_env)->GetMethodID(jni_env, UsbEndpoint, "getInterval", "()I");

	UsbInterface =
		(*jni_env)->FindClass(jni_env, "android/hardware/usb/UsbInterface");
	jni->UsbInterface_getEndpointCount =
		(*jni_env)->GetMethodID(jni_env,
			UsbInterface, "getEndpointCount", "()I");
	jni->UsbInterface_getId =
		(*jni_env)->GetMethodID(jni_env,
			UsbInterface, "getId", "()I");
	jni->UsbInterface_getAlternateSetting =
		(*jni_env)->GetMethodID(jni_env,
			UsbInterface, "getAlternateSetting", "()I");
	jni->UsbInterface_getInterfaceClass =
		(*jni_env)->GetMethodID(jni_env,
			UsbInterface, "getInterfaceClass", "()I");
	jni->UsbInterface_getInterfaceSubclass =
		(*jni_env)->GetMethodID(jni_env,
			UsbInterface, "getInterfaceSubclass", "()I");
	jni->UsbInterface_getInterfaceProtocol =
		(*jni_env)->GetMethodID(jni_env,
			UsbInterface, "getInterfaceProtocol", "()I");
	jni->UsbInterface_getName =
		(*jni_env)->GetMethodID(jni_env,
			UsbInterface, "getName", "()Ljava/lang/String;");
	jni->UsbInterface_getEndpoint =
		(*jni_env)->GetMethodID(jni_env,
			UsbInterface, "getEndpoint",
			"(I)Landroid/hardware/usb/UsbEndpoint;");

	UsbManager =
		(*jni_env)->FindClass(jni_env, "android/hardware/usb/UsbManager");
	jni->UsbManager_getDeviceList =
		(*jni_env)->GetMethodID(jni_env,
			UsbManager, "getDeviceList", "()Ljava/util/HashMap;");
	jni->UsbManager_hasPermission =
		(*jni_env)->GetMethodID(jni_env,
			UsbManager, "hasPermission", "(Landroid/hardware/usb/UsbDevice;)Z");
	jni->UsbManager_openDevice =
		(*jni_env)->GetMethodID(jni_env,
			UsbManager, "openDevice",
			"(Landroid/hardware/usb/UsbDevice;)" /**/
			"Landroid/hardware/usb/UsbDeviceConnection;");
	jni->UsbManager_requestPermission =
		(*jni_env)->GetMethodID(jni_env,
			UsbManager, "requestPermission",
			"(Landroid/hardware/usb/UsbDevice;Landroid/app/PendingIntent;)V");

	(*jni_env)->DeleteLocalRef(jni_env, UsbManager);
	(*jni_env)->DeleteLocalRef(jni_env, UsbInterface);
	(*jni_env)->DeleteLocalRef(jni_env, UsbEndpoint);
	(*jni_env)->DeleteLocalRef(jni_env, UsbDeviceConnection);
	(*jni_env)->DeleteLocalRef(jni_env, UsbDevice);
	(*jni_env)->DeleteLocalRef(jni_env, UsbConfiguration);
	(*jni_env)->DeleteLocalRef(jni_env, PendingIntent);
	(*jni_env)->DeleteLocalRef(jni_env, PackageManager__FEATURE_USB_HOST);
	(*jni_env)->DeleteLocalRef(jni_env, PackageManager);
	(*jni_env)->DeleteLocalRef(jni_env, Intent);
	(*jni_env)->DeleteLocalRef(jni_env, Build__VERSION);

	(*jni_env)->DeleteLocalRef(jni_env, Iterator);
	(*jni_env)->DeleteLocalRef(jni_env, HashMap);
	(*jni_env)->DeleteLocalRef(jni_env, Collection);
	return LIBUSB_SUCCESS;
}

static int android_jni_env(struct android_jni_context *jni, JNIEnv **jni_env)
{
	JavaVM *javavm = jni->javavm;
	int status = (*javavm)->GetEnv(javavm, (void**)jni_env, JNI_VERSION_1_1);
	if (status == JNI_EDETACHED) {
		JavaVMAttachArgs thr_args = {
			.version = JNI_VERSION_1_6,
			.name = NULL,
			.group = NULL
		};
		status = (*javavm)->AttachCurrentThread(javavm, jni_env, &thr_args);
		if (status == JNI_OK) {
			status = pthread_setspecific(jni->detach_pthread_key, javavm);
			if (status == ENOMEM)
				return LIBUSB_ERROR_NO_MEM;
		}
	}
	return status == 0 ? LIBUSB_SUCCESS : LIBUSB_ERROR_OTHER;
}
