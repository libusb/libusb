/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

/* Compile descriptor.c with a stub backend to test the public API without USB hardware. */
#include "../libusb/descriptor.c"

static const struct {
	const char *name;
	int expected;
	uint8_t config[35];
} cases[] = {
	{ "trailing short IAD", LIBUSB_ERROR_IO, {
		9, LIBUSB_DT_CONFIG, 18, 0, 1, 1, 0, 0x80, 0,
		2, LIBUSB_DT_ENDPOINT, 4, 0, 0, 0,
		3, LIBUSB_DT_INTERFACE_ASSOCIATION, 0,
	} },
	{ "short IAD followed by another descriptor", LIBUSB_ERROR_IO, {
		9, LIBUSB_DT_CONFIG, 18, 0, 1, 1, 0, 0x80, 0,
		3, LIBUSB_DT_INTERFACE_ASSOCIATION, 0,
		2, LIBUSB_DT_ENDPOINT, 4, 0, 0, 0,
	} },
	{ "valid IAD", LIBUSB_SUCCESS, {
		9, LIBUSB_DT_CONFIG, 35, 0, 2, 1, 0, 0x80, 0,
		8, LIBUSB_DT_INTERFACE_ASSOCIATION, 0, 2, 0xff, 1, 2, 3,
		9, LIBUSB_DT_INTERFACE, 0, 0, 0, 0xff, 1, 2, 0,
		9, LIBUSB_DT_INTERFACE, 1, 0, 0, 0xff, 1, 2, 0,
	} },
};

static int test_get_config(struct libusb_device *dev, uint8_t index, void *buf, size_t len)
{
	UNUSED(dev);
	len = MIN(len, cases[index].config[2]);
	memcpy(buf, cases[index].config, len);
	return (int)len;
}

const struct usbi_os_backend usbi_backend = {
	.get_config_descriptor = test_get_config,
};

#ifdef ENABLE_LOGGING
void usbi_log(struct libusb_context *ctx, enum libusb_log_level level,
	const char *function, const char *format, ...)
{
	UNUSED(ctx);
	UNUSED(level);
	UNUSED(function);
	UNUSED(format);
}
#endif

int LIBUSB_CALL libusb_control_transfer(libusb_device_handle *handle, uint8_t type,
	uint8_t request, uint16_t value, uint16_t index, unsigned char *data,
	uint16_t length, unsigned int timeout)
{
	UNUSED(handle);
	UNUSED(type);
	UNUSED(request);
	UNUSED(value);
	UNUSED(index);
	UNUSED(data);
	UNUSED(length);
	UNUSED(timeout);
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

int main(void)
{
	struct libusb_device dev = { .device_descriptor = { .bNumConfigurations = ARRAYSIZE(cases) } };
	int failed = 0;

	for (uint8_t i = 0; i < ARRAYSIZE(cases); i++) {
		struct libusb_interface_association_descriptor_array *array = NULL;
		int result = libusb_get_interface_association_descriptors(&dev, i, &array);
		const struct libusb_interface_association_descriptor *iad =
			result == LIBUSB_SUCCESS && array && array->length == 1 ? array->iad : NULL;

		if (result != cases[i].expected ||
		    (result == LIBUSB_SUCCESS &&
		     (!iad || iad->bLength != 8 || iad->bDescriptorType != LIBUSB_DT_INTERFACE_ASSOCIATION ||
		      iad->bFirstInterface != 0 || iad->bInterfaceCount != 2 ||
		      iad->bFunctionClass != 0xff || iad->bFunctionSubClass != 1 ||
		      iad->bFunctionProtocol != 2 || iad->iFunction != 3))) {
			fprintf(stderr, "%s: %s (status %d, expected %d)\n", cases[i].name,
				result != cases[i].expected ? "unexpected status" : "unexpected IAD array",
				result, cases[i].expected);
			failed = 1;
		}
		if (result == LIBUSB_SUCCESS)
			libusb_free_interface_association_descriptors(array);
	}

	return failed;
}
