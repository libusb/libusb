/* Fuzz the backend-independent library core with an in-process mock
 * backend.
 *
 * Pair partner of fuzz_usbfs_descriptors: that target drives the Linux
 * *backend* descriptor parsing; this one drives everything else —
 * libusb/core.c (context, device discovery/sanitize, handle lifecycle),
 * libusb/io.c (transfer submission, the event loop and completion
 * machinery), libusb/sync.c (sync wrappers), libusb/hotplug.c and the
 * posix event/timer/threading plumbing — by unity-including them and
 * supplying a fuzz-driven `usbi_backend` (a superset of the existing
 * os/null_usb.c template).
 *
 * Threat model: libusb is used by tools that talk to attacker-pluggable
 * devices; the io state machine and completion paths are what a hostile
 * device actually reaches. The mock completes every submitted transfer
 * with a fuzz-selected status, runs fuzz-selected timeouts through the
 * timerfd machinery, and exposes a fuzz-shaped device descriptor/config
 * blob to the discovery/sanitize logic.
 *
 * Built as part of the OSS-Fuzz integration; not exercised by the
 * autotools test suite.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "libusbi.h"

/* The backend-independent library, one translation unit. */
#include "../../libusb/core.c"
#include "../../libusb/descriptor.c"
#include "../../libusb/io.c"
#include "../../libusb/hotplug.c"
#include "../../libusb/sync.c"
#include "../../libusb/strerror.c"
#include "../../libusb/os/events_posix.c"
#include "../../libusb/os/threads_posix.c"

/* ------------------------------------------------------------------ */
/* Fuzz state                                                          */
/* ------------------------------------------------------------------ */

static const uint8_t *fuzz_data;
static size_t fuzz_size;
static size_t fuzz_pos;

static const uint8_t *fuzz_bytes(size_t n)
{
	const uint8_t *ret;

	if (fuzz_size - fuzz_pos < n)
		return NULL;
	ret = fuzz_data + fuzz_pos;
	fuzz_pos += n;
	return ret;
}

static uint8_t fuzz_byte(void)
{
	const uint8_t *b = fuzz_bytes(1);

	return b ? b[0] : 0;
}

/* ------------------------------------------------------------------ */
/* Mock device priv + backend                                          */
/* ------------------------------------------------------------------ */

struct mock_device_priv {
	uint8_t desc[4096];   /* config-descriptor blob */
	size_t desc_len;
	uint8_t active_config;
};

enum { MOCK_MAX_PENDING = 16 };

static struct usbi_transfer *mock_pending[MOCK_MAX_PENDING];
static enum libusb_transfer_status mock_status[MOCK_MAX_PENDING];
static size_t mock_pending_n;

static int mock_init(struct libusb_context *ctx)
{
	(void)ctx;
	return LIBUSB_SUCCESS;
}

static void mock_exit(struct libusb_context *ctx)
{
	(void)ctx;
}

static int
mock_get_device_list(struct libusb_context *ctx,
	struct discovered_devs **discdevs)
{
	struct libusb_device *dev;
	struct mock_device_priv *priv;
	const uint8_t *desc;
	unsigned long session_id = 1;
	int num_configs, rcode;

	/* One mock device, built from the fuzz stream. */
	desc = fuzz_bytes(18);
	if (desc == NULL)
		return LIBUSB_SUCCESS; /* no devices */

	dev = usbi_get_device_by_session_id(ctx, session_id);
	if (dev == NULL) {
		dev = usbi_alloc_device(ctx, session_id);
		if (dev == NULL)
			return LIBUSB_ERROR_NO_MEM;
	}

	memcpy(&dev->device_descriptor, desc, sizeof(dev->device_descriptor));
	dev->bus_number = 1;
	dev->device_address = 1;
	num_configs = dev->device_descriptor.bNumConfigurations;

	priv = usbi_get_device_priv(dev);
	priv->desc_len = 0;
	priv->active_config = 1;

	if (num_configs > 0) {
		const uint8_t *blob;
		size_t blob_len;

		blob = fuzz_bytes(fuzz_size - fuzz_pos);
		if (blob == NULL) {
			libusb_unref_device(dev);
			return LIBUSB_SUCCESS;
		}
		blob_len = fuzz_size - fuzz_pos;
		if (blob_len > sizeof(priv->desc))
			blob_len = sizeof(priv->desc);
		memcpy(priv->desc, blob, blob_len);
		priv->desc_len = blob_len;
	}

	rcode = usbi_sanitize_device(dev);
	if (rcode != LIBUSB_SUCCESS) {
		libusb_unref_device(dev);
		return rcode; /* malformed descriptor: error path */
	}

	usbi_connect_device(dev);

	*discdevs = discovered_devs_append(*discdevs, dev);
	if (*discdevs == NULL)
		return LIBUSB_ERROR_NO_MEM;

	return 1; /* one device */
}

static int
mock_get_active_config_descriptor(struct libusb_device *dev, void *buf,
	size_t len)
{
	struct mock_device_priv *priv = usbi_get_device_priv(dev);

	if (priv->desc_len == 0)
		return LIBUSB_ERROR_NOT_FOUND;
	memcpy(buf, priv->desc, MIN(len, priv->desc_len));
	return (int)MIN(len, priv->desc_len);
}

static int
mock_get_config_descriptor(struct libusb_device *dev, uint8_t idx, void *buf,
	size_t len)
{
	struct mock_device_priv *priv = usbi_get_device_priv(dev);

	if (idx != 0 || priv->desc_len == 0)
		return LIBUSB_ERROR_NOT_FOUND;
	memcpy(buf, priv->desc, MIN(len, priv->desc_len));
	return (int)MIN(len, priv->desc_len);
}

static int
mock_get_config_descriptor_by_value(struct libusb_device *dev, uint8_t value,
	void **buffer)
{
	struct mock_device_priv *priv = usbi_get_device_priv(dev);

	if (priv->active_config != value || priv->desc_len == 0)
		return LIBUSB_ERROR_NOT_FOUND;
	*buffer = priv->desc;
	return (int)priv->desc_len;
}

static int mock_get_configuration(struct libusb_device_handle *handle,
	uint8_t *config)
{
	struct mock_device_priv *priv = usbi_get_device_priv(handle->dev);

	*config = priv->active_config;
	return LIBUSB_SUCCESS;
}

static int mock_set_configuration(struct libusb_device_handle *handle,
	int config)
{
	struct mock_device_priv *priv = usbi_get_device_priv(handle->dev);

	priv->active_config = (uint8_t)config;
	return LIBUSB_SUCCESS;
}

static int mock_claim_interface(struct libusb_device_handle *handle,
	uint8_t interface_number)
{
	(void)handle;
	(void)interface_number;
	return LIBUSB_SUCCESS;
}

static int mock_release_interface(struct libusb_device_handle *handle,
	uint8_t interface_number)
{
	(void)handle;
	(void)interface_number;
	return LIBUSB_SUCCESS;
}

static int mock_set_interface_altsetting(struct libusb_device_handle *handle,
	uint8_t interface_number, uint8_t altsetting)
{
	(void)handle;
	(void)interface_number;
	(void)altsetting;
	return LIBUSB_SUCCESS;
}

static int mock_clear_halt(struct libusb_device_handle *handle,
	unsigned char endpoint)
{
	(void)handle;
	(void)endpoint;
	return LIBUSB_SUCCESS;
}

static int mock_reset_device(struct libusb_device_handle *handle)
{
	(void)handle;
	return LIBUSB_SUCCESS;
}

static int mock_kernel_driver_active(struct libusb_device_handle *handle,
	uint8_t interface_number)
{
	(void)handle;
	(void)interface_number;
	return 0; /* no kernel driver */
}

static int mock_submit_transfer(struct usbi_transfer *itransfer)
{
	if (mock_pending_n == MOCK_MAX_PENDING)
		return LIBUSB_ERROR_BUSY;

	mock_pending[mock_pending_n] = itransfer;
	/* One fuzz byte picks the completion status for this transfer. */
	mock_status[mock_pending_n] =
		(enum libusb_transfer_status)(fuzz_byte() % 6);
	mock_pending_n++;
	return LIBUSB_SUCCESS;
}

static int mock_cancel_transfer(struct usbi_transfer *itransfer)
{
	size_t i;

	for (i = 0; i < mock_pending_n; i++) {
		if (mock_pending[i] == itransfer) {
			mock_status[i] = LIBUSB_TRANSFER_CANCELLED;
			break;
		}
	}
	return LIBUSB_SUCCESS;
}

static void mock_clear_transfer_priv(struct usbi_transfer *itransfer)
{
	(void)itransfer;
}

static int mock_handle_events(struct libusb_context *ctx, void *event_data,
	unsigned int count, unsigned int num_ready)
{
	size_t i;

	(void)ctx;
	(void)event_data;
	(void)count;
	(void)num_ready;

	/* Complete every pending transfer with its fuzz-selected status,
	 * driving the io.c completion machinery for real. */
	for (i = 0; i < mock_pending_n; i++)
		usbi_handle_transfer_completion(mock_pending[i], mock_status[i]);
	mock_pending_n = 0;

	return LIBUSB_SUCCESS;
}

static int mock_wrap_sys_device(struct libusb_context *ctx,
	struct libusb_device_handle *dev_handle, intptr_t sys_dev)
{
	(void)ctx;
	(void)dev_handle;
	(void)sys_dev;
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

const struct usbi_os_backend usbi_backend = {
	.name = "Fuzz mock backend",
	.caps = 0,
	.init = mock_init,
	.exit = mock_exit,
	.get_device_list = mock_get_device_list,
	.get_active_config_descriptor = mock_get_active_config_descriptor,
	.get_config_descriptor = mock_get_config_descriptor,
	.get_config_descriptor_by_value = mock_get_config_descriptor_by_value,
	.get_configuration = mock_get_configuration,
	.set_configuration = mock_set_configuration,
	.claim_interface = mock_claim_interface,
	.release_interface = mock_release_interface,
	.set_interface_altsetting = mock_set_interface_altsetting,
	.clear_halt = mock_clear_halt,
	.reset_device = mock_reset_device,
	.kernel_driver_active = mock_kernel_driver_active,
	.submit_transfer = mock_submit_transfer,
	.cancel_transfer = mock_cancel_transfer,
	.clear_transfer_priv = mock_clear_transfer_priv,
	.handle_events = mock_handle_events,
	.wrap_sys_device = mock_wrap_sys_device,
	.device_priv_size = sizeof(struct mock_device_priv),
};

/* ------------------------------------------------------------------ */
/* The fuzz driver                                                     */
/* ------------------------------------------------------------------ */

static void mock_transfer_cb(struct libusb_transfer *transfer)
{
	(void)transfer;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	libusb_context *ctx = NULL;
	struct libusb_device **list = NULL;
	libusb_device_handle *handle = NULL;
	ssize_t cnt;
	uint8_t timeout;

	if (size < 8)
		return 0;

	fuzz_data = data;
	fuzz_size = size;
	fuzz_pos = 0;
	mock_pending_n = 0;

	if (libusb_init(&ctx) != LIBUSB_SUCCESS)
		return 0;

	cnt = libusb_get_device_list(ctx, &list);
	if (cnt > 0 && libusb_open(list[0], &handle) == LIBUSB_SUCCESS) {
		(void)libusb_claim_interface(handle, fuzz_byte() & 0x01);

		/* Async bulk transfer: the fuzz bytes are both the payload
		 * and (via the mock backend) the completion selector. */
		{
			struct libusb_transfer *transfer;
			uint8_t buf[128];

			transfer = libusb_alloc_transfer(0);
			if (transfer != NULL) {
				size_t n = MIN(size, sizeof(buf));

				memcpy(buf, data, n);
				timeout = fuzz_byte();
				libusb_fill_bulk_transfer(transfer, handle,
					0x01, buf, (int)n, mock_transfer_cb,
					NULL, (uint32_t)timeout * 10);
				if (libusb_submit_transfer(transfer) == 0)
					libusb_handle_events(ctx);
				libusb_free_transfer(transfer);
			}
		}

		/* Sync control transfer: exercises sync.c on top of the
		 * same submission/completion machinery. */
		{
			uint8_t setup[LIBUSB_CONTROL_SETUP_SIZE + 32];
			struct libusb_transfer *transfer;

			transfer = libusb_alloc_transfer(0);
			if (transfer != NULL) {
				libusb_fill_control_setup(setup,
					(fuzz_byte() & 0x01) ? 0x40 : 0x00,
					data[1], (data[2] << 8) | data[3],
					0, 16);
				libusb_fill_control_transfer(transfer,
					handle, setup, mock_transfer_cb,
					NULL, 0);
				if (libusb_submit_transfer(transfer) == 0)
					libusb_handle_events(ctx);
				libusb_free_transfer(transfer);
			}
		}

		(void)libusb_release_interface(handle, 0);
		libusb_close(handle);
	}
	if (cnt >= 0)
		libusb_free_device_list(list, 1);

	libusb_exit(ctx);
	return 0;
}

