/* Fuzz the sysfs/usbfs descriptor-blob parsing in libusb/os/linux_usbfs.c.
 *
 * On Linux libusb learns a device's descriptors from the kernel: either the
 * sysfs "descriptors" attribute or a read of the usbfs device node. The
 * kernel passes through descriptor bytes reported by the (potentially
 * hostile) device, so parse_config_descriptors() and seek_to_next_config()
 * operate on attacker-influenced data. Both have file-local linkage and need
 * a struct libusb_device with its linux_device_priv, so this target includes
 * the backend source directly (same unity-include approach as
 * fuzz_descriptor_parsers) and drives both the usbfs and sysfs modes on
 * every input.
 *
 * Built as part of the OSS-Fuzz integration; not exercised by the autotools
 * test suite.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "libusbi.h"
#include "../../libusb/os/linux_usbfs.c"

/* Stubs for symbols that linux_usbfs.c references from other translation
 * units but that the parsing paths exercised here never really need. */
void usbi_log(struct libusb_context *ctx, enum libusb_log_level level,
              const char *function, const char *format, ...) {
    (void)ctx; (void)level; (void)function; (void)format;
}
usbi_mutex_static_t active_contexts_lock = USBI_MUTEX_INITIALIZER;
struct list_head active_contexts_list = { &active_contexts_list, &active_contexts_list };
libusb_device *libusb_ref_device(libusb_device *dev) { (void)dev; return dev; }
void libusb_unref_device(libusb_device *dev) { (void)dev; }
const char *libusb_error_name(int error_code) { (void)error_code; return "?"; }
void usbi_handle_disconnect(struct libusb_context *ctx, struct libusb_device_handle *h) { (void)ctx; (void)h; }
int usbi_handle_transfer_completion(struct usbi_transfer *itransfer, enum libusb_transfer_status status) { (void)itransfer; (void)status; return 0; }
int usbi_handle_transfer_cancellation(struct usbi_transfer *itransfer) { (void)itransfer; return 0; }
struct libusb_device *usbi_alloc_device(struct libusb_context *ctx, unsigned long session_id) { (void)ctx; (void)session_id; return NULL; }
void usbi_connect_device(struct libusb_device *dev) { (void)dev; }
void usbi_disconnect_device(struct libusb_device *dev) { (void)dev; }
enum libusb_error usbi_sanitize_device(struct libusb_device *dev) { (void)dev; return LIBUSB_ERROR_NOT_SUPPORTED; }
struct libusb_device *usbi_get_device_by_session_id(struct libusb_context *ctx, unsigned long session_id) { (void)ctx; (void)session_id; return NULL; }
int usbi_add_event_source(struct libusb_context *ctx, usbi_os_handle_t os_handle, short poll_events) { (void)ctx; (void)os_handle; (void)poll_events; return 0; }
void usbi_remove_event_source(struct libusb_context *ctx, usbi_os_handle_t os_handle) { (void)ctx; (void)os_handle; }
int usbi_get_config_string_index(libusb_device *dev, uint8_t config_value, uint8_t *index_out) { (void)dev; (void)config_value; (void)index_out; return LIBUSB_ERROR_NOT_SUPPORTED; }
int usbi_get_interface_string_index(libusb_device *dev, uint8_t config_value, uint8_t interface_number, uint8_t alt_setting, uint8_t *index_out) { (void)dev; (void)config_value; (void)interface_number; (void)alt_setting; (void)index_out; return LIBUSB_ERROR_NOT_SUPPORTED; }
int linux_udev_start_event_monitor(void) { return -1; }
int linux_udev_stop_event_monitor(void) { return -1; }
int linux_udev_scan_devices(struct libusb_context *ctx) { (void)ctx; return -1; }
void linux_udev_hotplug_poll(void) {}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct libusb_device *dev;
    struct linux_device_priv *priv;
    uint8_t *copy;
    size_t dev_sz = PTR_ALIGN(sizeof(*dev)) + sizeof(struct linux_device_priv);

    /* Need at least a device descriptor; the blob is exactly what the
     * kernel file would contain: device descriptor followed by the raw
     * configuration descriptor stream. */
    if (size < LIBUSB_DT_DEVICE_SIZE || size > 8192)
        return 0;

    /* Fresh exact-size copies so any byte read past the end is caught. */
    dev = calloc(1, dev_sz);
    copy = malloc(size);
    if (!dev || !copy) {
        free(dev);
        free(copy);
        return 0;
    }
    memcpy(copy, data, size);

    priv = (struct linux_device_priv *)usbi_get_device_priv(dev);
    priv->descriptors = copy;
    priv->descriptors_len = size;

    /* Pass 1: usbfs mode (no sysfs directory). */
    priv->sysfs_dir = NULL;
    parse_config_descriptors(dev);
    free(priv->config_descriptors);
    priv->config_descriptors = NULL;

    /* Pass 2: sysfs mode, exercising seek_to_next_config() when the device
     * claims more than one configuration. */
    priv->sysfs_dir = (char *)"/sys/devices/mock";
    parse_config_descriptors(dev);
    free(priv->config_descriptors);
    priv->config_descriptors = NULL;

    free(copy);
    free(dev);
    return 0;
}
