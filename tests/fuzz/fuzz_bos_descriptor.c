#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <libusb.h>

/* Fuzz the public BOS device-capability parsers.
   We construct a valid BOS dev-cap header (3 bytes) + variable payload.
   No hardware needed; ctx=NULL is fine. */

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (!data) return 0;

  /* bLength is 3 (header) + payload; must fit in one byte. */
  uint8_t payload_len = (size > 252) ? 252 : (uint8_t)size;  /* 255 - 3 = 252 */
  size_t total_len = 3u + (size_t)payload_len;

  /* Allocate header + payload for the flexible array member. */
  struct libusb_bos_dev_capability_descriptor *devcap =
      (struct libusb_bos_dev_capability_descriptor*)
      malloc(sizeof(*devcap) + payload_len);
  if (!devcap) return 0;

  devcap->bLength         = (uint8_t)total_len;
  devcap->bDescriptorType = LIBUSB_DT_DEVICE_CAPABILITY; /* 0x10 */
  /* Copy fuzz bytes into the variable-length payload. */
  if (payload_len) memcpy(devcap->dev_capability_data, data, payload_len);

  /* 1) USB 2.0 Extension dev-cap */
  devcap->bDevCapabilityType = LIBUSB_BT_USB_2_0_EXTENSION;
  struct libusb_usb_2_0_extension_descriptor *d20 = NULL;
  (void)libusb_get_usb_2_0_extension_descriptor(NULL, devcap, &d20);
  libusb_free_usb_2_0_extension_descriptor(d20);

  /* 2) SuperSpeed USB Device Capability dev-cap */
  devcap->bDevCapabilityType = LIBUSB_BT_SS_USB_DEVICE_CAPABILITY;
  struct libusb_ss_usb_device_capability_descriptor *dss = NULL;
  (void)libusb_get_ss_usb_device_capability_descriptor(NULL, devcap, &dss);
  libusb_free_ss_usb_device_capability_descriptor(dss);

  /* 3) Container ID dev-cap */
  devcap->bDevCapabilityType = LIBUSB_BT_CONTAINER_ID;
  struct libusb_container_id_descriptor *dcid = NULL;
  (void)libusb_get_container_id_descriptor(NULL, devcap, &dcid);
  libusb_free_container_id_descriptor(dcid);

  free(devcap);
  return 0;
}