/* LIBUSB-WIN32, Generic Windows USB Library
 * Copyright (c) 2002-2005 Stephan Meyer <ste_meyer@web.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#ifndef __LIBUSB_DRIVER_H__
#define __LIBUSB_DRIVER_H__

#ifdef __GNUC__
#include <ddk/usb100.h>
#include <ddk/usbdi.h>
#include <ddk/winddk.h>
#include "usbdlib_gcc.h"
#else
#include <wdm.h>
#include "usbdi.h"
#include "usbdlib.h"
#endif

#include <wchar.h>
#include <initguid.h>

#undef interface

#include "driver_debug.h"
#include "driver_api.h"

/* some missing defines */
#ifdef __GNUC__

#define USBD_TRANSFER_DIRECTION_OUT       0   
#define USBD_TRANSFER_DIRECTION_BIT       0
#define USBD_TRANSFER_DIRECTION_IN        (1 << USBD_TRANSFER_DIRECTION_BIT)
#define USBD_SHORT_TRANSFER_OK_BIT        1
#define USBD_SHORT_TRANSFER_OK            (1 << USBD_SHORT_TRANSFER_OK_BIT)
#define USBD_START_ISO_TRANSFER_ASAP_BIT  2
#define USBD_START_ISO_TRANSFER_ASAP   (1 << USBD_START_ISO_TRANSFER_ASAP_BIT)

#endif


#define USB_RECIP_DEVICE    0x00
#define USB_RECIP_INTERFACE 0x01
#define USB_RECIP_ENDPOINT  0x02
#define USB_RECIP_OTHER     0x03

#define USB_TYPE_STANDARD   0x00
#define USB_TYPE_CLASS      0x01
#define USB_TYPE_VENDOR	    0x02


#define LIBUSB0_NT_DEVICE_NAME L"\\Device\\libusb0"
#define LIBUSB0_SYMBOLIC_LINK_NAME L"\\DosDevices\\libusb0-"

#define LIBUSB0_MAX_NUMBER_OF_ENDPOINTS  32
#define LIBUSB0_MAX_NUMBER_OF_INTERFACES 32


#define LIBUSB0_DEFAULT_TIMEOUT 5000
#define LIBUSB0_MAX_CONTROL_TRANSFER_TIMEOUT 240000


#ifndef __GNUC__
#define DDKAPI
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE (!(FALSE))
#endif

typedef int bool_t;

#include <pshpack1.h>

typedef struct 
{ 
  unsigned char length;
  unsigned char type;
} usb_descriptor_header_t;

#include <poppack.h>


typedef struct
{
  long usage_count;
  int remove_pending;
  KEVENT event;
} libusb_remove_lock_t;

typedef struct
{
  int address;
  USBD_PIPE_HANDLE handle;
} libusb_endpoint_t;

typedef struct
{
  int valid;
  int claimed;
  libusb_endpoint_t endpoints[LIBUSB0_MAX_NUMBER_OF_ENDPOINTS];
} libusb_interface_t;


typedef struct
{
  DEVICE_OBJECT	*self;
  DEVICE_OBJECT	*physical_device_object;
  DEVICE_OBJECT	*next_stack_device;
  DEVICE_OBJECT	*target_device;
  libusb_remove_lock_t remove_lock; 
  LONG ref_count;
  bool_t is_filter;
  bool_t is_started;
  bool_t surprise_removal_ok;
  int id;
  struct {
    USBD_CONFIGURATION_HANDLE handle;
    int value;
    libusb_interface_t interfaces[LIBUSB0_MAX_NUMBER_OF_INTERFACES];
  } config;
  POWER_STATE power_state;
  DEVICE_POWER_STATE device_power_states[PowerSystemMaximum];
} libusb_device_t;



NTSTATUS DDKAPI add_device(DRIVER_OBJECT *driver_object, 
                           DEVICE_OBJECT *physical_device_object);

NTSTATUS DDKAPI dispatch(DEVICE_OBJECT *device_object, IRP *irp);
NTSTATUS dispatch_pnp(libusb_device_t *dev, IRP *irp);
NTSTATUS dispatch_power(libusb_device_t *dev, IRP *irp);
NTSTATUS dispatch_ioctl(libusb_device_t *dev, IRP *irp);

NTSTATUS complete_irp(IRP *irp, NTSTATUS status, ULONG info);

NTSTATUS call_usbd(libusb_device_t *dev, void *urb,
                   ULONG control_code, int timeout);
NTSTATUS pass_irp_down(libusb_device_t *dev, IRP *irp, 
                       PIO_COMPLETION_ROUTINE completion_routine, 
                       void *context);

bool_t accept_irp(libusb_device_t *dev, IRP *irp);

bool_t get_pipe_handle(libusb_device_t *dev, int endpoint_address, 
                       USBD_PIPE_HANDLE *pipe_handle);
void clear_pipe_info(libusb_device_t *dev);
bool_t update_pipe_info(libusb_device_t *dev,
                        USBD_INTERFACE_INFORMATION *interface_info);

void remove_lock_initialize(libusb_device_t *dev);
NTSTATUS remove_lock_acquire(libusb_device_t *dev);
void remove_lock_release(libusb_device_t *dev);
void remove_lock_release_and_wait(libusb_device_t *dev);

NTSTATUS set_configuration(libusb_device_t *dev,
                           int configuration, int timeout);
NTSTATUS get_configuration(libusb_device_t *dev,
                           unsigned char *configuration, int *ret, 
                           int timeout);
NTSTATUS set_interface(libusb_device_t *dev,
                       int interface, int altsetting, int timeout);
NTSTATUS get_interface(libusb_device_t *dev,
                       int interface, unsigned char *altsetting, 
                       int *ret, int timeout);
NTSTATUS set_feature(libusb_device_t *dev,
                     int recipient, int index, int feature, int timeout);
NTSTATUS clear_feature(libusb_device_t *dev,
                       int recipient, int index, int feature, int timeout);
NTSTATUS get_status(libusb_device_t *dev, int recipient,
                    int index, char *status, int *ret, int timeout);
NTSTATUS set_descriptor(libusb_device_t *dev,
                        void *buffer, int size, 
                        int type, int recipient, int index, int language_id, 
                        int *sent, int timeout);
NTSTATUS get_descriptor(libusb_device_t *dev, void *buffer, int size, 
                        int type, int recipient, int index, int language_id,
                        int *received, int timeout);
USB_CONFIGURATION_DESCRIPTOR *
get_config_descriptor(libusb_device_t *dev, int value, int *size);

NTSTATUS transfer(libusb_device_t *dev, IRP *irp, 
                  int direction, int urb_function, int endpoint, 
                  int packet_size, MDL *buffer, int size);

NTSTATUS vendor_class_request(libusb_device_t *dev,
                              int type, int recipient,
                              int request, int value, int index,
                              void *buffer, int size, int direction,
                              int *ret, int timeout);

NTSTATUS abort_endpoint(libusb_device_t *dev, int endpoint, int timeout);
NTSTATUS reset_endpoint(libusb_device_t *dev, int endpoint, int timeout);
NTSTATUS reset_device(libusb_device_t *dev, int timeout);

NTSTATUS claim_interface(libusb_device_t *dev, int interface);
NTSTATUS release_interface(libusb_device_t *dev, int interface);
NTSTATUS release_all_interfaces(libusb_device_t *dev);


bool_t reg_get_hardware_id(DEVICE_OBJECT *physical_device_object, 
                           char *data, int size);
bool_t reg_get_properties(libusb_device_t *dev);


void power_set_device_state(libusb_device_t *dev, 
                            DEVICE_POWER_STATE device_state, bool_t block);

USB_INTERFACE_DESCRIPTOR *
find_interface_desc(USB_CONFIGURATION_DESCRIPTOR *config_desc, 
                    unsigned int size, int interface_number, int altsetting);



#endif
