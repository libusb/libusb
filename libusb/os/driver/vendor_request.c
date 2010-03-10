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


#include "libusb_driver.h"


NTSTATUS vendor_class_request(libusb_device_t *dev,
                              int type, int recipient,
                              int request, int value, int index, 
                              void *buffer, int size, int direction,
                              int *ret, int timeout)
{
  NTSTATUS status = STATUS_SUCCESS;
  URB urb;

  *ret = 0;

  DEBUG_PRINT_NL();

  memset(&urb, 0, sizeof(struct _URB_CONTROL_VENDOR_OR_CLASS_REQUEST));

  switch(type)
    {
    case USB_TYPE_CLASS:
      DEBUG_MESSAGE("vendor_class_request(): type: class");
      switch(recipient)
        {
        case USB_RECIP_DEVICE:
          DEBUG_MESSAGE("vendor_class_request(): recipient: device");
          urb.UrbHeader.Function = URB_FUNCTION_CLASS_DEVICE;
          break;
        case USB_RECIP_INTERFACE:
          DEBUG_MESSAGE("vendor_class_request(): recipient: interface");
          urb.UrbHeader.Function = URB_FUNCTION_CLASS_INTERFACE;
          break;
        case USB_RECIP_ENDPOINT:
          DEBUG_MESSAGE("vendor_class_request(): recipient: endpoint");
          urb.UrbHeader.Function = URB_FUNCTION_CLASS_ENDPOINT;
          break;
        case USB_RECIP_OTHER:
          DEBUG_MESSAGE("vendor_class_request(): recipient: other");
          urb.UrbHeader.Function = URB_FUNCTION_CLASS_OTHER;
          break;
        default:
          DEBUG_ERROR("vendor_class_request(): invalid recipient");
          return STATUS_INVALID_PARAMETER;
        }
      break;
    case USB_TYPE_VENDOR:
      DEBUG_MESSAGE("vendor_class_request(): type: vendor");
      switch(recipient)
        {
        case USB_RECIP_DEVICE:
          DEBUG_MESSAGE("vendor_class_request(): recipient: device");
          urb.UrbHeader.Function = URB_FUNCTION_VENDOR_DEVICE;
          break;
        case USB_RECIP_INTERFACE:
          DEBUG_MESSAGE("vendor_class_request(): recipient: interface");
          urb.UrbHeader.Function = URB_FUNCTION_VENDOR_INTERFACE;
          break;
        case USB_RECIP_ENDPOINT:
          DEBUG_MESSAGE("vendor_class_request(): recipient: endpoint");
          urb.UrbHeader.Function = URB_FUNCTION_VENDOR_ENDPOINT;
          break;
        case USB_RECIP_OTHER:
          DEBUG_MESSAGE("vendor_class_request(): recipient: other");
          urb.UrbHeader.Function = URB_FUNCTION_VENDOR_OTHER;
          break;
        default:
          DEBUG_ERROR("vendor_class_request(): invalid recipient");
          return STATUS_INVALID_PARAMETER;
        }
      break;
    default:
      DEBUG_ERROR("vendor_class_request(): invalid type");
      return STATUS_INVALID_PARAMETER;
    }

  DEBUG_MESSAGE("vendor_class_request(): request: 0x%02x", request);
  DEBUG_MESSAGE("vendor_class_request(): value: 0x%04x", value);
  DEBUG_MESSAGE("vendor_class_request(): index: 0x%04x", index);
  DEBUG_MESSAGE("vendor_class_request(): size: %d", size);

  if(direction == USBD_TRANSFER_DIRECTION_IN)
    {
      DEBUG_MESSAGE("vendor_class_request(): direction: in");
    }
  else
    {
      DEBUG_MESSAGE("vendor_class_request(): direction: out");
    }

  DEBUG_MESSAGE("vendor_class_request(): timeout: %d", timeout);

  urb.UrbHeader.Length = sizeof(struct _URB_CONTROL_VENDOR_OR_CLASS_REQUEST);
  urb.UrbControlVendorClassRequest.TransferFlags 
    = direction | USBD_SHORT_TRANSFER_OK ;
  urb.UrbControlVendorClassRequest.TransferBufferLength = size;
  urb.UrbControlVendorClassRequest.TransferBufferMDL = NULL;
  urb.UrbControlVendorClassRequest.TransferBuffer = buffer;
  urb.UrbControlVendorClassRequest.Request = (UCHAR)request;
  urb.UrbControlVendorClassRequest.Value = (USHORT)value;
  urb.UrbControlVendorClassRequest.Index = (USHORT)index;
  
  status = call_usbd(dev, &urb, IOCTL_INTERNAL_USB_SUBMIT_URB, timeout);
  
  if(!NT_SUCCESS(status) || !USBD_SUCCESS(urb.UrbHeader.Status))
    {
     DEBUG_ERROR("vendor_class_request(): request failed: status: 0x%x, "
                 "urb-status: 0x%x", status, urb.UrbHeader.Status);
    }
  else
    {
      if(direction == USBD_TRANSFER_DIRECTION_IN)
        *ret = urb.UrbControlVendorClassRequest.TransferBufferLength;
      DEBUG_MESSAGE("vendor_class_request(): %d bytes transmitted", 
                    urb.UrbControlVendorClassRequest.TransferBufferLength);
    }

  return status;
}

