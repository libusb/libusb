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



NTSTATUS set_descriptor(libusb_device_t *dev,
                        void *buffer, int size, int type, int recipient,
                        int index, int language_id, int *sent, int timeout)
{
  NTSTATUS status = STATUS_SUCCESS;
  URB urb;

  DEBUG_PRINT_NL();
  DEBUG_MESSAGE("set_descriptor(): buffer size %d", size);
  DEBUG_MESSAGE("set_descriptor(): type %04d", type);
  DEBUG_MESSAGE("set_descriptor(): recipient %04d", recipient);
  DEBUG_MESSAGE("set_descriptor(): index %04d", index);
  DEBUG_MESSAGE("set_descriptor(): language id %04d", language_id);
  DEBUG_MESSAGE("set_descriptor(): timeout %d", timeout);

  memset(&urb, 0, sizeof(struct _URB_CONTROL_DESCRIPTOR_REQUEST));


  switch(recipient)
    {
    case USB_RECIP_DEVICE:
      urb.UrbHeader.Function = URB_FUNCTION_SET_DESCRIPTOR_TO_DEVICE;
      break;
    case USB_RECIP_INTERFACE:
      urb.UrbHeader.Function = URB_FUNCTION_SET_DESCRIPTOR_TO_INTERFACE;
      break;
    case USB_RECIP_ENDPOINT:
      urb.UrbHeader.Function = URB_FUNCTION_SET_DESCRIPTOR_TO_ENDPOINT;
      break;
    default:
      DEBUG_ERROR("set_descriptor(): invalid recipient");
      return STATUS_INVALID_PARAMETER;
    }

  urb.UrbHeader.Length = sizeof(struct _URB_CONTROL_DESCRIPTOR_REQUEST);
  urb.UrbControlDescriptorRequest.TransferBufferLength = size;
  urb.UrbControlDescriptorRequest.TransferBuffer = buffer;
  urb.UrbControlDescriptorRequest.DescriptorType = (UCHAR)type;
  urb.UrbControlDescriptorRequest.Index = (UCHAR)index;
  urb.UrbControlDescriptorRequest.LanguageId = (USHORT)language_id;
	
  status = call_usbd(dev, &urb, IOCTL_INTERNAL_USB_SUBMIT_URB, timeout);
  
  if(!NT_SUCCESS(status) || !USBD_SUCCESS(urb.UrbHeader.Status))
    {
      DEBUG_ERROR("set_descriptor(): setting descriptor failed: status: "
                  "0x%x, urb-status: 0x%x", status, urb.UrbHeader.Status);
    }
  else
    {
      *sent = urb.UrbControlDescriptorRequest.TransferBufferLength;
    }
  return status;
}
