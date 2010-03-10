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



NTSTATUS get_status(libusb_device_t *dev, int recipient,
                    int index, char *status, int *ret, int timeout)
{
  NTSTATUS _status = STATUS_SUCCESS;
  URB urb;

  DEBUG_PRINT_NL();
  DEBUG_MESSAGE("get_status(): recipient %02d", recipient);
  DEBUG_MESSAGE("get_status(): index %04d", index);
  DEBUG_MESSAGE("get_status(): timeout %d", timeout);

  memset(&urb, 0, sizeof(URB));

  switch(recipient)
    {
    case USB_RECIP_DEVICE:
      urb.UrbHeader.Function = URB_FUNCTION_GET_STATUS_FROM_DEVICE;
      break;
    case USB_RECIP_INTERFACE:
      urb.UrbHeader.Function = URB_FUNCTION_GET_STATUS_FROM_INTERFACE;
      break;
    case USB_RECIP_ENDPOINT:
      urb.UrbHeader.Function = URB_FUNCTION_GET_STATUS_FROM_ENDPOINT;
      break;
    case USB_RECIP_OTHER:
      urb.UrbHeader.Function = URB_FUNCTION_GET_STATUS_FROM_OTHER;
      break;
    default:
      DEBUG_ERROR("get_status(): invalid recipient");
      return STATUS_INVALID_PARAMETER;
    }

  urb.UrbHeader.Length = sizeof(struct _URB_CONTROL_GET_STATUS_REQUEST);
  urb.UrbControlGetStatusRequest.TransferBufferLength = 2;
  urb.UrbControlGetStatusRequest.TransferBuffer = status; 
  urb.UrbControlGetStatusRequest.Index = (USHORT)index; 
	
  _status = call_usbd(dev, &urb, IOCTL_INTERNAL_USB_SUBMIT_URB, timeout);
      
  if(!NT_SUCCESS(_status) || !USBD_SUCCESS(urb.UrbHeader.Status))
    {
      DEBUG_ERROR("get_status(): getting status failed: "
                   "status: 0x%x, urb-status: 0x%x", 
                   _status, urb.UrbHeader.Status);
      *ret = 0;
    }
  else
    {
      *ret = urb.UrbControlGetStatusRequest.TransferBufferLength;
    }

  return _status;
}

