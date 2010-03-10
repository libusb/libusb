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



NTSTATUS get_interface(libusb_device_t *dev,
                       int interface, unsigned char *altsetting, 
                       int *ret, int timeout)
{
  NTSTATUS status = STATUS_SUCCESS;
  URB urb;

  DEBUG_PRINT_NL();
  DEBUG_MESSAGE("get_interface(): interface %d", interface);
  DEBUG_MESSAGE("get_interface(): timeout %d", timeout);

  if(!dev->config.value)
    {
      DEBUG_ERROR("get_interface(): invalid configuration 0"); 
      return STATUS_INVALID_DEVICE_STATE;
    }

  memset(&urb, 0, sizeof(URB));

  urb.UrbHeader.Function = URB_FUNCTION_GET_INTERFACE;
  urb.UrbHeader.Length = sizeof(struct _URB_CONTROL_GET_INTERFACE_REQUEST);
  urb.UrbControlGetInterfaceRequest.TransferBufferLength = 1;
  urb.UrbControlGetInterfaceRequest.TransferBuffer = altsetting;
  urb.UrbControlGetInterfaceRequest.Interface = (USHORT)interface;
  
  status = call_usbd(dev, &urb, IOCTL_INTERNAL_USB_SUBMIT_URB, timeout);
  
  if(!NT_SUCCESS(status) || !USBD_SUCCESS(urb.UrbHeader.Status))
    {
      DEBUG_ERROR("get_interface(): getting interface "
                  "failed: status: 0x%x, urb-status: 0x%x", 
                  status, urb.UrbHeader.Status);
      *ret = 0;
    }
  else
    {
      *ret = urb.UrbControlGetInterfaceRequest.TransferBufferLength;
      DEBUG_MESSAGE("get_interface(): current altsetting is %d", *altsetting); 
    }

  return status;
}


