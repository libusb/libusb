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


NTSTATUS get_configuration(libusb_device_t *dev,
                           unsigned char *configuration, int *ret, 
                           int timeout)
{
  NTSTATUS status = STATUS_SUCCESS;
  URB urb;

  DEBUG_PRINT_NL();
  DEBUG_MESSAGE("get_configuration(): timeout %d", timeout);

  memset(&urb, 0, sizeof(URB));

  urb.UrbHeader.Function = URB_FUNCTION_GET_CONFIGURATION;
  urb.UrbHeader.Length = sizeof(struct _URB_CONTROL_GET_CONFIGURATION_REQUEST);
  urb.UrbControlGetConfigurationRequest.TransferBufferLength = 1;
  urb.UrbControlGetConfigurationRequest.TransferBuffer = configuration;


  status = call_usbd(dev, &urb, IOCTL_INTERNAL_USB_SUBMIT_URB, timeout);

  if(!NT_SUCCESS(status) || !USBD_SUCCESS(urb.UrbHeader.Status))
    {
      DEBUG_ERROR("get_configuration(): getting configuration failed: "
                  "status: 0x%x, urb-status: 0x%x",
                  status, urb.UrbHeader.Status);
      *ret = 0;
    }
  else
    {
      DEBUG_MESSAGE("get_configuration(): current configuration is: %d", 
                    *configuration);
      *ret = urb.UrbControlGetConfigurationRequest.TransferBufferLength;
    }

  return status;
}
