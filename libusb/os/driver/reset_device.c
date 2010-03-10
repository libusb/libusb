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


NTSTATUS reset_device(libusb_device_t *dev, int timeout)
{
  NTSTATUS status = STATUS_SUCCESS;

  DEBUG_MESSAGE("reset_device()");

  status = call_usbd(dev, NULL, IOCTL_INTERNAL_USB_RESET_PORT, timeout);
  
  if(!NT_SUCCESS(status))
    {
      DEBUG_ERROR("reset_device(): IOCTL_INTERNAL_USB_RESET_PORT failed: "
                  "status: 0x%x", status);
    }

  status = call_usbd(dev, NULL, IOCTL_INTERNAL_USB_CYCLE_PORT, timeout);
  
  if(!NT_SUCCESS(status))
    {
      DEBUG_ERROR("reset_device(): IOCTL_INTERNAL_USB_CYCLE_PORT failed: "
                  "status: 0x%x", status);
    }

  return status;
}
