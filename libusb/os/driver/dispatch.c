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

NTSTATUS DDKAPI dispatch(DEVICE_OBJECT *device_object, IRP *irp)
{
  libusb_device_t *dev = device_object->DeviceExtension;

  switch(IoGetCurrentIrpStackLocation(irp)->MajorFunction) 
    {
    case IRP_MJ_PNP:
      return dispatch_pnp(dev, irp);
      
    case IRP_MJ_POWER:
      return dispatch_power(dev, irp);
    }

  /* since this driver may run as an upper filter we have to check whether */
  /* the IRP is sent to this device object or to the lower one */
  if(accept_irp(dev, irp))
    {
      switch(IoGetCurrentIrpStackLocation(irp)->MajorFunction) 
        {
        case IRP_MJ_DEVICE_CONTROL:
          
          if(dev->is_started)
            {
              return dispatch_ioctl(dev, irp);
            }
          else /* not started yet */
            {
              return complete_irp(irp, STATUS_INVALID_DEVICE_STATE, 0);
            }

        case IRP_MJ_CREATE:
          
          if(dev->is_started)
            {
              if(InterlockedIncrement(&dev->ref_count) == 1)
                {
                  if(dev->power_state.DeviceState != PowerDeviceD0)
                    {
                      /* power up the device, block until the call */
                      /* completes */
                      power_set_device_state(dev, PowerDeviceD0, TRUE);
                    }
                }

              return complete_irp(irp, STATUS_SUCCESS, 0);
            }
          else /* not started yet */
            {
              return complete_irp(irp, STATUS_INVALID_DEVICE_STATE, 0);
            }
          
        case IRP_MJ_CLOSE:
          
          if(!InterlockedDecrement(&dev->ref_count))
            {
              /* release all interfaces when the last handle is closed */
              release_all_interfaces(dev);
            }
          return complete_irp(irp, STATUS_SUCCESS, 0);
          
        case IRP_MJ_CLEANUP:

          return complete_irp(irp, STATUS_SUCCESS, 0);
          
        default:
          return complete_irp(irp, STATUS_NOT_SUPPORTED, 0);
        }
    }
  else /* the IRP is for the lower device object */
    {
      return pass_irp_down(dev, irp, NULL, NULL);
    }
}

