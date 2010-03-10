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



NTSTATUS set_configuration(libusb_device_t *dev, int configuration, 
                           int timeout)
{
  NTSTATUS status = STATUS_SUCCESS;
  URB urb, *urb_ptr = NULL;
  USB_CONFIGURATION_DESCRIPTOR *configuration_descriptor = NULL;
  USB_INTERFACE_DESCRIPTOR *interface_descriptor = NULL;
  USBD_INTERFACE_LIST_ENTRY *interfaces = NULL;
  int i, j, interface_number, desc_size;

  DEBUG_PRINT_NL();
  DEBUG_MESSAGE("set_configuration(): configuration %d", configuration);
  DEBUG_MESSAGE("set_configuration(): timeout %d", timeout);

  if(dev->config.value == configuration)
    {
      return STATUS_SUCCESS;
    }

  memset(&urb, 0, sizeof(URB));

  if(!configuration)
    {
      urb.UrbHeader.Function = URB_FUNCTION_SELECT_CONFIGURATION;
      urb.UrbHeader.Length = sizeof(struct _URB_SELECT_CONFIGURATION);

      status = call_usbd(dev, &urb, IOCTL_INTERNAL_USB_SUBMIT_URB, timeout);
      
      if(!NT_SUCCESS(status) || !USBD_SUCCESS(urb.UrbHeader.Status))
        {
          DEBUG_ERROR("set_configuration(): setting configuration %d failed: "
                      "status: 0x%x, urb-status: 0x%x", 
                      configuration, status, urb.UrbHeader.Status);
          return status;
        }

      dev->config.handle =  urb.UrbSelectConfiguration.ConfigurationHandle;
      dev->config.value = 0;

      clear_pipe_info(dev);

      return status;
    }

  configuration_descriptor = get_config_descriptor(dev, configuration, 
                                                   &desc_size);
  if(!configuration_descriptor)
    {
      DEBUG_ERROR("set_configuration(): getting configuration descriptor "
                  "failed");
      return STATUS_INVALID_PARAMETER;
    }

  interfaces = 
    ExAllocatePool(NonPagedPool,(configuration_descriptor->bNumInterfaces + 1)
                   * sizeof(USBD_INTERFACE_LIST_ENTRY));

  if(!interfaces)
    {
      DEBUG_ERROR("set_configuration(): memory allocation failed");
      ExFreePool(configuration_descriptor);
      return STATUS_NO_MEMORY;
    }

  memset(interfaces, 0, (configuration_descriptor->bNumInterfaces + 1) 
         * sizeof(USBD_INTERFACE_LIST_ENTRY));

  interface_number = 0;

  for(i = 0; i < configuration_descriptor->bNumInterfaces; i++)
    {
      for(j = interface_number; j < LIBUSB0_MAX_NUMBER_OF_INTERFACES; j++)
        {
          interface_descriptor =
            find_interface_desc(configuration_descriptor, desc_size, j, 0);
          if(interface_descriptor) 
            {
              interface_number = ++j;
              break;
            }
        }

      if(!interface_descriptor)
        {
          DEBUG_ERROR("set_configuration(): unable to find interface "
                      "descriptor at index %d", i);
          ExFreePool(interfaces);
          ExFreePool(configuration_descriptor);
          return STATUS_INVALID_PARAMETER;
        }
      else
        {
          DEBUG_MESSAGE("set_configuration(): found interface %d",
                        interface_descriptor->bInterfaceNumber);
          interfaces[i].InterfaceDescriptor = interface_descriptor;
        }
    }

  urb_ptr = USBD_CreateConfigurationRequestEx(configuration_descriptor,
                                              interfaces);

  if(!urb_ptr)
    {
      DEBUG_ERROR("set_configuration(): memory allocation failed");
      ExFreePool(interfaces);
      ExFreePool(configuration_descriptor);
      return STATUS_NO_MEMORY;
    }

  for(i = 0; i < configuration_descriptor->bNumInterfaces; i++)
    {
      for(j = 0; j < (int)interfaces[i].Interface->NumberOfPipes; j++)
        {
          interfaces[i].Interface->Pipes[j].MaximumTransferSize 
            = LIBUSB0_MAX_READ_WRITE;
        }
    }

  status = call_usbd(dev, urb_ptr, IOCTL_INTERNAL_USB_SUBMIT_URB, timeout);

  if(!NT_SUCCESS(status) || !USBD_SUCCESS(urb_ptr->UrbHeader.Status))
    {
      DEBUG_ERROR("set_configuration(): setting configuration %d failed: "
                  "status: 0x%x, urb-status: 0x%x", 
                  configuration, status, urb_ptr->UrbHeader.Status);
      ExFreePool(interfaces);
      ExFreePool(configuration_descriptor);
      ExFreePool(urb_ptr);
      return status;
    }

  dev->config.handle = urb_ptr->UrbSelectConfiguration.ConfigurationHandle;
  dev->config.value = configuration;

  clear_pipe_info(dev);

  for(i = 0; i < configuration_descriptor->bNumInterfaces; i++)
    {
      update_pipe_info(dev, interfaces[i].Interface);
    }

  ExFreePool(interfaces);
  ExFreePool(urb_ptr);
  ExFreePool(configuration_descriptor);

  return status;
}
