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

/* missing in mingw's ddk headers */
#ifndef PLUGPLAY_REGKEY_DEVICE
#define PLUGPLAY_REGKEY_DEVICE  1
#endif

#define LIBUSB_REG_SURPRISE_REMOVAL_OK L"SurpriseRemovalOK"


static bool_t reg_get_property(DEVICE_OBJECT *physical_device_object, 
                               int property, char *data, int size);

static bool_t reg_get_property(DEVICE_OBJECT *physical_device_object,
                               int property, char *data, int size)
{
  WCHAR tmp[512];
  ULONG ret;
  ULONG i;

  if(!physical_device_object || !data || !size)
    {
      return FALSE;
    }

  memset(data, 0, size);
  memset(tmp, 0, sizeof(tmp));

  if(NT_SUCCESS(IoGetDeviceProperty(physical_device_object,
                                    property,
                                    sizeof(tmp) - 2,
                                    tmp,
                                    &ret)) && ret)
    {
      /* convert unicode string to normal character string */
      for(i = 0; (i < ret/2) && (i < ((ULONG)size - 1)); i++)
        {
          data[i] = (char)tmp[i];
        }
      
      _strlwr(data);

      return TRUE;
    }

  return FALSE;
}


bool_t reg_get_properties(libusb_device_t *dev)
{
  HANDLE key = NULL;
  NTSTATUS status;
  UNICODE_STRING name;
  KEY_VALUE_FULL_INFORMATION *info;
  ULONG length;

  if(!dev->physical_device_object)
    {
      return FALSE;
    }

  /* default settings */
  dev->surprise_removal_ok = FALSE;
  dev->is_filter = TRUE;

  status = IoOpenDeviceRegistryKey(dev->physical_device_object,
                                   PLUGPLAY_REGKEY_DEVICE,
                                   STANDARD_RIGHTS_ALL,
                                   &key);
  if(NT_SUCCESS(status)) 
    {
      RtlInitUnicodeString(&name, LIBUSB_REG_SURPRISE_REMOVAL_OK);
      
      length = sizeof(KEY_VALUE_FULL_INFORMATION) + name.MaximumLength
        + sizeof(ULONG);

      info = ExAllocatePool(NonPagedPool, length);
      
      if(info) 
        {
          memset(info, 0, length);

          status = ZwQueryValueKey(key, &name, KeyValueFullInformation,
                                   info, length, &length);
          
          if(NT_SUCCESS(status) && (info->Type == REG_DWORD))
            {
              ULONG val = *((ULONG *)(((char *)info) + info->DataOffset));

              dev->surprise_removal_ok = val ? TRUE : FALSE;
              dev->is_filter = FALSE;
            }
          
          ExFreePool(info);
        }
      
      ZwClose(key);
    }

  return TRUE;
}

bool_t reg_get_hardware_id(DEVICE_OBJECT *physical_device_object, 
                           char *data, int size)
{
  if(!physical_device_object || !data || !size)
    {
      return FALSE;
    }

  return reg_get_property(physical_device_object, DevicePropertyHardwareID, 
                          data, size);
}

