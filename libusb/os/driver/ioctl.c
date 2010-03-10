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


NTSTATUS dispatch_ioctl(libusb_device_t *dev, IRP *irp)
{
  int ret = 0;
  NTSTATUS status = STATUS_SUCCESS;

  IO_STACK_LOCATION *stack_location = IoGetCurrentIrpStackLocation(irp);
  ULONG control_code =
    stack_location->Parameters.DeviceIoControl.IoControlCode;

  ULONG input_buffer_length
    = stack_location->Parameters.DeviceIoControl.InputBufferLength;
  ULONG output_buffer_length
    = stack_location->Parameters.DeviceIoControl.OutputBufferLength;
  ULONG transfer_buffer_length
    = stack_location->Parameters.DeviceIoControl.OutputBufferLength;

  libusb0_request *request = (libusb0_request *)irp->AssociatedIrp.SystemBuffer;
  char *output_buffer = (char *)irp->AssociatedIrp.SystemBuffer;
  char *input_buffer = (char *)irp->AssociatedIrp.SystemBuffer;
  MDL *transfer_buffer_mdl = irp->MdlAddress;

  status = remove_lock_acquire(dev);

  if(!NT_SUCCESS(status))
    { 
      status = complete_irp(irp, status, 0);
      remove_lock_release(dev);
      return status;
    }

  if(!request || input_buffer_length < sizeof(libusb0_request)
     || input_buffer_length > LIBUSB0_MAX_READ_WRITE
     || output_buffer_length > LIBUSB0_MAX_READ_WRITE
     || transfer_buffer_length > LIBUSB0_MAX_READ_WRITE)
    { 
      DEBUG_ERROR("dispatch_ioctl(): invalid input or output buffer\n");

      status = complete_irp(irp, STATUS_INVALID_PARAMETER, 0);
      remove_lock_release(dev);
      return status;
    }

  DEBUG_PRINT_NL();

  switch(control_code) 
    {     
    case LIBUSB0_IOCTL_SET_CONFIGURATION:

      status = set_configuration(dev, request->configuration.configuration,
                                 request->timeout);
      break;
      
    case LIBUSB0_IOCTL_GET_CONFIGURATION:
      
      if(!output_buffer || output_buffer_length < 1)
        {
          DEBUG_ERROR("dispatch_ioctl(), get_configuration: invalid output "
                      "buffer");
          status = STATUS_INVALID_PARAMETER;
          break;
        }

      status = get_configuration(dev, output_buffer, &ret, request->timeout);
      break;

    case LIBUSB0_IOCTL_SET_INTERFACE:

      status = set_interface(dev, request->interface.interface,
                             request->interface.altsetting, request->timeout);
      break;

    case LIBUSB0_IOCTL_GET_INTERFACE:

      if(!output_buffer || output_buffer_length < 1)
        {
          DEBUG_ERROR("dispatch_ioctl(), get_interface: invalid output "
                      "buffer");
          status =  STATUS_INVALID_PARAMETER;
          break;
        }

      status = get_interface(dev, request->interface.interface,
                             output_buffer, &ret, request->timeout);
      break;

    case LIBUSB0_IOCTL_SET_FEATURE:

      status = set_feature(dev, request->feature.recipient,
                           request->feature.index, request->feature.feature,
                           request->timeout);
      
      break;

    case LIBUSB0_IOCTL_CLEAR_FEATURE:

      status = clear_feature(dev, request->feature.recipient,
                             request->feature.index, request->feature.feature,
                             request->timeout);
      
      break;

    case LIBUSB0_IOCTL_GET_STATUS:

      if(!output_buffer || output_buffer_length < 2)
        {
          DEBUG_ERROR("dispatch_ioctl(), get_status: invalid output buffer");
          status = STATUS_INVALID_PARAMETER;
          break;
        }

      status = get_status(dev, request->status.recipient,
                          request->status.index, output_buffer,
                          &ret, request->timeout);

      break;

    case LIBUSB0_IOCTL_SET_DESCRIPTOR:

      if(input_buffer_length <= sizeof(libusb0_request))
        {
          DEBUG_ERROR("dispatch_ioctl(), set_descriptor: invalid input "
                      "buffer");
          status = STATUS_INVALID_PARAMETER;
          break;
        }
      
      status = set_descriptor(dev, 
                              input_buffer + sizeof(libusb0_request), 
                              input_buffer_length - sizeof(libusb0_request), 
                              request->descriptor.type,
                              request->descriptor.recipient,
                              request->descriptor.index,
                              request->descriptor.language_id, 
                              &ret, request->timeout);
      
      break;

    case LIBUSB0_IOCTL_GET_DESCRIPTOR:

      if(!output_buffer || !output_buffer_length)
        {
          DEBUG_ERROR("dispatch_ioctl(), get_descriptor: invalid output "
                      "buffer");
          status = STATUS_INVALID_PARAMETER;
          break;
        }

      status = get_descriptor(dev, output_buffer, 
                              output_buffer_length,
                              request->descriptor.type,
                              request->descriptor.recipient,
                              request->descriptor.index,
                              request->descriptor.language_id, 
                              &ret, request->timeout);
      
      break;
      
    case LIBUSB0_IOCTL_INTERRUPT_OR_BULK_READ:

      if(!transfer_buffer_mdl)
        {
          DEBUG_ERROR("dispatch_ioctl(), bulk_int_read: invalid transfer "
                      "buffer");
          status = STATUS_INVALID_PARAMETER;
          break;
        }

      return transfer(dev, irp,
                      USBD_TRANSFER_DIRECTION_IN,
                      URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER,
                      request->endpoint.endpoint,
                      request->endpoint.packet_size,
                      transfer_buffer_mdl, 
                      transfer_buffer_length);

    case LIBUSB0_IOCTL_INTERRUPT_OR_BULK_WRITE:

      /* we don't check 'transfer_buffer_mdl' here because it might be NULL */
      /* if the DLL requests to send a zero-length packet */
      return transfer(dev, irp,
                      USBD_TRANSFER_DIRECTION_OUT,
                      URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER,
                      request->endpoint.endpoint,
                      request->endpoint.packet_size,
                      transfer_buffer_mdl, 
                      transfer_buffer_length);

    case LIBUSB0_IOCTL_VENDOR_READ:

      if(output_buffer_length && !output_buffer)
        {
          DEBUG_ERROR("dispatch_ioctl(), vendor_read: invalid output buffer");
          status = STATUS_INVALID_PARAMETER;
          break;
        }

      status = vendor_class_request(dev,
                                    request->vendor.type, 
                                    request->vendor.recipient,
                                    request->vendor.request,
                                    request->vendor.value,
                                    request->vendor.index,
                                    output_buffer,
                                    output_buffer_length,
                                    USBD_TRANSFER_DIRECTION_IN,
                                    &ret, request->timeout);
      break;

    case LIBUSB0_IOCTL_VENDOR_WRITE:
      
      status = 
        vendor_class_request(dev,
                             request->vendor.type, 
                             request->vendor.recipient,
                             request->vendor.request,
                             request->vendor.value,
                             request->vendor.index,
                             input_buffer_length == sizeof(libusb0_request) ?
                             NULL : input_buffer + sizeof(libusb0_request),
                             input_buffer_length - sizeof(libusb0_request),
                             USBD_TRANSFER_DIRECTION_OUT, 
                             &ret, request->timeout);
      break;

    case LIBUSB0_IOCTL_RESET_ENDPOINT:

      status = reset_endpoint(dev, request->endpoint.endpoint,
                              request->timeout);
      break;
      
    case LIBUSB0_IOCTL_ABORT_ENDPOINT:
	 
      status = abort_endpoint(dev, request->endpoint.endpoint,
                              request->timeout);
      break;

    case LIBUSB0_IOCTL_RESET_DEVICE: 
      
      status = reset_device(dev, request->timeout);
      break;

    case LIBUSB0_IOCTL_SET_DEBUG_LEVEL:

      DEBUG_SET_LEVEL(request->debug.level);
      break;

    case LIBUSB0_IOCTL_GET_VERSION:

      if(!request || output_buffer_length < sizeof(libusb0_request))
        {
          DEBUG_ERROR("dispatch_ioctl(), get_version: invalid output buffer");
          status = STATUS_INVALID_PARAMETER;
          break;
        }

      request->version.major = VERSION_MAJOR;
      request->version.minor = VERSION_MINOR;
      request->version.micro = VERSION_MICRO;
      request->version.nano  = VERSION_NANO;

      ret = sizeof(libusb0_request);
      break;

    case LIBUSB0_IOCTL_CLAIM_INTERFACE:
      status = claim_interface(dev, request->interface.interface);
      break;

    case LIBUSB0_IOCTL_RELEASE_INTERFACE:
      status = release_interface(dev, request->interface.interface);
      break;

    case LIBUSB0_IOCTL_ISOCHRONOUS_READ:
      if(!transfer_buffer_mdl)
        {
          DEBUG_ERROR("dispatch_ioctl(), isochronous_read: invalid transfer "
                      "buffer");
          status = STATUS_INVALID_PARAMETER;
          break;
        }

      return transfer(dev, irp, USBD_TRANSFER_DIRECTION_IN,
                      URB_FUNCTION_ISOCH_TRANSFER, request->endpoint.endpoint,
                      request->endpoint.packet_size, transfer_buffer_mdl, 
                      transfer_buffer_length);

    case LIBUSB0_IOCTL_ISOCHRONOUS_WRITE:

      if(!transfer_buffer_mdl)
        {
          DEBUG_ERROR("dispatch_ioctl(), isochronous_write: invalid transfer "
                      "buffer");
          status = STATUS_INVALID_PARAMETER;
          break;
        }

      return transfer(dev, irp, USBD_TRANSFER_DIRECTION_OUT,
                      URB_FUNCTION_ISOCH_TRANSFER, request->endpoint.endpoint,
                      request->endpoint.packet_size, transfer_buffer_mdl, 
                      transfer_buffer_length);

    default:
      
      status = STATUS_INVALID_PARAMETER;
    }

  status = complete_irp(irp, status, ret);  
  remove_lock_release(dev);

  return status;
}
