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


typedef struct {
  URB *urb;
  int sequence;
} context_t;

static int sequence = 0;

NTSTATUS DDKAPI transfer_complete(DEVICE_OBJECT *device_object, 
                                  IRP *irp, void *context);

static NTSTATUS create_urb(libusb_device_t *dev, URB **urb, int direction, 
                           int urb_function, int endpoint, int packet_size, 
                           MDL *buffer, int size);

NTSTATUS transfer(libusb_device_t *dev, IRP *irp,
                  int direction, int urb_function, int endpoint, 
                  int packet_size, MDL *buffer, int size)
{
  IO_STACK_LOCATION *stack_location = NULL;
  context_t *context;
  NTSTATUS status = STATUS_SUCCESS;
 
  DEBUG_PRINT_NL();

  if(urb_function == URB_FUNCTION_ISOCH_TRANSFER)
    DEBUG_MESSAGE("transfer(): isochronous transfer");
  else
    DEBUG_MESSAGE("transfer(): bulk or interrupt transfer");

  if(direction == USBD_TRANSFER_DIRECTION_IN)
    DEBUG_MESSAGE("transfer(): direction in");
  else
    DEBUG_MESSAGE("transfer(): direction out");

  DEBUG_MESSAGE("transfer(): endpoint 0x%02x", endpoint);

  if(urb_function == URB_FUNCTION_ISOCH_TRANSFER)
    DEBUG_MESSAGE("transfer(): packet_size 0x%x", packet_size);

  DEBUG_MESSAGE("transfer(): size %d", size);
  DEBUG_MESSAGE("transfer(): sequence %d", sequence);
  DEBUG_PRINT_NL();

  if(!dev->config.value)
    {
      DEBUG_ERROR("transfer(): invalid configuration 0");
      remove_lock_release(dev);
      return complete_irp(irp, STATUS_INVALID_DEVICE_STATE, 0);
    }
  
  context = ExAllocatePool(NonPagedPool, sizeof(context_t));

  if(!context)
    {
      remove_lock_release(dev);
      return complete_irp(irp, STATUS_NO_MEMORY, 0);
    }

  status = create_urb(dev, &context->urb, direction, urb_function, 
                      endpoint, packet_size, buffer, size);
    
  if(!NT_SUCCESS(status))
    {
      ExFreePool(context);
      remove_lock_release(dev);
      return complete_irp(irp, status, 0);
    }

  context->sequence = sequence++;

  stack_location = IoGetNextIrpStackLocation(irp);
    
  stack_location->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
  stack_location->Parameters.Others.Argument1 = context->urb;
  stack_location->Parameters.DeviceIoControl.IoControlCode 
    = IOCTL_INTERNAL_USB_SUBMIT_URB;
    
  IoSetCompletionRoutine(irp, transfer_complete, context,
                         TRUE, TRUE, TRUE);
    
  return IoCallDriver(dev->target_device, irp);
}


NTSTATUS DDKAPI transfer_complete(DEVICE_OBJECT *device_object, IRP *irp, 
                                  void *context)
{
  context_t *c = (context_t *)context;
  int transmitted = 0;
  libusb_device_t *dev = device_object->DeviceExtension;

  if(irp->PendingReturned)
    {
      IoMarkIrpPending(irp);
    }

  if(NT_SUCCESS(irp->IoStatus.Status) 
     && USBD_SUCCESS(c->urb->UrbHeader.Status))
    {
      if(c->urb->UrbHeader.Function == URB_FUNCTION_ISOCH_TRANSFER)
        {
          transmitted = c->urb->UrbIsochronousTransfer.TransferBufferLength;
        }
      if(c->urb->UrbHeader.Function == URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER)
        {
          transmitted 
            = c->urb->UrbBulkOrInterruptTransfer.TransferBufferLength;
        }
      
      DEBUG_MESSAGE("transfer_complete(): sequence %d: %d bytes transmitted", 
                    c->sequence, transmitted);
    }
  else
    {
      if(irp->IoStatus.Status == STATUS_CANCELLED)
        {
          DEBUG_ERROR("transfer_complete(): sequence %d: timeout error",
                      c->sequence);
        }
      else
        {
          DEBUG_ERROR("transfer_complete(): sequence %d: transfer failed: "
                      "status: 0x%x, urb-status: 0x%x", 
                      c->sequence, irp->IoStatus.Status, 
                      c->urb->UrbHeader.Status);
        }
    }

  ExFreePool(c->urb);
  ExFreePool(c);

  irp->IoStatus.Information = transmitted;

  remove_lock_release(dev);

  return STATUS_SUCCESS;
}


static NTSTATUS create_urb(libusb_device_t *dev, URB **urb, int direction, 
                           int urb_function, int endpoint, int packet_size, 
                           MDL *buffer, int size)
{
  USBD_PIPE_HANDLE pipe_handle = NULL;
  int num_packets = 0;
  int i, urb_size;

  *urb = NULL;
  
  if(!get_pipe_handle(dev, endpoint, &pipe_handle))
    {
      DEBUG_ERROR("create_urb(): getting endpoint pipe failed");
      return STATUS_INVALID_PARAMETER;
    }
  
  /* isochronous transfer */
  if(urb_function == URB_FUNCTION_ISOCH_TRANSFER)
    {
      num_packets = (size + packet_size - 1) / packet_size;
      
      if(num_packets > 255)
        {
          DEBUG_ERROR("create_urb(): transfer size too large");
          return STATUS_INVALID_PARAMETER;
        }
      
      urb_size = sizeof(struct _URB_ISOCH_TRANSFER)
        + sizeof(USBD_ISO_PACKET_DESCRIPTOR) * num_packets;
    }
  else /* bulk or interrupt transfer */
    {
      urb_size = sizeof(struct _URB_BULK_OR_INTERRUPT_TRANSFER);
    }
  
  *urb = ExAllocatePool(NonPagedPool, urb_size);
  
  if(!*urb)
    {
      DEBUG_ERROR("create_urb(): memory allocation error");
      return STATUS_NO_MEMORY;
    }
  
  memset(*urb, 0, urb_size);
  
  (*urb)->UrbHeader.Length = (USHORT)urb_size;
  (*urb)->UrbHeader.Function = (USHORT)urb_function;
  
  /* isochronous transfer */
  if(urb_function == URB_FUNCTION_ISOCH_TRANSFER)
    {
      (*urb)->UrbIsochronousTransfer.PipeHandle = pipe_handle;
      (*urb)->UrbIsochronousTransfer.TransferFlags 
        = direction | USBD_SHORT_TRANSFER_OK | USBD_START_ISO_TRANSFER_ASAP;
      (*urb)->UrbIsochronousTransfer.TransferBufferLength = size;
      (*urb)->UrbIsochronousTransfer.TransferBufferMDL = buffer;
      (*urb)->UrbIsochronousTransfer.NumberOfPackets = num_packets;
      
      for(i = 0; i < num_packets; i++)
        {
          (*urb)->UrbIsochronousTransfer.IsoPacket[i].Offset = i * packet_size;
          (*urb)->UrbIsochronousTransfer.IsoPacket[i].Length = packet_size;
        }
    }
  /* bulk or interrupt transfer */
  else
    {
      (*urb)->UrbBulkOrInterruptTransfer.PipeHandle = pipe_handle;
      (*urb)->UrbBulkOrInterruptTransfer.TransferFlags 
        = direction | USBD_SHORT_TRANSFER_OK;
      (*urb)->UrbBulkOrInterruptTransfer.TransferBufferLength = size;
      (*urb)->UrbBulkOrInterruptTransfer.TransferBufferMDL = buffer;
    }

  return STATUS_SUCCESS;
}

