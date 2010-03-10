
#ifndef __USBDLIB_H
#define __USBDLIB_H

#if __GNUC__ >=3
#pragma GCC system_header
#endif

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push,4)


  typedef struct _USBD_INTERFACE_LIST_ENTRY {
    PUSB_INTERFACE_DESCRIPTOR InterfaceDescriptor;
    PUSBD_INTERFACE_INFORMATION Interface;
  } USBD_INTERFACE_LIST_ENTRY, *PUSBD_INTERFACE_LIST_ENTRY;


#define URB_STATUS(urb) ((urb)->UrbHeader.Status)

#define GET_SELECT_CONFIGURATION_REQUEST_SIZE(totalInterfaces, totalPipes) \
             (sizeof(struct _URB_SELECT_CONFIGURATION) \
             + ((totalInterfaces - 1) * sizeof(USBD_INTERFACE_INFORMATION)) \
             + ((totalPipes - 1) * sizeof(USBD_PIPE_INFORMATION)))

#define GET_SELECT_INTERFACE_REQUEST_SIZE(totalPipes) \
             (sizeof(struct _URB_SELECT_INTERFACE) \
             + ((totalPipes - 1) * sizeof(USBD_PIPE_INFORMATION)))

#define GET_USBD_INTERFACE_SIZE(numEndpoints) \
             (sizeof(USBD_INTERFACE_INFORMATION) \
             + (sizeof(USBD_PIPE_INFORMATION)*(numEndpoints)) \
             - sizeof(USBD_PIPE_INFORMATION))

#define GET_ISO_URB_SIZE(n) (sizeof(struct _URB_ISOCH_TRANSFER) \
             + sizeof(USBD_ISO_PACKET_DESCRIPTOR) * n)


#define UsbBuildInterruptOrBulkTransferRequest(urb, \
                                               length, \
                                               pipeHandle, \
                                               transferBuffer, \
                                               transferBufferMDL, \
                                               transferBufferLength, \
                                               transferFlags, \
                                               link) { \
            (urb)->UrbHeader.Function = \
                   URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER; \
            (urb)->UrbHeader.Length = (length); \
            (urb)->UrbBulkOrInterruptTransfer.PipeHandle = (pipeHandle); \
            (urb)->UrbBulkOrInterruptTransfer.TransferBufferLength = \
                   (transferBufferLength); \
            (urb)->UrbBulkOrInterruptTransfer.TransferBufferMDL = \
                   (transferBufferMDL); \
            (urb)->UrbBulkOrInterruptTransfer.TransferBuffer = \
                   (transferBuffer); \
            (urb)->UrbBulkOrInterruptTransfer.TransferFlags = \
                   (transferFlags); \
            (urb)->UrbBulkOrInterruptTransfer.UrbLink = (link); }
            

#define UsbBuildGetDescriptorRequest(urb, \
                                     length, \
                                     descriptorType, \
                                     descriptorIndex, \
                                     languageId, \
                                     transferBuffer, \
                                     transferBufferMDL, \
                                     transferBufferLength, \
                                     link) { \
            (urb)->UrbHeader.Function =  \
                   URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE; \
            (urb)->UrbHeader.Length = (length); \
            (urb)->UrbControlDescriptorRequest.TransferBufferLength = \
                   (transferBufferLength); \
            (urb)->UrbControlDescriptorRequest.TransferBufferMDL = \
                   (transferBufferMDL); \
            (urb)->UrbControlDescriptorRequest.TransferBuffer = \
                   (transferBuffer); \
            (urb)->UrbControlDescriptorRequest.DescriptorType = \
                   (descriptorType); \
            (urb)->UrbControlDescriptorRequest.Index = (descriptorIndex); \
            (urb)->UrbControlDescriptorRequest.LanguageId = (languageId); \
            (urb)->UrbControlDescriptorRequest.UrbLink = (link); }



#define UsbBuildGetStatusRequest(urb, \
                                 op, \
                                 index, \
                                 transferBuffer, \
                                 transferBufferMDL, \
                                 link) { \
            (urb)->UrbHeader.Function =  (op); \
            (urb)->UrbHeader.Length = \
                   sizeof(struct _URB_CONTROL_GET_STATUS_REQUEST); \
            (urb)->UrbControlGetStatusRequest.TransferBufferLength = \
                   sizeof(USHORT); \
            (urb)->UrbControlGetStatusRequest.TransferBufferMDL = \
                   (transferBufferMDL); \
            (urb)->UrbControlGetStatusRequest.TransferBuffer = \
                   (transferBuffer); \
            (urb)->UrbControlGetStatusRequest.Index = (index); \
            (urb)->UrbControlGetStatusRequest.UrbLink = (link); }


#define UsbBuildFeatureRequest(urb, \
                               op, \
                               featureSelector, \
                               index, \
                               link) { \
            (urb)->UrbHeader.Function =  (op); \
            (urb)->UrbHeader.Length = \
                   sizeof(struct _URB_CONTROL_FEATURE_REQUEST); \
            (urb)->UrbControlFeatureRequest.FeatureSelector = \
                   (featureSelector); \
            (urb)->UrbControlFeatureRequest.Index = (index); \
            (urb)->UrbControlFeatureRequest.UrbLink = (link); }



#define UsbBuildSelectConfigurationRequest(urb, \
                                         length, \
                                         configurationDescriptor) { \
            (urb)->UrbHeader.Function =  URB_FUNCTION_SELECT_CONFIGURATION; \
            (urb)->UrbHeader.Length = (length); \
            (urb)->UrbSelectConfiguration.ConfigurationDescriptor = \
                   (configurationDescriptor); }

#define UsbBuildSelectInterfaceRequest(urb, \
                                      length, \
                                      configurationHandle, \
                                      interfaceNumber, \
                                      alternateSetting) { \
            (urb)->UrbHeader.Function =  URB_FUNCTION_SELECT_INTERFACE; \
            (urb)->UrbHeader.Length = (length); \
            (urb)->UrbSelectInterface.Interface.AlternateSetting = \
                   (alternateSetting); \
            (urb)->UrbSelectInterface.Interface.InterfaceNumber = \
                   (interfaceNumber); \
            (urb)->UrbSelectInterface.ConfigurationHandle = \
                   (configurationHandle); }


#define UsbBuildVendorRequest(urb, \
                              cmd, \
                              length, \
                              transferFlags, \
                              reservedbits, \
                              request, \
                              value, \
                              index, \
                              transferBuffer, \
                              transferBufferMDL, \
                              transferBufferLength, \
                              link) { \
            (urb)->UrbHeader.Function =  cmd; \
            (urb)->UrbHeader.Length = (length); \
            (urb)->UrbControlVendorClassRequest.TransferBufferLength = \
                   (transferBufferLength); \
            (urb)->UrbControlVendorClassRequest.TransferBufferMDL = \
                   (transferBufferMDL); \
            (urb)->UrbControlVendorClassRequest.TransferBuffer = \
                   (transferBuffer); \
            (urb)->UrbControlVendorClassRequest.RequestTypeReservedBits = \
                   (reservedbits); \
            (urb)->UrbControlVendorClassRequest.Request = (request); \
            (urb)->UrbControlVendorClassRequest.Value = (value); \
            (urb)->UrbControlVendorClassRequest.Index = (index); \
            (urb)->UrbControlVendorClassRequest.TransferFlags = \
                   (transferFlags); \
            (urb)->UrbControlVendorClassRequest.UrbLink = (link); }


#define UsbBuildOsFeatureDescriptorRequest(urb, \
                              length, \
                              interface, \
                              index, \
                              transferBuffer, \
                              transferBufferMDL, \
                              transferBufferLength, \
                              link) { \
            (urb)->UrbHeader.Function = \
                   URB_FUNCTION_GET_MS_FEATURE_DESCRIPTOR; \
            (urb)->UrbHeader.Length = (length); \
            (urb)->UrbOSFeatureDescriptorRequest.TransferBufferLength = \
                   (transferBufferLength); \
            (urb)->UrbOSFeatureDescriptorRequest.TransferBufferMDL = \
                   (transferBufferMDL); \
            (urb)->UrbOSFeatureDescriptorRequest.TransferBuffer = \
                   (transferBuffer); \
            (urb)->UrbOSFeatureDescriptorRequest.InterfaceNumber = \
                   (interface); \
            (urb)->UrbOSFeatureDescriptorRequest.MS_FeatureDescriptorIndex = \
                   (index); \
            (urb)->UrbOSFeatureDescriptorRequest.UrbLink = (link); }


  VOID
  DDKAPI
  USBD_Debug_LogEntry(
                      IN CHAR *Name, 
                      IN ULONG Info1,
                      IN ULONG Info2,
                      IN ULONG Info3
                      );

  VOID
  DDKAPI 
  USBD_GetUSBDIVersion(
                       PUSBD_VERSION_INFORMATION VersionInformation
                       );


  PUSB_INTERFACE_DESCRIPTOR
  DDKAPI 
  USBD_ParseConfigurationDescriptor(
                                    IN PUSB_CONFIGURATION_DESCRIPTOR ConfigurationDescriptor,
                                    IN UCHAR InterfaceNumber,
                                    IN UCHAR AlternateSetting
                                    );

  PURB
  DDKAPI
  USBD_CreateConfigurationRequest(
                                  IN PUSB_CONFIGURATION_DESCRIPTOR ConfigurationDescriptor,
                                  IN OUT PUSHORT Siz
                                  );

  PUSB_COMMON_DESCRIPTOR
  DDKAPI
  USBD_ParseDescriptors(
                        IN PVOID DescriptorBuffer,
                        IN ULONG TotalLength,
                        IN PVOID StartPosition,
                        IN LONG DescriptorType
                        );

  PUSB_INTERFACE_DESCRIPTOR
  DDKAPI
  USBD_ParseConfigurationDescriptorEx(
                                      IN PUSB_CONFIGURATION_DESCRIPTOR ConfigurationDescriptor,
                                      IN PVOID StartPosition,
                                      IN LONG InterfaceNumber,
                                      IN LONG AlternateSetting,
                                      IN LONG InterfaceClass,
                                      IN LONG InterfaceSubClass,
                                      IN LONG InterfaceProtocol
                                      );

  PURB
  DDKAPI
  USBD_CreateConfigurationRequestEx(
                                    IN PUSB_CONFIGURATION_DESCRIPTOR ConfigurationDescriptor,
                                    IN PUSBD_INTERFACE_LIST_ENTRY InterfaceList
                                    );

  ULONG
  DDKAPI
  USBD_GetInterfaceLength(
                          IN PUSB_INTERFACE_DESCRIPTOR InterfaceDescriptor,
                          IN PUCHAR BufferEnd
                          );

  VOID
  DDKAPI
  USBD_RegisterHcFilter(
                        PDEVICE_OBJECT DeviceObject,
                        PDEVICE_OBJECT FilterDeviceObject
                        );

  NTSTATUS
  DDKAPI
  USBD_GetPdoRegistryParameter(
                               IN PDEVICE_OBJECT PhysicalDeviceObject,
                               IN OUT PVOID Parameter,
                               IN ULONG ParameterLength,
                               IN PWCHAR KeyName,
                               IN ULONG KeyNameLength
                               );

  NTSTATUS
  DDKAPI
  USBD_QueryBusTime(
                    IN PDEVICE_OBJECT RootHubPdo,
                    IN PULONG CurrentFrame
                    );

  ULONG
  DDKAPI
  USBD_CalculateUsbBandwidth(
                             ULONG MaxPacketSize,
                             UCHAR EndpointType,
                             BOOLEAN LowSpeed
                             );


#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif /* __USBDLIB_H */
 
