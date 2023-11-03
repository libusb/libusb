// It's not yet possible to automate actual Chrome's device selection, so
// for now run automated tests via Node.js WebUSB implementation.
//
// It might differ from browser one, but should be enough to catch most obvious issues.

const { WebUSB } = require('usb');

globalThis.navigator = {
  usb: new WebUSB({
    allowAllDevices: true
  })
};
