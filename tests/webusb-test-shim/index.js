// It's not yet possible to automate actual Chrome's device selection, so
// for now run automated tests via Node.js WebUSB implementation.
//
// It might differ from browser one, but should be enough to catch most obvious issues.

const { WebUSB } = require('usb');

// Node.js 21 introduced a global `navigator` object, so assign an empty one only if it's not present yet.
globalThis.navigator ??= {};

navigator.usb = new WebUSB({
  allowAllDevices: true
});
