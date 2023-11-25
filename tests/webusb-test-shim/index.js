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

// events_posix uses Web events on the global scope (for now), but Node.js doesn't have them.

const fakeEventTarget = new EventTarget();

for (let method in fakeEventTarget) {
  globalThis[method] = fakeEventTarget[method].bind(fakeEventTarget);
}
