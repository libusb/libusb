from conans import ConanFile, CMake

class LibUsbConan(ConanFile):
    name = "libusb"
    license = "GNU Lesser General Public License v2.1"
    url = "https://libusb.info/"
    description = "A library for USB device access from Linux, macOS, Windows, OpenBSD/NetBSD and Haiku userspace."
    settings = "os", "compiler", "build_type", "arch"
    options = {}
    default_options = ""
    generators = "cmake"
    exports_sources = "*", "!build/*"
        
    def build(self):
        cmake = CMake(self)
        cmake.configure(source_folder=".")
        cmake.build()
        cmake.install()

#    def package(self):
#         nothing to do here. All is handled by cmake.install() above.
        
    def package_info(self):
        self.cpp_info.libs = ["LibUsb"]
