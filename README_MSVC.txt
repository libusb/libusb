To compile libusb 1.0 using either Microsoft Visual Studio or the Windows DDK

- If needed, edit msvc/config.h according to your needs (you might want to
  comment out ENABLE_DEBUG_LOGGING for instance).

That's it! You should now be able to compile the solution.


Note 1: For Visual Studio, 3 sets of solution files are provided depending on
whether you are running MSVC6, Visual Studio 2008 (MSVC9) or Visual Studio 2005
(MSVC8). For the DDK, just run ddk_build.cmd from a DDK build environment
command prompt.

Note 2: If the the compilation process complains about missing libraries, you
will need to ensure that the default library paths for your project point to a
directory that contains setupapi.lib and ole32.lib.
If needed, these libraries can be obtained by downloading either the latest
Windows SDK or the DDK.

Note 3: Provided that you have the required environment, it is possible to
produce either a 32 or 64 bit version of the library. Both these version are
supported and have been equally tested during development.

For additional information, please refer to:
  http://libusb.org/wiki/windows_backend