To compile libusb 1.0 using either Microsoft Visual Studio or the Windows DDK

Note 1: For Visual Studio, 3 sets of solution files are provided depending on 
whether you are running MSVC6, Visual Studio 2008 (MSVC9) or Visual Studio 2005 
(MSVC8). For the DDK, just run ddk_build.cmd from a DDK build environment 
command prompt.

Note 2: In the text below, (Win32) means "when producing 32 bit binaries" and
(x64) "when producing 64 bit binaries". This is independent of whether your 
platform is actually 32 or 64 bit.

- Download the pthread.h and sched.h headers from 
  ftp://sourceware.org/pub/pthreads-win32/prebuilt-dll-2-8-0-release/include/
  into the msvc directory.

- (Win32) download pthreadVC2.lib from:
  ftp://sourceware.org/pub/pthreads-win32/prebuilt-dll-2-8-0-release/lib/ 
  into the msvc directory.

- To run the 32 bit executables, download pthreadVC2.dll from the same link 
  either into your executable destination or copy it into C:\Window\System32
  (for 32 bit systems) or C:\Windows\SysWOW64 (for 64 bit systems - yes, this
  is not a typo: 32 bit DLLs must go to SysWOW64 on 64 bit systems).

- (x64) Follow the "Direct access to the CVS code repository" details on
  http://sourceware.org/pthreads-win32/ and create both a pthreadVC2_x64.lib
  and pthreadVC2_x64.dll from the latest pthread-win32 source.
  
  To help compiling pthreadVC2_x64.dll on x64 platforms, sample .sln and 
  .vcproj files are provided in the msvc\pthread-win32_x64\ directory.
  
- (x64) Copy pthreadVC2_x64.lib to the msvc directory.

- To run the 64 bit executables, you need to either have pthreadVC2_x64.dll
  in your executable directory or in C:\Windows\System32 (again, not a typo).
  
Alternativaly, precompiled pthread-win32 binaries for 64bit and 32 bit
platforms, as well as the necessary headers can be obtained frome:
http://libusb.org/raw-attachment/wiki/windows_backend/pthread-win32_libusb.zip

- Edit config_msvc.h according to your needs (you might want to comment out
  ENABLE_DEBUG_LOGGING).

You should now be able to compile the solution.

Note that if the the compilation process complains about missing libraries,
you will need to ensure that the default library paths for your project point
to a directory that contains setupapi.lib and ole32.lib.
If needed, these libraries can be obtained by downloading either the latest 
Windows SDK or the DDK.

For additional information, please refer to:
  http://libusb.org/wiki/windows_backend