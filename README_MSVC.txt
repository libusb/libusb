To compile libusb 1.0 using MSVC 9:

Note: in the text below, (Win32) means "when producing 32 bit binaries" and
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
  
  To help compiling pthreadVC2_x64.dll on x64 platforms, sample .sln and .vcproj 
  files for pthread-win32 are provided in the msvc\pthread-win32_x64\ directory.
  
- (x64) Copy pthreadVC2_x64.lib to the msvc directory.

- To run the 64 bit executables, you need to either have pthreadVC2_x64.dll
  in your executable directory or in C:\Windows\System32 (again, not a typo).

- Edit config_msvc.h according to your needs (you might want to comment out
  ENABLE_DEBUG_LOGGING).
  
- If you haven't done so, download and install the latest Windows DDK 
  (http://www.microsoft.com/downloads/details.aspx?FamilyID=2105564e-1a9a-4bf4-8d74-ec5b52da3d00)
  
- In Visual Studio, go to Tools -> Options -> Projects and Solutions ->
  VC++ directories and add the following to "Include files":
  <path of Windows DDK>\inc
  
- Also in VC++ directories and add the following to "Library files":
  <path of Windows DDK>\lib\<target platform>\<arch>
  Where <targe platform> is one of wxp, wlh (Vista) or win7 and <arch> is
  one of i386 or amd64, depending on whether Platform is Win32 or x64.

You should now be able to compile the solution.

The default solution is set to produce the static library and statically 
linked binaries. The DLL is currently built as a standalone project.

For additional information, please refer to:
  http://libusb.org/wiki/windows_backend