$toolsets = "v141", "v142", "v143", "v145"
$platforms = "Win32", "x64", "ARM64"
$configurations = "Debug", "Release", "Debug-MT", "Release-MT",
                  "Debug-Hotplug", "Release-Hotplug", "Debug-Hotplug-MT", "Release-Hotplug-MT"

foreach ($toolset in $toolsets) {
    foreach ($plat in $platforms) {
        foreach ($conf in $configurations) {
            write-host ">>> PlatformToolset=$toolset,Platform=$plat,Configuration=$conf"
            msbuild -m -v:m -p:PlatformToolset=$toolset,Platform=$plat,Configuration=$conf $PSScriptRoot\libusb.sln
        }
    }
}
