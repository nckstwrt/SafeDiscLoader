# SafeDiscLoader
 Allows playing SafeDisc (version 2.9 to the latest 4.9) protected games on modern Windows. 

# Download
[Releases](https://github.com/nckstwrt/SafeDiscLoader/releases)

# Usage
SafeDiscLoader is a single executable and can be used in the following ways to run SafeDisc protected games:

### Just Double-Click
From here a window will appear allowing you to select your SafeDisc.exe
### Drag your SafeDisc exe onto SafeDiscLoader.exe
That is equivalent to running SafeDiscLoader with the safedisc.exe as the first argument. SafeDiscLoader will attempt to pass on any additional arguments provided. i.e. `SafeDiscLoader.exe TheSims2.exe -w` will load The Sims 2 in windowed mode
### Create a SafeDiscLoader.ini file
If a SafeDiscLoader.ini file is found in the same directory as SafeDiscLoader.exe it will use its contents as if it were commandline arguments passed. i.e. Create a text file called SafeDiscLoader.ini with just `TheSims2.exe -w` to load The Sims 2

# Credits
All credit goes to Reloaded for their Universal SafeDisc Loader and [RibShark](https://twitter.com/RibShark) for his secdrv.sys [SafeDiscShim emulation code](https://github.com/RibShark/SafeDiscShim)

# Background
I mainly started looking into this as there was no way of playing Football Manager 2005 5.0.5 or Football Manager 2006 6.0.3 on Windows 10 or 11 as there were never any NoCD patches released for these latest versions of the game. Reloaded's SDLoader would run these versions just fine on older Windows versions but failed on Windows 10 and 11. The missing part was the secdrv.sys emulation that RibShark has recently provided as part of his SafeDiscShim. Reloaded's loader assumed secdrv.sys would still be installed and accessible. RibShark's code hooks CreateFile and DeviceIoControl to emulate sysdrv.sys being present and allows Reloaded's loader to do its thing. My code is just a decompiled version of Reloaded's SDLoader that now injects a hooks only version of RibShark's emulation code.
 
 # Notices
> [!IMPORTANT]
> This is not intended for Piracy but for users to exercise their Fair Use rights for the games they actually own and can no longer play due to draconian and unsupported copy protection

> [!CAUTION]
> Antivirus software that blocks code injection will block this loader, so make sure to greenlist the included exe and dll or disable your antivirus software.
