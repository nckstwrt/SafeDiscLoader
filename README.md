> [!IMPORTANT]
> **This is now obsolete!** Please use the new and improved version here: [SafeDiscLoader2](https://github.com/nckstwrt/SafeDiscLoader2)  
> Supports SafeDisc version 2.0 to 4.9 and no longer relies on Reloaded's DLL (which got flagged by some virus checkers)

# SafeDiscLoader
 Allows playing SafeDisc (version 2.7 to the latest 4.9) protected games on modern Windows. 

# Download
[Releases](https://github.com/nckstwrt/SafeDiscLoader/releases)

# Usage
SafeDiscLoader is a single executable and can be used in the following ways to run SafeDisc protected games:

### Just Double-Click
From here a window will appear allowing you to select your game's SafeDisc .exe file
### Drag your SafeDisc exe onto SafeDiscLoader.exe
That is equivalent to running SafeDiscLoader with the dragged SafeDisc .exe file as the first argument. SafeDiscLoader will attempt to pass on any additional arguments provided. i.e. `SafeDiscLoader.exe Sims2.exe -w` will load The Sims 2 in windowed mode
### Create a SafeDiscLoader.ini file
If a SafeDiscLoader.ini file is found in the same directory as SafeDiscLoader.exe it will use its contents as if it were commandline arguments passed. i.e. Create a text file called SafeDiscLoader.ini with just `Sims2.exe -w` to load The Sims 2
### Using it with non-SafeDisc executables
You can also use SafeDiscLoader to make SafeDisc utilities work on modern Windows. e.g. Safedisc2Cleaner which can unwrap Safedisc executables below version 2.7.

# Credits
*  Reloaded for their Universal SafeDisc Loader
*  [RibShark](https://twitter.com/RibShark) for his secdrv.sys [SafeDiscShim emulation code](https://github.com/RibShark/SafeDiscShim)
* SafeDisc 2.7 + 2.8 Loader code written by me
* DiscEmuCheck (DCEHookApi) written by [Luca1991](https://github.com/Luca1991/DiscCheckEmu)

# Background
I mainly started looking into this as there was no way of playing Football Manager 2005 5.0.5 or Football Manager 2006 6.0.3 on Windows 10 or 11 as there were never any NoCD patches released for these latest versions of the game. Reloaded's SDLoader would run these versions just fine on older Windows versions but failed on Windows 10 and 11. The missing part was the secdrv.sys emulation that RibShark has recently provided as part of his SafeDiscShim. Reloaded's loader assumed secdrv.sys would still be installed and accessible. RibShark's code hooks CreateFile and DeviceIoControl to emulate sysdrv.sys being present and allows Reloaded's loader to do its thing. My code is just a decompiled version of Reloaded's SDLoader that now injects a hooks only version of RibShark's emulation code.

# DiscCheckEmu Support
Some games also had other CD Checks outside of SafeDisc (normally just checking for a CD having a file or a certain volume name). These checks can be supported by including DCEAPIHook.dll from https://github.com/Luca1991/DiscCheckEmu in the same directory as the game's excutable along with a supporting DCEConfig.yaml. Currently supported Configs/Games can be found at: https://github.com/Luca1991/DCEConfigs/
 
 # Notices
> [!IMPORTANT]
> This is not intended for Piracy but for users to exercise their Fair Use rights for the games they actually own and can no longer play due to draconian and unsupported copy protection

> [!CAUTION]
> Antivirus software that blocks code injection will block this loader, so make sure to greenlist the included exe and dll or disable your antivirus software.
