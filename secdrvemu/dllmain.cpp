#ifdef _DEBUG
#define LOGGING
#define EJECT_DEBUGGER
#define EJECT_DEBUGGER_TIMEOUT INFINITE
#endif

#define MINIMUM_SAFEDISC_SUBVERSION 70

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include "minhook/include/MinHook.h"
#include "winternl.h"
#include "Utils.h"
#include "CStringPort.h"
#define NTSTATUS int
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth
#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)

HMODULE hOurModule;

static unsigned int ioctlCodeMain = 0xef002407;
BOOL ProcessMainIoctl(LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize);

typedef NTSTATUS(WINAPI *NtDeviceIoControlFile_typedef)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
NtDeviceIoControlFile_typedef NtDeviceIoControlFile_Orig;

typedef HANDLE(WINAPI *CreateFileA_typedef)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
CreateFileA_typedef CreateFileA_Orig;

typedef BOOL(WINAPI *CreateProcessA_typedef)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
CreateProcessA_typedef CreateProcessA_Orig;

typedef BOOL(WINAPI *CreateProcessW_typedef)(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
CreateProcessW_typedef CreateProcessW_Orig;

typedef HMODULE(WINAPI *LoadLibraryA_typedef)(LPCSTR lpLibFileName);
LoadLibraryA_typedef LoadLibraryA_Orig;

typedef BOOL(WINAPI *DebugActiveProcess_typedef)(DWORD dwProcessId);
DebugActiveProcess_typedef DebugActiveProcess_Orig;

typedef BOOL(WINAPI *WaitForDebugEvent_typedef)(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds);
WaitForDebugEvent_typedef WaitForDebugEvent_Orig;

#ifdef EJECT_DEBUGGER

HANDLE hDebuggerThread = INVALID_HANDLE_VALUE;
DWORD dwSavedProcessId = 0;

BOOL WINAPI WaitForDebugEvent_Hook(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds)
{
	if (hDebuggerThread != INVALID_HANDLE_VALUE && hDebuggerThread == GetCurrentThread() && dwMilliseconds == INFINITE)
	{
		while (true)
		{
			BOOL ret = WaitForDebugEvent_Orig(lpDebugEvent, EJECT_DEBUGGER_TIMEOUT);
			if (ret)
				return ret;

			MessageBox(0, "We gonna kill that debugger now", "Killer", 0);
			((DebugActiveProcess_typedef)GetProcAddress(LoadLibrary("Kernel32.dll"), "DebugActiveProcessStop"))(dwSavedProcessId);
			ExitProcess(0);
		}
	}
	else
		return WaitForDebugEvent_Orig(lpDebugEvent, dwMilliseconds);
}

BOOL WINAPI DebugActiveProcess_Hook(DWORD dwProcessId)
{
	hDebuggerThread = GetCurrentThread();
	log("DebugActiveProcess: %d (0x%X) by Thread: %X\n", dwProcessId, dwProcessId, (DWORD)hDebuggerThread);

	dwSavedProcessId = dwProcessId;
	return DebugActiveProcess_Orig(dwProcessId);
}

#endif

BOOL Patch2728Installed = FALSE;
BOOL PatchCheckFailed = FALSE;
DWORD Version, SubVersion, Revision;
DWORD ItemA = 0;
DWORD ItemE_1 = 0;
DWORD ItemE_2 = 0;
DWORD ItemE_3 = 0;

struct TableOffset
{
	DWORD Offset;
	DWORD ValueLocation;
};

TableOffset tableOffsets_2_80_00[] = { 
{ 0x00, 0x470 },
{ 0x08, 0x608 },
{ 0x0C, 0x580 },
{ 0x2C, 0x1A08 },
{ 0x34, 0x1398 },
{ 0x38, 0x10F0 },
{ 0x40, 0x1288 },
{ 0x44, 0x1178 },
{ 0x48, 0x1200 },
{ 0x4C, 0x1068 },
{ 0x50, 0xD30 },
{ 0x54, 0xDB8 },
{ 0x58, 0xE40 },
{ 0x5C, 0xEC8 },
{ 0x60, 0xF50 },
{ 0x64, 0xFD8 },
{ 0x6C, 0x1CE8 },
{ 0x70, 0x2018 },
{ 0x80, 0x1760 },
{ 0x8C, 0x1C8 },
{ 0x90, 0x250 },
{ 0x94, 0x2D8 },
{ 0x9C, 0x360 },
{ 0xB4, 0x3E8 },
{ 0x100, 0x3960 },
{ 0x130, 0x1D70 },
{ 0x144, 0x4510 } };

TableOffset tableOffsets_2_72_00[] = { 
{ 0x000, 0x470 },
{ 0x008, 0x608 },
{ 0x00C, 0x580 },
{ 0x02C, 0x19E0 },
{ 0x034, 0x14D8 },
{ 0x038, 0x1230 },
{ 0x040, 0x13C8 },
{ 0x044, 0x12B8 },
{ 0x048, 0x1340 },
{ 0x04C, 0x11A8 },
{ 0x050, 0xE70 },
{ 0x054, 0xEF8 },
{ 0x058, 0xF80 },
{ 0x05C, 0x1008 },
{ 0x060, 0x1090 },
{ 0x064, 0x1118 },
{ 0x06C, 0x1CB0 },
{ 0x070, 0x1FE0 },
{ 0x080, 0x1848 },
{ 0x08C, 0x1C8 },
{ 0x090, 0x250 },
{ 0x094, 0x2D8 },
{ 0x09C, 0x360 },
{ 0x0B0, 0x3E8 },
{ 0x0FC, 0x3938 },
{ 0x128, 0x1D38 },
{ 0x13C, 0x42C8 } };

TableOffset tableOffsets_2_70_30[] = { 
{ 0x000, 0x470 },
{ 0x008, 0x608 },
{ 0x00C, 0x580 },
{ 0x02C, 0x19E8 },
{ 0x034, 0x14D8 },
{ 0x038, 0x1230 },
{ 0x040, 0x13C8 },
{ 0x044, 0x12B8 },
{ 0x048, 0x1340 },
{ 0x04C, 0x11A8 },
{ 0x050, 0xE70 },
{ 0x054, 0xEF8 },
{ 0x058, 0xF80 },
{ 0x05C, 0x1008 },
{ 0x060, 0x1090 },
{ 0x064, 0x1118 },
{ 0x06C, 0x1CC8 },
{ 0x070, 0x1FF8 },
{ 0x080, 0x1850 },
{ 0x08C, 0x1C8 },
{ 0x090, 0x250 },
{ 0x094, 0x2D8 },
{ 0x09C, 0x360 },
{ 0x0B0, 0x3E8 },
{ 0x0FC, 0x3950 },
{ 0x128, 0x1D50 },
{ 0x13C, 0x42E0 } };

DWORD AuthServDataAddr;
DWORD AuthServStartAddr;
DWORD AuthServEndAddr;
DWORD CRCTableAddress;
BOOL SetCRCTableHasBeenCalled = FALSE;

void SetCRCTable()
{
	if (SetCRCTableHasBeenCalled == FALSE)
	{
		int i;
		BYTE searchBytes[16*22];
		TableOffset *offsets;
		int offset_count;

		if (Version == 2 && SubVersion == 80)
		{
			offsets = tableOffsets_2_80_00;
			offset_count = sizeof(tableOffsets_2_80_00) / sizeof(TableOffset);
		}
		if (Version == 2 && SubVersion == 72)
		{
			offsets = tableOffsets_2_72_00;
			offset_count = sizeof(tableOffsets_2_72_00) / sizeof(TableOffset);
		}

		if (Version == 2 && SubVersion == 70 && Revision == 30)
		{
			offsets = tableOffsets_2_70_30;
			offset_count = sizeof(tableOffsets_2_70_30) / sizeof(TableOffset);
		}

		// Default is all 0xA5s
		memset(searchBytes, 0xA5, 16*22);

		DWORD CRCOffset = CRCTableAddress;
		log("CRCOffset: %08X\n", CRCOffset);

		if (*((DWORD*)CRCOffset) == 0xA5A5A5A5)
		{
			log("Applying Table to %08X\n", CRCOffset);

			// Write CRC Table
			for (i = 0; i < 16*23; i++)
				*(BYTE*)(CRCOffset + i) = 0xA5;
			
			for (i = 0; i < offset_count; i++)
			{
				DWORD Offset = CRCOffset + offsets[i].Offset;
				DWORD ValueLocation = AuthServDataAddr + offsets[i].ValueLocation;
				*((DWORD*)Offset) = *((DWORD*)ValueLocation);
			}
		}
		SetCRCTableHasBeenCalled = TRUE;
	}
}

void WINAPI OurCopyFunction()
{
	// Let's emulate the CopyFunction
	DWORD ItemA_AddressPointedTo = *(DWORD*)ItemA;
	DWORD ItemA_AddressPointedTo2 = *(DWORD*)(ItemA_AddressPointedTo + 0xc);
	DWORD ItemA_1Address = *(DWORD*)(ItemA_AddressPointedTo2 + 0x24);
	DWORD ItemA_2Address = *(DWORD*)(ItemA_AddressPointedTo2 + 0x34);
	DWORD ItemA_3Address = *(DWORD*)(ItemA_AddressPointedTo2 + 0x44);
	//log("ItemA_1Address: %08X ItemA_2Address: %08X ItemA_3Address: %08X\n", ItemA_1Address, ItemA_2Address, ItemA_3Address);

	memcpy((DWORD*)ItemA_1Address, (DWORD*)ItemE_3, 1024);		// The first key should really end up as the 3rd key
	// memcpy((DWORD*)ItemA_2Address, (DWORD*)ItemE_2, 1024);   // Second key will already be set and go through the CRCs 
	memcpy((DWORD*)ItemA_3Address, (DWORD*)ItemE_3, 1024);
}

// Grabber function to jump to in the debugger after getting the right CRC to dump the table for use here 
void WINAPI Grabber()
{
	BYTE *pCRCTable = (BYTE*)CRCTableAddress;
	for (int i = 0; i != 16*23; i+=4)
	{
		if (pCRCTable[i] == 0xA5 && pCRCTable[i+1] == 0xA5 && pCRCTable[i+2] == 0xA5 && pCRCTable[i+3] == 0xA5)
			continue;

		DWORD loc = FindHex(AuthServStartAddr, AuthServEndAddr, &pCRCTable[i], 4);
		if (loc == -1)
			log("Could not find CRC pointer for %03X", i);
		else
		{
			log("{ 0x%03X, 0x%X },\n", i, loc - AuthServDataAddr);
		}
	}
	log("Press any key...");
	getch();
}

DWORD StealCRCTable_2ndFunc;
DWORD StealCRCTable_JMPBack;
__declspec(naked) void StealCRCTable()
{
	__asm
	{
		mov edx, dword ptr ss:[esp]
		mov eax, dword ptr ds:[edx+0x18]
		mov [CRCTableAddress], eax

#ifdef USE_CRC_GRABBER
		call Grabber;
#else
		call SetCRCTable;
#endif

		mov eax, [StealCRCTable_2ndFunc]
		call eax
		push [StealCRCTable_JMPBack]
		retn;
	}
}

HMODULE WINAPI LoadLibraryA_Hook(LPCSTR lpLibFileName)
{
	//log("LoadLibraryA_Hook: %s\n", lpLibFileName == NULL ? "NULL" : lpLibFileName);
	//if (stricmp(lpLibFileName, "rasapi32.dll") == 0)
		//while(true) { ; }

	HMODULE ret = LoadLibraryA_Orig(lpLibFileName);
	
	if (lpLibFileName)
	{
		if (PatchCheckFailed == FALSE && Patch2728Installed == FALSE && strstr(lpLibFileName, ".tmp"))
		{
			log("Loaded DLL: %s\n", lpLibFileName);

			BOOL bReadVersion = FALSE;
			char szExeFile[MAX_PATH];
			if (GetModuleFileName(NULL, szExeFile, MAX_PATH) != 0)
			{
				log("Loaded DLL from: %s\n", szExeFile);

				CStringPort csExeFile = szExeFile;
				csExeFile.MakeLower();
				if (csExeFile.Find(".exe") != -1)
					bReadVersion = GetSafeDiscVersion(szExeFile, &Version, &SubVersion, &Revision);
			}
			
			// Check for SecServ.dll
			if (strstr(lpLibFileName, "~df394b.tmp"))
			{
				if (bReadVersion == TRUE && Version == 2 && SubVersion < 90 && SubVersion >= MINIMUM_SAFEDISC_SUBVERSION)
				{
					PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)ret;
					PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((BYTE*)pidh + pidh->e_lfanew);

					DWORD StartAddr = (DWORD)ret;
					DWORD EndAddr = StartAddr + pinh->OptionalHeader.SizeOfImage;

					// Item A
					log("------------\n");
					log("Item A\n");
					log("------------\n");

					DWORD firstMatch = FindHexString(StartAddr, EndAddr, "FF5014C3");
					DWORD secondMatch = FindHexString(firstMatch+1, EndAddr, "FF5014C3");
					log("FirstMatch: %X SecondMatch: %X\n", firstMatch, secondMatch);
					ItemA = *(DWORD*)(secondMatch + 6);
					log("Item A: %08X (Key Offset to be referenced and used by our copy function)\n", ItemA);

					// Item C
					log("\n------------\n");
					log("Item C\n");
					log("------------\n");

					DWORD ItemCLocation = FindHexString(StartAddr, EndAddr, "66B80100C9C21000E900");
					log("ItemCLocation: %X\n", ItemCLocation);
					DWORD ItemCLocation1stAddr = *((DWORD*)(ItemCLocation-0xf));
					DWORD ItemCLocation2ndAddr = *((DWORD*)(ItemCLocation-4));
					log("Item C - 1st Addr: %08X (Memory Location that needs to be made 0 so the cmp check works)\n", ItemCLocation1stAddr); 
					log("Item C - 2nd Addr: %08X (Memory Location to the function pointer that will be changed to point to our copy function)\n", ItemCLocation2ndAddr);

					DWORD CRCHookLocation = FindHexString(StartAddr, EndAddr, "83661000E810000000");
					if (CRCHookLocation != -1L)
					{
						log("CRCHookLocation: %08X\n", CRCHookLocation);
						WriteProtectedDWORD(CRCHookLocation + 4, 0xE9);
						DWORD StealCRCTableLocation = (DWORD)&StealCRCTable;
						WriteProtectedDWORD(CRCHookLocation + 5,StealCRCTableLocation - (CRCHookLocation + 4 + 5));

						StealCRCTable_2ndFunc = CRCHookLocation + 0x19;
						StealCRCTable_JMPBack = CRCHookLocation + 0x9;
					}
					else
						log("Cannot find CRC Hook Location\n");

					WriteProtectedDWORD(ItemCLocation1stAddr, 0);
					WriteProtectedDWORD(ItemCLocation2ndAddr, (DWORD)&OurCopyFunction);
				}
				else
					PatchCheckFailed = TRUE;
			}
			else
			{
				if (bReadVersion == TRUE && Version == 2 && SubVersion < 90 && SubVersion >= MINIMUM_SAFEDISC_SUBVERSION && PatchCheckFailed == FALSE && Patch2728Installed == FALSE)
				{
					// The only other tmp dll that gets loaded is AuthServ.dll
					PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)ret;
					PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((BYTE*)pidh + pidh->e_lfanew);

					DWORD StartAddr = (DWORD)ret;
					DWORD EndAddr = StartAddr + pinh->OptionalHeader.SizeOfImage;

					// Item D
					log("------------\n");
					log("Item D\n");
					log("------------\n");

					DWORD ItemDLocationPart1 = FindHexString(StartAddr, EndAddr, "EB05B85000????8BE55DC3");
					DWORD ItemDLocationPart2 = FindHexString(StartAddr, EndAddr, "EB0E8B0D????????FF51048B55F88902E9");

					// Part 1
					ItemDLocationPart1 += 2;	
					log("ItemDLocationPart1: %08X (Address of function to return the right result code)\n", ItemDLocationPart1);
					log("Need to find a version of it that is just mov then ret\n");
					BYTE SearchBuffer[6];
					memcpy(SearchBuffer, (BYTE*)ItemDLocationPart1, 5);
					SearchBuffer[5] = 0xC3;
					ItemDLocationPart1 = FindHex(StartAddr, EndAddr, SearchBuffer, 6);
					log("New ItemDLocationPart1: %08X\n", ItemDLocationPart1);
					
					// Part 2
					ItemDLocationPart2 += 4;	//
					log("ItemDLocationPart2: %08X (Code Location that has a pointer to the data that has a pointer to the cd check function we will redirect)\n", ItemDLocationPart2);
					
					DWORD ItemDLocationPart2_AddressFromTheCode = *((DWORD*)ItemDLocationPart2);
					log("Item D Part 2 - Address from the code: %08X\n", ItemDLocationPart2_AddressFromTheCode);
					DWORD ItemDLocationPart2_LocationAtAddressFromTheCode = *((DWORD*)ItemDLocationPart2_AddressFromTheCode);
					log("Item D Part 2 - LocationAddress from the code: %08X\n", ItemDLocationPart2_AddressFromTheCode);
					DWORD ItemDLocationPart2_LocationAtAddressFromTheCodePlus4 = ItemDLocationPart2_LocationAtAddressFromTheCode + 4;

					// Removes all CD Checks
					WriteProtectedDWORD(ItemDLocationPart2_LocationAtAddressFromTheCodePlus4, ItemDLocationPart1);	// Redirect the CD Checks to give the right result

					// Item E - TODO: Currently hardcoded
					if (Version == 2 && SubVersion == 90)
						ItemE_3 = ((DWORD)ret) + 0x34BAA;

					if (Version == 2)
					{
						if (SubVersion == 80)	// 2.80.10 == HPCOS + FIFA 2003 + Bond Nightfire
						{
							ItemE_1 = ((DWORD)ret) + 0x32AC8;   // Key 1 - Final Key before processing
							ItemE_2 = ((DWORD)ret) + 0x3301D;   // Key 2 - The difficult key
							ItemE_3 = ((DWORD)ret) + 0x33572;   // 0x32AC8;//0x3301D;	// Key 3 (Final Key)
						}
						if (SubVersion == 72 && Revision == 0)  // Madden 2003
						{
							ItemE_1 = ((DWORD)ret) + 0x32878;
							ItemE_2 = ((DWORD)ret) + 0x32DCD;
							ItemE_3 = ((DWORD)ret) + 0x33322;
						}
						if (SubVersion == 70 && Revision == 30)	// Mafia, MS Combat Flight Simulator 3
						{
							ItemE_1 = ((DWORD)ret) + 0x32890;
							ItemE_2 = ((DWORD)ret) + 0x32DE5;
							ItemE_3 = ((DWORD)ret) + 0x3333A;
						}
					
						if (ItemE_1 != 0 && ItemE_2 != 0 && ItemE_3 != 0)
						{
							LogKey("First Key", ItemE_1);
							LogKey("Second Key", ItemE_2);
							LogKey("Third Key", ItemE_3);

							for (int i = 0; i < 1024; i++)
							{
								*((BYTE*)(ItemE_2 + i)) ^= *((BYTE*)(ItemE_1 + i)) ^ *((BYTE*)(ItemE_3 + i));
							}

							LogKey("New Second Key", ItemE_2);
						}

						DWORD ItemA_AddressPointedTo = *(DWORD*)ItemA;
						DWORD ItemA_AddressPointedTo2 = *(DWORD*)(ItemA_AddressPointedTo + 0xc);
						DWORD ItemA_1Address = *(DWORD*)(ItemA_AddressPointedTo2 + 0x24);
						DWORD ItemA_2Address = *(DWORD*)(ItemA_AddressPointedTo2 + 0x34);
						DWORD ItemA_3Address = *(DWORD*)(ItemA_AddressPointedTo2 + 0x44);
						log("ItemA_1Address: %08X ItemA_2Address: %08X ItemA_3Address: %08X\n", ItemA_1Address, ItemA_2Address, ItemA_3Address);

						// Only set the new Second Key here (it will then go through the 3 CRC processes)
						if (ItemE_2 != 0)
							memcpy((DWORD*)ItemA_2Address, (DWORD*)ItemE_2, 1024);

						AuthServDataAddr = StartAddr + GetSectionByName(StartAddr, ".data")->VirtualAddress;
						AuthServStartAddr = StartAddr;
						AuthServEndAddr = EndAddr;
					}

					//getch();
					//DebugBreak();
					Patch2728Installed = TRUE;
				}
			}
		}
	}

	return ret;
}

NTSTATUS NTAPI NtDeviceIoControlFile_Hook(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) 
{
    // all IOCTLs will pass through this function, but it's probably fine since secdrv uses unique control codes
    if (IoControlCode == ioctlCodeMain) {
        if (ProcessMainIoctl(InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength)) 
        {
            IoStatusBlock->Information = OutputBufferLength;
            IoStatusBlock->DUMMYUNIONNAME.Status = STATUS_SUCCESS;
        }
        else 
            IoStatusBlock->DUMMYUNIONNAME.Status = STATUS_UNSUCCESSFUL;
    }
    else if (IoControlCode == 0xCA002813) 
    {
        log("IOCTL 0xCA002813 unhandled (please report!)");
        IoStatusBlock->DUMMYUNIONNAME.Status = STATUS_UNSUCCESSFUL;
    }
    else 
    {
        // not a secdrv request, pass to original function
        return NtDeviceIoControlFile_Orig(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
    }
    return IoStatusBlock->DUMMYUNIONNAME.Status;
}

HANDLE WINAPI CreateFileA_Hook(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) 
{
/*
	char szFileName[MAX_PATH];
	GetModuleFileName(NULL, szFileName, MAX_PATH);
	log("%s: CreateFileA: %s\n", szFileName, lpFileName);
*/

	if (!lstrcmpiA(lpFileName, "\\\\.\\Secdrv") || !lstrcmpiA(lpFileName, "\\\\.\\Global\\SecDrv"))
    {
        // we need to return a handle when secdrv is opened, so we just open the null device to get an unused handle
        HANDLE dummyHandle = CreateFileA_Orig("NUL", GENERIC_READ, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (dummyHandle == INVALID_HANDLE_VALUE)
            log("unable to obtain a dummy handle for secdrv");
        return dummyHandle;
    }
    
	//CreateFileA_Orig

	return CreateFileA_Orig(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

int InjectSelf(DWORD pid)
{
	char szSecDrvEmuDLLPath[MAX_PATH];
	
	GetModuleFileName(hOurModule, szSecDrvEmuDLLPath, MAX_PATH);

	log("Injecting DLL %s\n", szSecDrvEmuDLLPath);

    // Open Process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) // Not INVALID_HANDLE_VALUE...Strangely
    {
        log("Process found, but cannot open handle\n");
        return -1;
    }

    // Get the address of our LoadLibraryA function. This is assuming our address for LoadLibrary will be the same as our target processes 
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

    // Get full path name of the target dll
    char szPath[MAX_PATH];
    GetFullPathNameA(szSecDrvEmuDLLPath, MAX_PATH, szPath, NULL);

    // Create Memory in Target Process to hold the DLL's filename
    LPVOID newMemory = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(szPath)+1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (newMemory == NULL)
    {
        log("Could not allocate memory inside the target process\n");
        return -1;
    }

    // Write the fullpath filename into the target process
    BOOL bWritten = WriteProcessMemory(hProcess, newMemory, szPath, strlen(szPath)+1, NULL);
    if (bWritten == 0)
    {
        log("There were no bytes written to the process's address space.\n");
        return -1;
    }

    // Create Remote Thread to run LoadLibrary with our fullpath
    HANDLE hNewThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, newMemory, NULL, NULL);
    if (hNewThread == NULL)
    {
        log("Could not create remote thread in target process\n");
    }
    
    // Wait for it to run
    WaitForSingleObject(hNewThread, INFINITE);

    // Clean up
    CloseHandle(hNewThread);
    CloseHandle(hProcess);

	log("Injecting into pid %d\n", pid);

	return 0;
}

BOOL WINAPI CreateProcessA_Hook(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,  LPPROCESS_INFORMATION lpProcessInformation) 
{
    log("CreateProcessA Hook\n");

    // if the process isn't created suspended, set the flag so we can inject hooks
    const DWORD isCreateSuspended = dwCreationFlags & CREATE_SUSPENDED;
    if (!isCreateSuspended) dwCreationFlags |= CREATE_SUSPENDED;

    if (!CreateProcessA_Orig(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)) 
        return FALSE;

    log("Hooking and calling Process at CreateProcessA_Hook\n");

	InjectSelf(lpProcessInformation->dwProcessId);

	if (!isCreateSuspended)
		ResumeThread(lpProcessInformation->hThread);

    return TRUE;
}

BOOL WINAPI CreateProcessW_Hook(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) 
{
	log("CreateProcessW Hook\n");

  // if the process isn't created suspended, set the flag so we can inject hooks
  const DWORD isCreateSuspended = dwCreationFlags & CREATE_SUSPENDED;
  if ( !isCreateSuspended ) dwCreationFlags |= CREATE_SUSPENDED;

  if ( !CreateProcessW_Orig(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation) )
    return FALSE;

  InjectSelf(lpProcessInformation->dwProcessId);

  if (!isCreateSuspended)
	ResumeThread(lpProcessInformation->hThread);

  return TRUE;
}

DWORD WINAPI HookThread(HINSTANCE hModule)
{
#ifdef LOGGING
	log_file = fopen("C:\\Games\\Football Manager 2005\\nicklog.txt", "a+t");
    AllocConsole();
    freopen("CONOUT$", "w", stdout); 
	log("TRIED TO ALLOC A CONSOLE\n");
#endif

	log("Hooks Starting\n");

	hOurModule = hModule;

    MH_STATUS status = MH_Initialize();

    DisableThreadLibraryCalls(hModule);

    if (status != MH_OK)
    {
        log("Minhook init failed!\n");
        return 0;
    }

	// No longer fail if we can't hook CreateProcess - it might not be needed and DxWnd can make it unhookable if it hooks it when DisableGameUX is enabled
	if ((status = MH_CreateHookApi(L"kernel32", "CreateProcessA", &CreateProcessA_Hook, reinterpret_cast<LPVOID*>(&CreateProcessA_Orig))) != MH_OK) 
    {
        log("Unable to hook CreateProcessA: %d\n", status);
		//return false;
    }

	if (MH_CreateHookApi(L"kernel32", "CreateProcessW", &CreateProcessW_Hook, reinterpret_cast<LPVOID*>(&CreateProcessW_Orig)) != MH_OK) 
    {
        log("Unable to hook CreateProcessW\n");
        // return false;
    }

    if (MH_CreateHookApi(L"ntdll", "NtDeviceIoControlFile", &NtDeviceIoControlFile_Hook, reinterpret_cast<LPVOID*>(&NtDeviceIoControlFile_Orig)) != MH_OK) 
    {
        log("Unable to hook NtDeviceIoControlFile\n");
        return 0;
    }

	// If using DCEAPIHook then hook using Kernel32's Export table instead - this ensures DCE will hook the same CreateFileA pointer as SafeDisc
	if (GetFileAttributes("DCEAPIHook.dll") != -1L)
	{
		CreateFileA_Orig = (HANDLE(WINAPI*)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE))(FindRealAddress("kernel32.dll", "CreateFileA"));
		FindRealAddress("kernel32.dll", "CreateFileA", (DWORD)&CreateFileA_Hook);
	}
	else
	{
		if (MH_CreateHookApi(L"kernel32", "CreateFileA", &CreateFileA_Hook, reinterpret_cast<LPVOID*>(&CreateFileA_Orig)) != MH_OK) 
		{
			log("Unable to hook CreateFileA\n");
			return false;
		}
	}
	
	if (MH_CreateHookApi(L"kernel32", "LoadLibraryA", &LoadLibraryA_Hook, reinterpret_cast<LPVOID*>(&LoadLibraryA_Orig)) != MH_OK) 
    {
        log("Unable to hook LoadLibraryA\n");
        return false;
    }

#ifdef EJECT_DEBUGGER
	if (MH_CreateHookApi(L"kernel32", "DebugActiveProcess", &DebugActiveProcess_Hook, reinterpret_cast<LPVOID*>(&DebugActiveProcess_Orig)) != MH_OK) 
    {
        log("Unable to hook DebugActiveProcess\n");
        return false;
    }

	if (MH_CreateHookApi(L"kernel32", "WaitForDebugEvent", &WaitForDebugEvent_Hook, reinterpret_cast<LPVOID*>(&WaitForDebugEvent_Orig)) != MH_OK) 
	{
        log("Unable to hook WaitForDebugEvent\n");
        return false;
    }
#endif

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
        log("Enable Hooks Failed!\n");
        return false;
    }

	log("Hooks Complete!\n");

	if (GetFileAttributes("DCEAPIHook.dll") != -1L)
	{
		LoadLibrary("DCEAPIHook.dll");
		log("Loading DCEAPIHook.dll!\n");
	}

    return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)  
    {
    case DLL_PROCESS_ATTACH:
		if (!HookThread(hModule))
			::MessageBox(NULL, "Failed to hook!", "SafeDiscLoader", MB_ICONERROR);
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
