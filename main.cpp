#ifdef _DEBUG
#define LOGGING
#endif

#define MINIMUM_SAFEDISC_SUBVERSION 70
#define SECDRVDLL_NAME "secdrvemu_v1.1.dll"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <tlhelp32.h>
#include "resource.h"
#include "secdrvemu/CStringPort.h"
#include "secdrvemu/Utils.h"

#ifdef _DEBUG
BOOL AlwaysCreateDLLs = TRUE;
#else
BOOL AlwaysCreateDLLs = FALSE;
#endif

BOOL bMovedDrvMgt = FALSE;
char szSystemDrvMgtPath[MAX_PATH];

void PutBackSafeDiscShim()
{
	if (bMovedDrvMgt)
	{
		char szSrcPath[MAX_PATH];
		sprintf(szSrcPath, "%s%s", szSystemDrvMgtPath, ".disable");
		if (!MoveFile(szSrcPath, szSystemDrvMgtPath))
			log("Unable to put back SafeDiscShim!\r\n");
		bMovedDrvMgt = FALSE;
	}
}

void exitlog(const char* fmt, ...)
{
	va_list va;
    va_start(va, fmt);
#ifdef _DEBUG
    vfprintf(stdout, fmt, va);
#else
	char buf[1000];
	vsprintf(buf, fmt, va);
	::MessageBox(NULL, buf, "SafeDiscLoader", MB_ICONERROR);
#endif
    va_end(va);

#ifdef _DEBUG
	getch();
#endif

	PutBackSafeDiscShim();
	exit(-1);
}

void LoadResource(DWORD ResID, BYTE **pBuf, DWORD *pSize)
{
    HRSRC myResource = FindResource(NULL,  MAKEINTRESOURCE(ResID), "DATA");

	if (myResource == NULL)
		exitlog("Could not LoadResource");
    HGLOBAL myResourceData = ::LoadResource(NULL, myResource);
	*pSize = SizeofResource(NULL, myResource);
    *pBuf = (BYTE *)LockResource(myResourceData);
}

void InjectDrvMgt(DWORD pid)
{
	HANDLE hProcess;
	char szSecDrvEmuDLLPath[MAX_PATH];
	GetTempPath(MAX_PATH, szSecDrvEmuDLLPath);
	strcat(szSecDrvEmuDLLPath, SECDRVDLL_NAME);
	if (AlwaysCreateDLLs || GetFileAttributes(szSecDrvEmuDLLPath) == -1L)
	{
		BYTE *pBuf;
		DWORD dwSize;
		LoadResource(IDR_SECDRVEMUDLL1, &pBuf, &dwSize);
		FILE *fout = fopen(szSecDrvEmuDLLPath, "wb");
		if (!fout)
		{
			exitlog("Could not write SecDrvEmu.dll\n");
		}
		fwrite(pBuf, 1, dwSize, fout);
		fclose(fout);
	}

    // Open Process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) // Not INVALID_HANDLE_VALUE...Strangely
    {
        exitlog("Process found, but cannot open handle\n");
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
        exitlog("Could not allocate memory inside the target process\n");
    }

    // Write the fullpath filename into the target process
    BOOL bWritten = WriteProcessMemory(hProcess, newMemory, szPath, strlen(szPath)+1, NULL);
    if (bWritten == 0)
    {
        exitlog("There were no bytes written to the process's address space.\n");
    }

    // Create Remote Thread to run LoadLibrary with our fullpath
    HANDLE hNewThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, newMemory, NULL, NULL);
    if (hNewThread == NULL)
    {
        exitlog("Could not create remote thread in target process\n");
    }
    
    // Wait for it to run
    WaitForSingleObject(hNewThread, INFINITE);

    // Clean up
    CloseHandle(hNewThread);
    CloseHandle(hProcess);
}

void InjectAndHope(const char *lpApplicationName, bool bShowPopUp = true)
{
	if (!bShowPopUp || MessageBox(NULL, "This does not appear to be a SafeDisc 2.7 or higher executable!\r\n\r\nInject SecDrvEmu.dll Emulation and hope for the best anyway?", "SafeDiscLoader", MB_ICONQUESTION | MB_YESNOCANCEL) == IDYES)
	{
		STARTUPINFO StartupInfo = { 0 };
		PROCESS_INFORMATION pi = { 0 };
		StartupInfo.cb = sizeof(STARTUPINFO);

		log("lpApplicationName: %s\n", lpApplicationName);
		BOOL bSuccess = CreateProcessA(NULL, (char*)lpApplicationName, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &StartupInfo, &pi);
		if (!bSuccess)
			exitlog("Failed to CreateProcess: %s\r\n(ErrCode: %d)\n", lpApplicationName, GetLastError());

		InjectDrvMgt(pi.dwProcessId);

		ResumeThread(pi.hThread);

		PutBackSafeDiscShim();
		exit(0);
	}
	else
		exit(-1);
}

HANDLE hProcess;

BYTE byte_402000[155] = { 0xEB, 0x00, 0x60, 0x9C, 0xE8, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0xC6, 0x40, 0x85,
0xFE, 0x83, 0xC0, 0x1B, 0xFF, 0x34, 0x24, 0x89, 0x44, 0x24, 0x04, 0xFF, 0x10, 0x5B, 0x89, 0x03,
0x9D, 0x61, 0xE9, 0x69, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 };

BYTE *byte_402009;
DWORD *dword_4029AC;
DWORD dword_4021BC = 187;
DWORD dword_4029B4;

void sub_401026(BYTE a1, BYTE a2, BYTE a3, BYTE a4, BYTE a5)
{
	BYTE *v5; // ebx
	void *v6; // [esp-34h] [ebp-34h]

	v5 = (((BYTE*)dword_4029AC) + *((DWORD *)dword_4029AC + 15)) - 8;
	v5[5] = a5;
	v5[4] = a4;
	v5[3] = a3;
	v5[2] = a2;
	v5[1] = a1;
	*v5 = 0xCC;
	v6 = (void *)(dword_4029B4 + v5 - ((BYTE *)dword_4029AC));
	DWORD flOldProtect;
	VirtualProtectEx(hProcess, v6, 8, 0x40, &flOldProtect);
	DWORD dwWritten;
	WriteProcessMemory(hProcess, v6, v5, 8, &dwWritten);
}

void sub_401000()
{

	char szSDLoaderDLLPath[MAX_PATH];
	GetTempPath(MAX_PATH, szSDLoaderDLLPath);
	strcat(szSDLoaderDLLPath, "SDLoader.dll");
	if (AlwaysCreateDLLs || GetFileAttributes(szSDLoaderDLLPath) == -1L)
	{
		BYTE *pBuf;
		DWORD dwSize;
		LoadResource(IDR_SDLOADERDLL1, &pBuf, &dwSize);
		FILE *fout = fopen(szSDLoaderDLLPath, "wb");
		if (!fout)
		{
			exitlog("Could not write SDLoader.dll\n");
		}
		fwrite(pBuf, 1, dwSize, fout);
		fclose(fout);
	}

	wsprintfA((char*)byte_402009, szSDLoaderDLLPath);
}

char *GetDirectoryFromPath(const char *szPath)
{
	char *szRet = strdup(szPath);
	if (strrchr(szRet, '\\'))
		*strrchr(szRet, '\\') = 0;
	else
		szRet = strdup(".");
	return szRet;
}

void SetCurrentDirectoryFromPath(const char *szPath)
{
	char *szDirPath = GetDirectoryFromPath(szPath);
	SetCurrentDirectory(szDirPath);
	free(szDirPath);
}

int main(int argc, char *argv[])
{
	BOOL bSuccess = TRUE;

	// Check for SafeDiscShim
	if (GetSystemDirectory(szSystemDrvMgtPath, MAX_PATH))
	{
		log("System Directory: %s\n", szSystemDrvMgtPath);
		strcat(szSystemDrvMgtPath, "\\drvmgt.dll");
		if (GetFileAttributes(szSystemDrvMgtPath) != -1L)
		{
			// Screw asking - gets annoying
			// if (::MessageBox(NULL, "SafeDiscShim Detected!\r\nPlease remove or disable before continuing.\r\n\r\nWould you like to temporarily disable SafeDiscShim?", "SafeDiscLoader", MB_ICONERROR | MB_YESNOCANCEL) == IDYES)
			{
				char szDestPath[MAX_PATH];
				sprintf(szDestPath, "%s%s", szSystemDrvMgtPath, ".disable");
				if (!MoveFile(szSystemDrvMgtPath, szDestPath))
					exitlog("Unable to disable SafeDiscShim!\r\n");
				else
					bMovedDrvMgt = TRUE;
			}
			//else
			//	exit(-1);
		}
	}

	byte_402009 = byte_402000 + 9;
	sub_401000();

#ifdef _DEBUG
	//char *szPath = "C:\\Program Files (x86)\\EA GAMES\\The Sims 2\\TSBin\\Sims2.exe -w";
	//char *szPath = "C:\\Games\\Football Manager 2005\\fm2005.exe";
	//char *szPath = "C:\\Games\\Call of Duty 4 - Modern Warfare\\iw3sp.exe";
	//char *szPath = "C:\\Games\\BF1942\\BF1942.exe";
	//char *szPath = "C:\\Games\\HPCOS\\System\\Game.Exe";
	//char *szPath = "C:\\Games\\FIFA 2003\\fifa2003.Exe";
	//char *szPath = "C:\\Games\\Nightfire\\Bond.exe";
	//char *szPath = "C:\\Games\\Mafia\\Game.exe";
	//char *szPath = "C:\\Games\\Need For Speed Underground\\Speed_Orig.exe";
	//char *szPath = "C:\\Games\\Need For Speed Underground\\Speed.exe";
	//char *szPath = "F:\\Games\\Harry Potter and the Chamber of Secrets\\system\\Game.exe";
	//char *szPath = "C:\\Games\\Madden NFL 2003\\mainapp.exe";
	//char *szPath = "C:\\Games\\Kohan\\Kohan.exe";
	char *szPath = "C:\\Games\\Kohan\\kohan_NoCD_Loader.exe";
	//char *szPath = "C:\\Games\\Kohan\\Kohan_Deviance1.exe";
	//char *szPath = "C:\\Games\\Hitman - Codename 47\\Hitman.exe";
	//char *szPath = "C:\\Games\\Combat Flight Simulator 3\\cfs3.exe";
#else
	char szPathBuffer[MAX_PATH];
	char *szPath = NULL;

	ZeroMemory(szPathBuffer, MAX_PATH);
	if (argc < 2)
	{
		FILE *fini = fopen("SafeDiscLoader.ini", "rt");
		if (fini)
		{
			fgets(szPathBuffer, MAX_PATH, fini);
			fclose(fini);

			if (strlen(szPathBuffer) != 0)
			{
				if (strstr(szPathBuffer, "\r"))
					*strstr(szPathBuffer, "\r") = 0;
				if (strstr(szPathBuffer, "\n"))
					*strstr(szPathBuffer, "\n") = 0;
				szPath = szPathBuffer;
			}
		}

		if (szPath == NULL)
		{
			OPENFILENAME ofn = {0};
			ofn.lStructSize = sizeof(ofn);
			ofn.hwndOwner = NULL;
			ofn.lpstrFile = szPathBuffer;
			ofn.nMaxFile = MAX_PATH;
			ofn.lpstrFilter = "Executables (*.exe)\0*.exe\0All\0*.*\0\0";
			ofn.nFilterIndex = 1;
			ofn.lpstrFileTitle = NULL;
			ofn.nMaxFileTitle = 0;
			ofn.lpstrInitialDir = NULL;
			ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

			if (GetOpenFileName(&ofn) == TRUE)
			{
				szPath = szPathBuffer;
			}
		}
	}
	else
	{
		for (int i = 1; i < argc; i++)
		{
			if (strstr(argv[i], " "))
			{
				strcat(szPathBuffer, "\"");
				strcat(szPathBuffer, argv[i]);
				strcat(szPathBuffer, "\"");
			}
			else
				strcat(szPathBuffer, argv[i]);
			if (i != argc-1)
				strcat(szPathBuffer, " ");
		}
		szPath = szPathBuffer;
	}
#endif

	log("szPath: %s\n", szPath);

	char *szExePath = szPath;

	CStringPort szExePart = szExePath;
	int exe_idx = szExePart.MakeLower().Find(".exe");

	if (exe_idx != -1)
	{
		// duplicate cut off after the .exe part (so any params etc are removed 
		// soit's just a path to the exe
		szExePath = strdup(szExePath);
		szExePath[exe_idx+4] = 0;

		// Cut off any quotation marks
		if (szExePath[0] == '\"')
			szExePath++;
		if (szExePath[strlen(szExePath)-1] == '\"')
			szExePath[strlen(szExePath)-1] = 0;
	}

	SetCurrentDirectoryFromPath(szPath);

	char szCurDir[MAX_PATH];
	if (GetCurrentDirectory(MAX_PATH, szCurDir))
		log("Current Directory: %s\n", szCurDir);

	const char *lpApplicationName = szPath;

	HANDLE hFile = CreateFile(szExePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	log("szExePath: %s\n", szExePath);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		exitlog("Could not open file: %s\r\n(ErrCode: %d)\n", szExePath, GetLastError());
	}

	DWORD nNumberOfBytesToRead = GetFileSize(hFile, 0);

	DWORD dwSize = (nNumberOfBytesToRead + 0x10000) & 0x3FFF0000;

	void *v2 = VirtualAlloc(0, (nNumberOfBytesToRead + 0x10000) & 0x3FFF0000, 0x1000u, 4u);
	dword_4029AC = (DWORD*) v2;

	if (!v2)
	{
		exitlog("Cannot allocate memory\n");
	}

	DWORD NumberOfBytesRead;
	ReadFile(hFile, v2, nNumberOfBytesToRead, &NumberOfBytesRead, 0);
	CloseHandle(hFile);

	if ( NumberOfBytesRead != nNumberOfBytesToRead )
	{
		exitlog("Could not read entire file\n");
	}

	DWORD SafeDiscVersion, SafeDiscSubVersion, SafeDiscRevision;
	if (GetSafeDiscVersionFromBuffer((BYTE*)v2, NumberOfBytesRead, &SafeDiscVersion, &SafeDiscSubVersion, &SafeDiscRevision))
	{
		if (SafeDiscVersion == 2 && SafeDiscSubVersion < 90 && SafeDiscSubVersion >= MINIMUM_SAFEDISC_SUBVERSION)
		{
			log("SafeDisc Version 2.7 or 2.8! Doing our own loader!\n");
			InjectAndHope(lpApplicationName, false);
		}
	}
	
	DWORD *esi = dword_4029AC;
	DWORD *ebx = esi;
	ebx += nNumberOfBytesToRead;
	ebx -= 4;
	if (*(WORD*)esi != 23117)
	{
		InjectAndHope(lpApplicationName);
	}
	esi = (DWORD*)(((BYTE*)esi) + esi[15]);
	if (esi > ebx)
	{
		InjectAndHope(lpApplicationName);
	}
	if (*esi != 17744)
	{
		InjectAndHope(lpApplicationName);
	}

	DWORD *v3 = esi;
	dword_4029B4 = v3[13];
	void *lpAddress = (LPVOID)(v3[10] + dword_4029B4); // Original OEP

	STARTUPINFO StartupInfo = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	StartupInfo.cb = sizeof(STARTUPINFO);

	log("lpApplicationName: %s\n", lpApplicationName);
	bSuccess = CreateProcessA(NULL, (char*)lpApplicationName, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &StartupInfo, &pi);

	if (!bSuccess)
		exitlog("Failed to CreateProcess: %s\r\n(ErrCode: %d)\n", lpApplicationName, GetLastError());
	hProcess = pi.hProcess;
	
	DWORD dword_402253;
	ReadProcessMemory(hProcess, (char *)lpAddress - 4, &dword_402253, 4, 0);
	if ( dword_402253 != 1887007348 )
	{
		TerminateProcess(hProcess, -1);
		InjectAndHope(lpApplicationName);
	}

	ReadProcessMemory(hProcess, (char *)lpAddress + 187, &dword_402253, 4, 0);
	if ( *((BYTE*)&dword_402253) != 0xE9 )
	{
		if ( *(((BYTE*)&dword_402253)+2) != 0xE9 )
		{
			TerminateProcess(hProcess, -1);
			InjectAndHope(lpApplicationName);
		}
		dword_4021BC = 189;
	}

	/*
	  Hook JMP-OEP:             disabled
	  Logging:                  enabled
	  CD-Check function skip:   enabled
	  Alternative Key Finding:  enabled
    */
#ifdef _DEBUG
	BOOL LOG_SD_LOADER = TRUE;
#else
	BOOL LOG_SD_LOADER = FALSE;
#endif


	sub_401026((BYTE)dword_4021BC, 0, LOG_SD_LOADER, 1, 1);		/// This sets the modes for SDLoader.dll - all 1s is debug stop at OEP. Normal is 0,0,1,1


	*(DWORD*)(byte_402000 + 0x97) = (DWORD)LoadLibraryA;

	void *lpBaseAddress = lpAddress;
	DWORD flOldProtect;
	BYTE unk_40209B[0x9b] = { 0 };		// 0x9b = 155

	InjectDrvMgt(pi.dwProcessId);

	InjectDCEAPIHook(pi.dwProcessId);

	bSuccess = VirtualProtectEx(pi.hProcess, lpAddress, 0x9B, 0x40, &flOldProtect);
	bSuccess = ReadProcessMemory(pi.hProcess, lpAddress, &unk_40209B, 0x9B, 0);
	bSuccess = WriteProcessMemory(pi.hProcess, lpAddress, &byte_402000, 0x9B, 0);
	if (!bSuccess)
		exitlog("Unable to write to process memory\n");

	bSuccess = ResumeThread(pi.hThread);

	if (!bSuccess)
		exitlog("Unable to resume exe\n");

	CONTEXT stru_402447 = { 0 };
	stru_402447.ContextFlags = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | \
                                 CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | \
                                 CONTEXT_EXTENDED_REGISTERS);
	while ( 1 )
	{
		if ( !GetThreadContext(pi.hThread, &stru_402447))
		{
			exitlog("Could not GetThreadContext 1\n");
		}
		DWORD dword_402550 = stru_402447.Eip;
		if ( (LPVOID)dword_402550 == lpBaseAddress )
		  break;
		Sleep(0x10u);
	}

	DWORD dword_4029BC;
	SuspendThread(pi.hThread);
	ReadProcessMemory(pi.hProcess, ((BYTE*)lpAddress) + 151, &dword_4029BC, 4, 0);

	bSuccess = FALSE;
	if (dword_4029BC)
	{
		WriteProcessMemory(hProcess, lpAddress, &unk_40209B, 0x9B, 0);
		lpBaseAddress = (BYTE*)lpAddress + dword_4021BC;
		BYTE *v9 = (BYTE*)lpAddress + dword_4021BC;

		DWORD unk_4023ED;
		BYTE unk_4023EB[2] = { 0xEB, 0xFE };
		ReadProcessMemory(hProcess, v9, &unk_4023ED, 2u, 0);
		WriteProcessMemory(hProcess, v9, &unk_4023EB, 2u, 0);    // <--- PUT EB FE in the start
		ResumeThread(pi.hThread);	

		for ( DWORD dword_4029C0 = 0; dword_4029C0 != 30; ++dword_4029C0 )
		{
			CONTEXT stru_402447_2 = { 0 };
			stru_402447_2.ContextFlags = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | \
									 CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | \
									 CONTEXT_EXTENDED_REGISTERS);
			GetThreadContext(pi.hThread, &stru_402447_2);
			if ( ((LPVOID)stru_402447_2.Eip) == lpBaseAddress )		// Should be 0x012c1159
			{
				SuspendThread(pi.hThread);
				WriteProcessMemory(pi.hProcess, lpBaseAddress, &unk_4023ED, 2u, 0);
				bSuccess = ResumeThread(pi.hThread);
				break;
			}
			Sleep(0x64u);
		}
	}

	if (!bSuccess)
		exitlog("Failed to start at OEP!\n");

	PutBackSafeDiscShim();
	return 0;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE /*hPrevInst*/, LPSTR cmd_line, int showmode)
{
#ifdef LOGGING
    AllocConsole();
    freopen("CONOUT$", "w", stdout); 
#endif

	int ret = main(__argc, __argv);

#ifdef LOGGING
	FreeConsole();
#endif
	return 0;
}