#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <tlhelp32.h>
#include "resource.h"

#define LDE_X86 0

//#ifdef _DEBUG
#define LOGGING
//#endif

#ifdef __cplusplus
extern "C"
#endif
int __stdcall LDE(void* address , DWORD type);

BOOL AlwaysCreateDLLs = TRUE;

/*
https://github.com/BeaEngine/lde64
void SetupHook(char *module, char *name_export, void *Hook_func, void *trampo, DWORD addr)
{
	DWORD	OldProtect;
	DWORD	len;
	FARPROC	Proc;

	if (addr != 0)
	{
		Proc = (FARPROC)addr;
	}
	else
	{
		Proc = GetProcAddress(GetModuleHandleA(module), name_export);
		if (!Proc)
		    return;
	}
	len = 0;
	while (len < 5)
		len += LDE((BYTE*)Proc + len , LDE_X86);
	memcpy(trampo, Proc, len);
	*(BYTE *)((BYTE*)trampo + len) = 0xE9;
	*(DWORD *)((BYTE*)trampo + len + 1) = (BYTE*)Proc - (BYTE*)trampo - 5;
	VirtualProtect(Proc, len, PAGE_EXECUTE_READWRITE, &OldProtect);
	*(BYTE*)Proc = 0xE9;
	*(DWORD*)((char*)Proc + 1) = (BYTE*)Hook_func - (BYTE*)Proc - 5;
	VirtualProtect(Proc, len, OldProtect, &OldProtect);
}*/

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
	exit(-1);
}

void log(const char* fmt, ...)
{
	va_list va;
    va_start(va, fmt);
    vfprintf(stdout, fmt, va);
    va_end(va);
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

int InjectDrvMgt(HANDLE hProcess, DWORD pid)
{
	char szSecDrvEmuDLLPath[MAX_PATH];
	GetTempPath(MAX_PATH, szSecDrvEmuDLLPath);
	strcat(szSecDrvEmuDLLPath, "secdrvemu.dll");
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

	return 0;
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

	byte_402009 = byte_402000 + 9;
	sub_401000();

	//char *szPath = "C:\\Program Files (x86)\\EA GAMES\\The Sims 2\\TSBin\\Sims2.exe -w";
	//char *szPath = "C:\\Games\\Football Manager 2005\\fm2005.exe";
	//char *szPath = "C:\\Games\\Call of Duty 4 - Modern Warfare\\iw3sp.exe";
#ifdef _DEBUG
	char *szPath = "C:\\Games\\Football Manager 2005\\fm2005.exe";
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
		char *szPath = szPathBuffer;
	}
#endif

	log("szPath: %s\n", szPath);

	char *szExePath = szPath;
	char *szExePart = strstr(szExePath, ".exe");
	if (szExePart)
	{
		szExePath = strdup(szExePath);
		strstr(szExePath, ".exe")[4] = 0;

		if (szExePath[0] == '\"')
			szExePath++;
		if (szExePath[strlen(szExePath)-1] == '\"')
			szExePath[strlen(szExePath)-1] = 0;
	}

	SetCurrentDirectoryFromPath(szPath);

	// "C:\\games\\Football Manager 2005"
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

	
	DWORD *esi = dword_4029AC;
	DWORD *ebx = esi;
	ebx += nNumberOfBytesToRead;
	ebx -= 4;
	if (*(WORD*)esi != 23117)
	{
		exitlog("This is not a valid SafeDisc file\n");
	}
	esi = (DWORD*)(((BYTE*)esi) + esi[15]);//*(DWORD*)(((BYTE *)esi)+0x3c);
	if (esi > ebx)
	{
		exitlog("This is not a valid SafeDisc file\n");
	}
	if (*esi != 17744)
	{
		exitlog("This is not a valid SafeDisc file\n");
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
		exitlog("This is not a valid SafeDisc file\n");
	}

	ReadProcessMemory(hProcess, (char *)lpAddress + 187, &dword_402253, 4, 0);
	if ( *((BYTE*)&dword_402253) != 0xE9 )
	{
		if ( *(((BYTE*)&dword_402253)+2) != 0xE9 )
		{
			exitlog("This is not a valid SafeDisc file\n");
			
		}
		dword_4021BC = 189;
	}

	sub_401026((BYTE)dword_4021BC, 0, 0, 1, 1);		/// This sets the modes for SDLoader.dll - all 1s is debug stop at OEP. Normal is 0,0,1,1


	*(DWORD*)(byte_402000 + 0x97) = (DWORD)LoadLibraryA;

	void *lpBaseAddress = lpAddress;
	DWORD flOldProtect;
	BYTE unk_40209B[0x9b] = { 0 };		// 0x9b = 155

	InjectDrvMgt(pi.hProcess, pi.dwProcessId);

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