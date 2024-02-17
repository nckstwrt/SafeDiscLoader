#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <stdio.h>
#include "minhook/include/MinHook.h"
#include "winternl.h"
#define NTSTATUS int
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth
#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)

#ifdef _DEBUG
#define LOGGING
#endif

HMODULE hOurModule;
FILE* log_file = NULL;

void logprintf(const char* fmt, ...)
{
#ifdef LOGGING
	va_list va;
	if (log_file)
	{
		va_start(va, fmt);
		vfprintf(log_file, fmt, va);
		va_end(va);
		fflush(log_file);
	}
	if (stdout)
	{
		va_start(va, fmt);
		vfprintf(stdout, fmt, va);
		va_end(va);
	}
#endif
}


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
        logprintf("IOCTL 0xCA002813 unhandled (please report!)");
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
	char szFileName[MAX_PATH];
	GetModuleFileName(NULL, szFileName, MAX_PATH);
	logprintf("%s: CreateFileA: %s\n", szFileName, lpFileName);

    if (!lstrcmpiA(lpFileName, "\\\\.\\Secdrv") || !lstrcmpiA(lpFileName, "\\\\.\\Global\\SecDrv"))
    {
        // we need to return a handle when secdrv is opened, so we just open the null device to get an unused handle
        HANDLE dummyHandle = CreateFileA_Orig("NUL", GENERIC_READ, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (dummyHandle == INVALID_HANDLE_VALUE)
            logprintf("unable to obtain a dummy handle for secdrv");
        return dummyHandle;
    }
    return CreateFileA_Orig(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

int InjectSelf(DWORD pid)
{
	char szSecDrvEmuDLLPath[MAX_PATH];
	
	GetModuleFileName(hOurModule, szSecDrvEmuDLLPath, MAX_PATH);

	logprintf("Injecting DLL %s\n", szSecDrvEmuDLLPath);

    // Open Process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) // Not INVALID_HANDLE_VALUE...Strangely
    {
        logprintf("Process found, but cannot open handle\n");
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
        logprintf("Could not allocate memory inside the target process\n");
        return -1;
    }

    // Write the fullpath filename into the target process
    BOOL bWritten = WriteProcessMemory(hProcess, newMemory, szPath, strlen(szPath)+1, NULL);
    if (bWritten == 0)
    {
        logprintf("There were no bytes written to the process's address space.\n");
        return -1;
    }

    // Create Remote Thread to run LoadLibrary with our fullpath
    HANDLE hNewThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, newMemory, NULL, NULL);
    if (hNewThread == NULL)
    {
        logprintf("Could not create remote thread in target process\n");
    }
    
    // Wait for it to run
    WaitForSingleObject(hNewThread, INFINITE);

    // Clean up
    CloseHandle(hNewThread);
    CloseHandle(hProcess);

	logprintf("Injecting into pid %d\n", pid);

	return 0;
}

BOOL WINAPI CreateProcessA_Hook(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,  LPPROCESS_INFORMATION lpProcessInformation) 
{
    logprintf("CreateProcessA Hook\n");
//	::MessageBox(0, "CreateProcessA Hooking!", "Hello", 0);

    // if the process isn't created suspended, set the flag so we can inject hooks
    const DWORD isCreateSuspended = dwCreationFlags & CREATE_SUSPENDED;
    if (!isCreateSuspended) dwCreationFlags |= CREATE_SUSPENDED;

    if (!CreateProcessA_Orig(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)) 
        return FALSE;

    logprintf("Hooking and calling Process at CreateProcessA_Hook\n");

	InjectSelf(lpProcessInformation->dwProcessId);

	if (!isCreateSuspended)
		ResumeThread(lpProcessInformation->hThread);

    return TRUE;
}

BOOL WINAPI CreateProcessW_Hook(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) 
{
	logprintf("CreateProcessW Hook\n");

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
	logprintf("TRIED TO ALLOC A CONSOLE\n");
	//MessageBox(0, "Hello", "Hello", 0);
#endif

	logprintf("Hooks Starting\n");

	hOurModule = hModule;

    MH_STATUS status = MH_Initialize();

    DisableThreadLibraryCalls(hModule);
    if (status != MH_OK)
    {
        logprintf("Minhook init failed!\n");
        return 0;
    }

    if (MH_CreateHookApi(L"ntdll", "NtDeviceIoControlFile", &NtDeviceIoControlFile_Hook, reinterpret_cast<LPVOID*>(&NtDeviceIoControlFile_Orig)) != MH_OK) 
    {
        logprintf("Unable to hook NtDeviceIoControlFile\n");
        return 0;
    }


	/*
	HMODULE hKernel = LoadLibrary("KERNEL32.DLL");
	void *ptrCreateFileA = NULL;
	if (hKernel != NULL)
	{
		ptrCreateFileA = GetProcAddress(hKernel, "CreateFileA");
		logprintf("ptrCreateFileA: %X\n", (DWORD)ptrCreateFileA);
	}
	else
		logprintf("Failed to LoadLibrary!\n");
	// FreeLibrary

	if (MH_CreateHook(ptrCreateFileA, &CreateFileA_Hook, (LPVOID*)(&CreateFileA_Orig)) != MH_OK) */
    if (MH_CreateHookApi(L"kernel32", "CreateFileA", &CreateFileA_Hook, reinterpret_cast<LPVOID*>(&CreateFileA_Orig)) != MH_OK) 
    {
        logprintf("Unable to hook CreateFileA\n");
        return false;
    }

	logprintf("CreateFileA_Orig = %X\n", (DWORD)*(LPVOID*)(&CreateFileA_Orig));
	
	if (MH_CreateHookApi(L"kernel32", "CreateProcessA", &CreateProcessA_Hook, reinterpret_cast<LPVOID*>(&CreateProcessA_Orig)) != MH_OK) 
    {
        logprintf("Unable to hook CreateProcessA\n");
        return false;
    }

	if (MH_CreateHookApi(L"kernel32", "CreateProcessW", &CreateProcessW_Hook, reinterpret_cast<LPVOID*>(&CreateProcessW_Orig)) != MH_OK) 
    {
        logprintf("Unable to hook CreateProcessW\n");
        return false;
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
        logprintf("Enable Hooks Failed!\n");
        return 0;
    }

	logprintf("Hooks Complete!\n");

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)  
    {
    case DLL_PROCESS_ATTACH:
        //CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)HookThread, hModule, 0, NULL);
		HookThread(hModule);
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

