#ifndef _UTILS_H_
#define _UTILS_H_

#include <windows.h>
#include <stdio.h>

FILE* log_file = NULL;

void log(const char* fmt, ...)
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

void LogKey(const char *keyName, DWORD addr)
{
	if (addr != 0)
	{
		log("%s (%08X): ", keyName, addr);
		for (int i = 0; i < 16; i++)
		{
			log("%02X ", (DWORD)*(((BYTE*)addr)+i));
		}
		log("\n");
	}
}

BYTE hexdigit(char hex)
{
    return (hex <= '9') ? hex - '0' : toupper(hex) - 'A' + 10;
}

BYTE hexbyte(const char* hex)
{
	if (*hex == '?')		// ?? is a wildcard and will be 00 - which means 00 matches with anything
		return 0;
	else
		return (hexdigit(*hex) << 4) | hexdigit(*(hex+1));
}

DWORD FindHex(DWORD StartAddr, DWORD EndAddr, BYTE *searchHex, DWORD searchSize)
{
	DWORD ret = -1L;
	DWORD i;
	BYTE *ptr = (BYTE *)StartAddr;
	DWORD Length = (EndAddr - StartAddr) - searchSize;
	BYTE *cmpptr = searchHex;
	DWORD matched = 0;
	DWORD mostmatched = 0;
	for (i = 0; i < Length; i++)
	{
		if ((*ptr == *cmpptr) || (*cmpptr == 0))
		{
			cmpptr++;
			matched++;
			if (matched == searchSize)
			{
				ret = ((DWORD)ptr) - (searchSize - 1);
				break;
			}
			if (mostmatched < matched)
				mostmatched = matched;
		}
		else
		{
			ptr -= matched;
			i -= matched;
			matched = 0;
			cmpptr = searchHex;
		}
		ptr++;
	}

	if (searchHex[0] == 0xa5)
		log("Most Matched: %d\n", mostmatched);
	return ret;
}

DWORD FindHexString(DWORD StartAddr, DWORD EndAddr, const char *szHexString, const char *szPurpose = NULL)
{
	DWORD ret = -1L;
	DWORD i;
	BYTE searchSize = strlen(szHexString)/2;
	BYTE *searchHex = new BYTE[searchSize];

	for (i = 0; i < searchSize; i++)
	{
		searchHex[i] = hexbyte(&szHexString[i*2]);
	}

	ret = FindHex(StartAddr, EndAddr, searchHex, searchSize);

	delete [] searchHex;

	if (szPurpose == NULL)
		log("FindHexString(%08X, %08X, \"%s\") == %08X\n", StartAddr, EndAddr, szHexString, ret);
	else
		log("FindHexString(%08X, %08X, \"%s\", \"%s\") == %08X\n", StartAddr, EndAddr, szHexString, szPurpose, ret);

	return ret;
}

BOOL GetSafeDiscVersionFromBuffer(BYTE *buffer, DWORD dwBufferSize, DWORD *pdwVersion, DWORD *pdwSubVersion, DWORD *pdwRevision)
{
	BOOL bRet = FALSE;
	if (buffer && dwBufferSize > 0)
	{
		DWORD AddrToVersion = FindHexString((DWORD)buffer, ((DWORD)buffer)+dwBufferSize, "426F475F202A39302E30262121202059793E0000000000000000000000000000");
		if (AddrToVersion != -1)
		{
			*pdwVersion = *(DWORD*)(AddrToVersion + 0x20);
			*pdwSubVersion = *(DWORD*)(AddrToVersion + 0x20 + 4);
			*pdwRevision = *(DWORD*)(AddrToVersion + 0x20 + 8);

			log("SafeDisc Version: %d.%02d.%02d\n", *pdwVersion, *pdwSubVersion, *pdwRevision);
			bRet = TRUE;
		}
	}
	return bRet;
}

BOOL GetSafeDiscVersion(const char *szExeFile, DWORD *pdwVersion, DWORD *pdwSubVersion, DWORD *pdwRevision)
{
	BOOL bRet = FALSE;
	HANDLE hFile = CreateFile(szExeFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, 0);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		DWORD dwFileSize = GetFileSize(hFile, NULL);
		DWORD dwBytesRead;
		BYTE *buffer = new BYTE[dwFileSize];
		ReadFile(hFile, buffer, dwFileSize, &dwBytesRead, NULL);
		bRet = GetSafeDiscVersionFromBuffer(buffer, dwBytesRead, pdwVersion, pdwSubVersion, pdwRevision);
		delete [] buffer;
	}
	CloseHandle(hFile);
	return bRet;
}

PIMAGE_SECTION_HEADER GetSectionByName(DWORD addr, const char *szName)
{
	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)addr;
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((BYTE*)pidh + pidh->e_lfanew);

	PIMAGE_FILE_HEADER pifh = (PIMAGE_FILE_HEADER)&pinh->FileHeader;
	PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(pinh);

	for (WORD i = 0; i < pifh->NumberOfSections; i++)
	{
		if (stricmp((char*)pish->Name, szName) == 0)
			return pish;
		pish++;
	}

	return NULL;
}

BOOL WriteProtectedDWORD(DWORD Addr, DWORD Value)
{
	BOOL bRet = FALSE;
	DWORD old;
	if (VirtualProtectEx(GetCurrentProcess(), (void*)Addr, 4, PAGE_READWRITE, &old))
	{
		*((DWORD*)Addr) = Value;
		if (VirtualProtectEx(GetCurrentProcess(), (void*)Addr, 4, old, &old))
			bRet = TRUE;
	}

	if (bRet)
		log("WriteProtectedDWORD(%08X, %08X)\n", Addr, Value);
	else
		log("Failed to WriteProtectedDWORD(%08X, %08X) !!!!\n", Addr, Value);
	return bRet;
}

// Only useful as SafeDisc sometimes loops through to find the DLLs real address (rather than the hooked Shim address)
DWORD FindRealAddress(const char *szDLLName, const char *szProcName)
{
	DWORD ret = -1L;
	HMODULE lib = LoadLibraryEx(szDLLName, NULL, DONT_RESOLVE_DLL_REFERENCES);
	PIMAGE_NT_HEADERS header = (PIMAGE_NT_HEADERS)((BYTE *)lib + ((PIMAGE_DOS_HEADER)lib)->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)lib + header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD* names = (DWORD*)((int)lib + exports->AddressOfNames);
	WORD* ords = (WORD*)((int)lib + exports->AddressOfNameOrdinals);
	DWORD* funcs = (DWORD*)((int)lib + exports->AddressOfFunctions);
	for (DWORD i = 0; i < exports->NumberOfNames; i++)
	{
		if (stricmp(szProcName, (char *)lib + (DWORD)names[i]) == 0)
		{
			// TODO: Worry about Ordinalbase ???
			ret = ((DWORD)lib) + (DWORD)funcs[ords[i]];
			break;
		}
	}
	return ret;
}

void EnableDebugPriv()
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;
 
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
 
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
 
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
 
    AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);
 
    CloseHandle(hToken);
}

#endif