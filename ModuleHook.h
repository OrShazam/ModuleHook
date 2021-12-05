
#include "common.h"
#include "util.h"
typedef struct {
	DWORD ProcessId;
	LPVOID ProcAddress;
	PBYTE restore;
	LPVOID remoteBuffer;
} HookData, *PHookData;

BOOL InitHookData(PHookData,const char* moduleName,const char* procName, DWORD ProcessId);

BOOL SetHook(PHookData data, PBYTE shellcode, SIZE_T shellcodeSize);

BOOL ResetHook(PHookData data);