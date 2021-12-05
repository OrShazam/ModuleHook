

#include "ModuleHook.h"


BOOL InitHookData(PHookData data,const char* moduleName, const char* procName,DWORD ProcessId){
	data->ProcessId = ProcessId;
	data->ProcAddress = RemoteProcAddress(ProcessId,moduleName,procName);
	if (data->ProcAddress == NULL)
		return FALSE;
	return TRUE;
}
BOOL SetHook(PHookData data, PBYTE shellcode, SIZE_T shellcodeSize){
	HANDLE hProcess = OpenProcess(
		PROCESS_ALL_ACCESS, // Stealth level: -infinity
		FALSE,
		data->ProcessId);
	if (hProcess == NULL)
		return FALSE;
	BOOL result;
	SIZE_T read;
	SIZE_T written;
	PBYTE restore = HeapAlloc(
		GetProcessHeap(),
		0,
		5);
	result = ReadProcessMemory(
		hProcess,
		data->ProcAddress,
		restore,
		5,
		&read);
	if (!result || read != 5){
		return FALSE;
	}
	data->restore = restore; // for resetting the hook
	LPVOID remoteBuffer = VirtualAllocEx(
		hProcess,
		NULL,
		shellcodeSize,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);
		
	if (remoteBuffer == NULL)
		return FALSE;
	
	data->remoteBuffer = remoteBuffer; // for resetting the hook
	
	result = WriteProcessMemory(
		hProcess,
		remoteBuffer,
		shellcode,
		shellcodeSize,
		&written);
		
	if (!result || written != shellcodeSize){
		VirtualFreeEx(
			hProcess,
			remoteBuffer,
			0,
			MEM_RELEASE);	
		return FALSE;
	}
	VirtualProtectEx(
		hProcess,
		remoteBuffer,
		shellcodeSize,
		PAGE_EXECUTE,
		&oldProtect);
	// Do I need little endian magic? 
	BYTE hook[5] = { 0XE8, remoteBuffer & 0xff, (remoteBuffer >> 8) & 0xff,
	(remoteBuffer >> 16) & 0xff, remoteBuffer >> 24 };
	// make it compatible with longer hook by using the hook size instead of just 5
	
	result = WriteProcessMemory(
		hProcess,
		data->ProcAddress,
		hook,
		5,
		&written);
	if (!result || written != 5){
		VirtualFreeEx(
			hProcess,
			remoteBuffer,
			0,
			MEM_RELEASE);	
		return FALSE;
	}
	return TRUE;
}
BOOL ResetHook(PHookData data){
	HANDLE hProcess = OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE,
		data->ProcessId);
	if (hProcess == NULL)
		return FALSE;
	
	VirtualFreeEx(
		hProcess,
		data->remoteBuffer,
		0,
		MEM_RELEASE);

	BOOL result;
	SIZE_T written;
	result = WriteProcessMemory(
		hProcess,
		ProcAddress,
		data->restore,
		5,
		&written);
	if (!result || !written){
		return FALSE;
	}
	return TRUE;
	
	
}
