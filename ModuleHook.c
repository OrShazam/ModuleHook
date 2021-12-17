

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
	DWORD oldProtect;
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
	
	if (remoteBuffer == NULL){
		CloseHandle(hProcess);
		return FALSE;
	}
	
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
		CloseHandle(hProcess);
		return FALSE;
	}
	VirtualProtectEx(
		hProcess,
		remoteBuffer,
		shellcodeSize,
		PAGE_EXECUTE,
		&oldProtect);

	BYTE hook[5] = { 0XE8, (DWORD)remoteBuffer & 0xff, ((DWORD)remoteBuffer >> 8) & 0xff,
	((DWORD)remoteBuffer >> 16) & 0xff, (DWORD)remoteBuffer >> 24 };
	// make sure start of function is writable
	VirtualProtectEx(
		hProcess,
		data->ProcAddress,
		5,
		PAGE_EXECUTE_READWRITE,
		&oldProtect);
		
	
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
		CloseHandle(hProcess);
		return FALSE;
	}
	CloseHandle(hProcess);
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
		data->ProcAddress,
		data->restore,
		5,
		&written);
	if (!result || !written){
		CloseHandle(hProcess);
		return FALSE;
	}
	CloseHandle(hProcess);
	return TRUE;
	
	
}
