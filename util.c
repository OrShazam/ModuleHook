


#define MAX_PATH 260
#include "util.h"
#include <tlhelp32.h>

BOOL strcmpend(const char* str1, const char* str2){
	if (str1 == NULL || str2 == NULL)
		return FALSE;
	char* end_str1 = str1;
	while (*end_str1 != '\0'){
		end_str1++;
	}
	if (end_str1 == str1) return FALSE;
	
	char* end_str2 = str2;
	while (*end_str2 != '\0'){
		end_str2++;
	}
	if (end_str2 == str2) return FALSE;
	
	while ((end_str1 != str1) && (end_str2 != str2)){
		if (tolower(*end_str1) != tolower(*end_str2))
			return FALSE;
		end_str2--;
		end_str1--;
	}
	return TRUE;
}
LPVOID RemoteProcAddress(DWORD ProcessId, const char* moduleName, const char* procName){
	HANDLE hSnapshot = CreateToolHelp32Snapshot(
		TH32CS_SNAPMODULE, 
		ProcessId);

	if (hSnapshot == INVALID_HANDLE_VALUE)
		return NULL;
	
	MOUDLEENTRY32 me;
	me.dwSize = sizeof(MODULEENTRY32);
	Module32First(hSnapshot, &me);
	
	while (GetLastError() != ERROR_NO_MORE_FILES){
		if (strcmpend(moduleName,me.szModule)){
			break;
		}
		Module32Next(hSnapshot, &me);
	}
	if (GetLastError() == ERROR_NO_MORE_FILES)
		return NULL;
	HMODULE hModule = LoadLibrary(me.szModule);
	if (hModule == NULL)
		return NULL;
	
	LPVOID procPtr = (LPVOID)GetProcAddress(hModule,procName);
	if (procPtr == NULL)
		return NULL;
	// loading the library was only needed for figuring out the proc address easily
	FreeLibrary(hModule);
	// a module handle is it's base address
	//count for the differences in the bases
	procPtr = procPtr - (me.hModule - hModule);
	return procPtr;
}



