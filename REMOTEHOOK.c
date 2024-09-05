//
// Created by ltzx2 on 2024/9/4.
//
#include<Windows.h>
#include<stdio.h>
#include <tlhelp32.h>
#define log printf
#define wlog wprintf

DWORD GetProcessIdByName(const wchar_t* pName)
{
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (h == INVALID_HANDLE_VALUE)
		return 0;
	PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
	for (BOOL ret = Process32First(h, &pe); ret; ret = Process32Next(h, &pe))
	{
		if (wcscmp(pe.szExeFile, pName) == 0)
		{
			CloseHandle(h);
			return pe.th32ProcessID;
		}
	}
	CloseHandle(h);
	return 0;
}




int main() {
	MessageBoxA(NULL, "starthook", "starthook", MB_OK);
	//_asm {
	//	pushad;
	//	push 0x0;
	//	push 0x6b6f6f68;
	//	mov ebx, esp;
	//	push 0;
	//	push ebx;
	//	push ebx;
	//	push 0x0;
	//	mov eax, 0x76cb0c30;
	//	call eax;
	//	add esp, 0x8;
	//	popad;
	//}
	//char shellcode[100] = {};
	/*	005E179C  0x60,0x6A,0x00,0x68,0x68,0x6F,0x6F,0x6B,0x8B,0xDC,0x6A,0x00,0x53,0x53,0x6A,0x00,0xB8,0x30,0x0C,0xCB,0x76,0xFF,0xD0,0x83,0xC4,0x08,0x61*/
	/*            c2 04 00*/

	//char shellcode[100] = { 0x60,0x6A,0x00,0x68,0x68,0x6F,0x6F,0x6B,0x8B,0xDC,0x6A,0x00,0x53,0x53,0x6A,0x00,0xB8,0x30,0x0C,0xCB,0x76,0xFF,0xD0,0x83,0xC4,0x08,0x61,0xc2,0x04,0x00 };
	char shellcode[100] = { 0x60,0x6A,0x00,0x68,0x68,0x6F,0x6F,0x6B,0x8B,0xDC,0x6A,0x00,0x53,0x53,0x6A,0x00,0xB8,0x30,0x0C,0x06,0x76,0xFF,0xD0,0x83,0xC4,0x08,0x61,0xc3 };
	int p[1] = { (int)shellcode };
	DWORD oldProtect;
	VirtualProtect(shellcode, 100, PAGE_EXECUTE_READWRITE, &oldProtect);
	_asm {
		call p;
	}
	//DWORD pid;
	//if (fscanf_s(stdin, "%d", &pid) != 1) {
	//	log("fscanf fail\n");
	//	return 0;
	//};
	//log("pid=%d\n", pid);
	printf("input proc name:");
	fflush(stdout);
	wchar_t procName[100];
	if (fwscanf_s(stdin, L"%s",procName,_countof(procName)) != 1) {
		log("fwscanf fail\n");
		return 0;
	}
	wlog(L"procName=%s\n", procName);
	DWORD pid = GetProcessIdByName(procName);
	if (pid == 0) {
		log("get process id failed\n");
		return 0;
	}
	log("pid=%d\n", pid);


	HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hproc == NULL) {
		log("open process failed\n");
		return 0;
	}
	LPVOID addr = VirtualAllocEx(hproc, NULL, 100, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (addr == NULL)
	{
		log("VirtualAllocEx failed\n");
		return 0;
	}
	if (WriteProcessMemory(hproc, addr, shellcode, 100, NULL) == FALSE) {
		log("write process memory failed\n");
		return 0;
	};
	HANDLE ht = CreateRemoteThread(hproc, NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);
	if (ht == NULL)
	{
		log("create remote thread failed\n");
		return 0;
	}
	WaitForSingleObject(ht, -1);
	CloseHandle(ht);
	CloseHandle(hproc);

	return 0;
}