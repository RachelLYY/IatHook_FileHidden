// RemoteThread.cpp : �������̨Ӧ�ó������ڵ㡣
//x64 x64ע��ɹ� x32ע��ʧ��

#include "stdafx.h"
#include <iostream>
#include <afx.h>  
#include"tlhelp32.h"  
#include "Psapi.h"  
#include  <direct.h>  
using namespace std;
BOOL EnableDebugPrivilege();
BOOL  InjectDllByRemoteThread(ULONG32 ulTargetProcessID, WCHAR* wzDllFullPath);
ULONG32  ulProcessID = 0;
//���ݽ��������PID

void PrintProcessNameAndID(DWORD processID)
{
	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
	// Get a handle to the process.
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);

	// Get the process name.

	if (NULL != hProcess)
	{
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
			&cbNeeded))
		{
			GetModuleBaseName(hProcess, hMod, szProcessName,
				sizeof(szProcessName) / sizeof(TCHAR));
		}
	}

	// Print the process name and identifier.
	//TCHAR��const char*����ֱ�ӱȽ� ��Ҫת�� Ȼ��ʹ��wcscmp�Ƚ�
	//char *CStr = "cmd.exe";
	char *CStr = "cmd.exe";
	size_t len = strlen(CStr) + 1;
	size_t converted = 0;
	wchar_t *WStr;
	WStr = (wchar_t*)malloc(len * sizeof(wchar_t));
	mbstowcs_s(&converted, WStr, len, CStr, _TRUNCATE);
	//_tprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processID);
	if (0 == wcscmp(szProcessName, WStr))
	{
		_tprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processID);
		ulProcessID = processID;
		//return processID;
	}
	
	// Release the handle to the process.
	CloseHandle(hProcess);
	//return NULL;
}

int _tmain(int argc, _TCHAR* argv[])
{
	//���Ȼ�ȡȨ��
	if (EnableDebugPrivilege() == FALSE)
	{
		return 0;
	}
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return 1;
	}
	// Calculate how many process identifiers were returned.
	cProcesses = cbNeeded / sizeof(DWORD);

	// Print the name and process identifier for each process.
	//ULONG32  ulProcessID = 0;
	for (i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] != 0)
		{
			//PrintProcessNameAndID(aProcesses[i]);

			PrintProcessNameAndID(aProcesses[i]);
		}
	}
	
	/*printf("Input ProcessID\r\n");
	cin >> ulProcessID;*/
	//�ֶ����PID
	
	//cout << "cmd's pid:" << ulProcessID << endl;
	_tprintf(TEXT("The cmd's pid is %u\n"), ulProcessID);
	WCHAR  wzDllFullPath[MAX_PATH] = { 0 };
	TCHAR szFilePath[MAX_PATH + 1] = { 0 };
	GetModuleFileName(NULL, szFilePath, MAX_PATH);
	char   buffer[MAX_PATH];
	getcwd(buffer, MAX_PATH);
	string tmp = buffer;
	string dllname = "hook.dll";
	tmp = tmp + "\\" + dllname;
	// ת��wchar_t
	char *CStr = const_cast<char*>(tmp.c_str());
	size_t len = strlen(CStr) + 1;
	size_t converted = 0;
	wchar_t *WStr;
	WStr = (wchar_t*)malloc(len * sizeof(wchar_t));
	mbstowcs_s(&converted, WStr, len, CStr, _TRUNCATE);

#ifdef  _WIN64		
	//wcsncat_s(wzDllFullPath, L"D:\\test1\\t1.dll", 20);
	wcsncat_s(wzDllFullPath, WStr, 500);
#else												
	wcsncat_s(wzDllFullPath, WStr, 20);
#endif
	//ע��dll
	InjectDllByRemoteThread(ulProcessID, wzDllFullPath);
	system("Pause");
	return 0;
}
BOOL  InjectDllByRemoteThread(ULONG32 ulTargetProcessID, WCHAR* wzDllFullPath)
{

	HANDLE  TargetProcessHandle = NULL;
	TargetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ulTargetProcessID);
	if (NULL == TargetProcessHandle)
	{
		printf("failed to open process!!\n");
		return FALSE;
	}
	WCHAR* VirtualAddress = NULL;
	ULONG32 ulDllLength = (ULONG32)_tcslen(wzDllFullPath) + 1;
	//ALLOC Address for Dllpath ��������ռ�
	VirtualAddress = (WCHAR*)VirtualAllocEx(TargetProcessHandle, NULL, ulDllLength * sizeof(WCHAR), MEM_COMMIT, PAGE_READWRITE);
	if (NULL == VirtualAddress)
	{
		printf("failed to Alloc!!\n");
		CloseHandle(TargetProcessHandle);
		return FALSE;
	}
	// write д���ڴ�����
	// TargetProcessHandle ��һ���޸��ڴ�Ľ��̾�� VirtualAddress��д����ڴ��ַ��ָ�룩 wzDllFullPath ��һ������д�����ݵ�����
	// sizeof(WCHAR):д�����ݵĴ�С
	if (FALSE == WriteProcessMemory(TargetProcessHandle, VirtualAddress, (LPVOID)wzDllFullPath, ulDllLength * sizeof(WCHAR), NULL))
	{
		printf("failed to write!!\n");
		VirtualFreeEx(TargetProcessHandle, VirtualAddress, ulDllLength, MEM_DECOMMIT);
		CloseHandle(TargetProcessHandle);
		return FALSE;
	}

	LPTHREAD_START_ROUTINE FunctionAddress = NULL;
	//��ָ���Ķ�̬���ӿ⣨DLL���м��������ĺ���������ĵ�ַ
	FunctionAddress = (PTHREAD_START_ROUTINE)::GetProcAddress(::GetModuleHandle(_T("Kernel32")), "LoadLibraryW");
	HANDLE ThreadHandle = INVALID_HANDLE_VALUE;
	//start
	//CreateRemoteThread��Creates a thread that runs in the virtual address space of another process.
	ThreadHandle = CreateRemoteThread(TargetProcessHandle, NULL, 0, FunctionAddress, VirtualAddress, 0, NULL);
	if (NULL == ThreadHandle)
	{
		cout << "The error code:" << GetLastError() << endl;
		//ʧ��
		VirtualFreeEx(TargetProcessHandle, VirtualAddress, ulDllLength, MEM_DECOMMIT);
		CloseHandle(TargetProcessHandle);
		return FALSE;
	}
	// WaitForSingleObject ->signaled ע��ɹ����滻��
	WaitForSingleObject(ThreadHandle, INFINITE);
	VirtualFreeEx(TargetProcessHandle, VirtualAddress, ulDllLength, MEM_DECOMMIT);			// ����
	CloseHandle(ThreadHandle);
	CloseHandle(TargetProcessHandle);
}
//����Ȩ��
BOOL EnableDebugPrivilege()
{
	HANDLE TokenHandle = NULL;
	TOKEN_PRIVILEGES TokenPrivilege;
	LUID uID;
	//��Ȩ������
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
	{
		return FALSE;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &uID))
	{
		CloseHandle(TokenHandle);
		TokenHandle = INVALID_HANDLE_VALUE;
		return FALSE;
	}
	TokenPrivilege.PrivilegeCount = 1;
	TokenPrivilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	TokenPrivilege.Privileges[0].Luid = uID;
	if (!AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivilege, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
		//����Ȩ��
	{
		CloseHandle(TokenHandle);
		TokenHandle = INVALID_HANDLE_VALUE;
		return  FALSE;
	}
	CloseHandle(TokenHandle);
	TokenHandle = INVALID_HANDLE_VALUE;
	return TRUE;
}