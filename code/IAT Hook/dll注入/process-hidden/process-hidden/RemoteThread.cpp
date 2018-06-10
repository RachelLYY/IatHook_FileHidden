// RemoteThread.cpp : 定义控制台应用程序的入口点。
//x64 x64注入成功 x32注入失败

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
//根据进程名获得PID

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
	//TCHAR和const char*不能直接比较 需要转换 然后使用wcscmp比较
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
	//首先获取权限
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
	//手动获得PID
	
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
	// 转成wchar_t
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
	//注入dll
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
	//ALLOC Address for Dllpath 分配虚拟空间
	VirtualAddress = (WCHAR*)VirtualAllocEx(TargetProcessHandle, NULL, ulDllLength * sizeof(WCHAR), MEM_COMMIT, PAGE_READWRITE);
	if (NULL == VirtualAddress)
	{
		printf("failed to Alloc!!\n");
		CloseHandle(TargetProcessHandle);
		return FALSE;
	}
	// write 写入内存区域
	// TargetProcessHandle 是一个修改内存的进程句柄 VirtualAddress是写入的内存地址（指针） wzDllFullPath 是一个放有写入数据的数组
	// sizeof(WCHAR):写入数据的大小
	if (FALSE == WriteProcessMemory(TargetProcessHandle, VirtualAddress, (LPVOID)wzDllFullPath, ulDllLength * sizeof(WCHAR), NULL))
	{
		printf("failed to write!!\n");
		VirtualFreeEx(TargetProcessHandle, VirtualAddress, ulDllLength, MEM_DECOMMIT);
		CloseHandle(TargetProcessHandle);
		return FALSE;
	}

	LPTHREAD_START_ROUTINE FunctionAddress = NULL;
	//从指定的动态链接库（DLL）中检索导出的函数或变量的地址
	FunctionAddress = (PTHREAD_START_ROUTINE)::GetProcAddress(::GetModuleHandle(_T("Kernel32")), "LoadLibraryW");
	HANDLE ThreadHandle = INVALID_HANDLE_VALUE;
	//start
	//CreateRemoteThread：Creates a thread that runs in the virtual address space of another process.
	ThreadHandle = CreateRemoteThread(TargetProcessHandle, NULL, 0, FunctionAddress, VirtualAddress, 0, NULL);
	if (NULL == ThreadHandle)
	{
		cout << "The error code:" << GetLastError() << endl;
		//失败
		VirtualFreeEx(TargetProcessHandle, VirtualAddress, ulDllLength, MEM_DECOMMIT);
		CloseHandle(TargetProcessHandle);
		return FALSE;
	}
	// WaitForSingleObject ->signaled 注入成功（替换）
	WaitForSingleObject(ThreadHandle, INFINITE);
	VirtualFreeEx(TargetProcessHandle, VirtualAddress, ulDllLength, MEM_DECOMMIT);			// 清理
	CloseHandle(ThreadHandle);
	CloseHandle(TargetProcessHandle);
}
//申请权限
BOOL EnableDebugPrivilege()
{
	HANDLE TokenHandle = NULL;
	TOKEN_PRIVILEGES TokenPrivilege;
	LUID uID;
	//打开权限令牌
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
		//调整权限
	{
		CloseHandle(TokenHandle);
		TokenHandle = INVALID_HANDLE_VALUE;
		return  FALSE;
	}
	CloseHandle(TokenHandle);
	TokenHandle = INVALID_HANDLE_VALUE;
	return TRUE;
}