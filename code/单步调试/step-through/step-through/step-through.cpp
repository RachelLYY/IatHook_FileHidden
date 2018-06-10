#include <windows.h>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include<iostream>
void EnterDebugLoop(const LPDEBUG_EVENT, PROCESS_INFORMATION);
void _tmain(int, TCHAR *argv[]);

DWORD OnCreateThreadDebugEvent(const LPDEBUG_EVENT) 
{ 
	//printf("OnCreateThreadDebugEvent\n"); 
	return 0; 
}
DWORD OnCreateProcessDebugEvent(const LPDEBUG_EVENT) 
{ 
	//printf("OnCreateProcessDebugEvent\n"); 
	return 0; 
}
DWORD OnExitThreadDebugEvent(const LPDEBUG_EVENT) 
{ 
	//printf("OnExitThreadDebugEvent\n"); 
	return 0; 
}
DWORD OnExitProcessDebugEvent(const LPDEBUG_EVENT) 
{ 
	//printf("OnExitProcessDebugEvent\n"); 
	return 0; 
}
DWORD OnLoadDllDebugEvent(const LPDEBUG_EVENT dv)
{
	// printf("OnLoadDllDebugEvent %x\n", dv->u.LoadDll.hFile);
	return 0;
}
DWORD OnUnloadDllDebugEvent(const LPDEBUG_EVENT) 
{ 
	// printf("OnUnloadDllDebugEvent\n"); 
	return 0; 
}
DWORD OnOutputDebugStringEvent(const LPDEBUG_EVENT) 
{ 
	//printf("OnOutputDebugStringEvent\n"); 
	return 0; 
}
DWORD OnRipEvent(const LPDEBUG_EVENT) 
{
	//printf("OnRipEvent\n"); 
	return 0; 
}
void _tmain(int argc, TCHAR *argv[])
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	DEBUG_EVENT DebugEv;
	ZeroMemory(&si, sizeof(si));
	//大小
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (argc != 2)
	{
		printf("Usage: %s [cmdline]\n", argv[0]);
		return;
	}
	// Start the child process. 
	if (!CreateProcess(NULL,   // No module name (use command line)
							   //程序名
		argv[1],        // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
						//debug调试程序
		DEBUG_PROCESS,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi)           // Pointer to PROCESS_INFORMATION structure
		)
	{
		printf("CreateProcess failed (%d).\n", GetLastError());
		return;
	}

	// Wait until child process exits.	等待子进程结束。关闭handle。
	//WaitForSingleObject(pi.hProcess, INFINITE);
	EnterDebugLoop(&DebugEv,pi);
	// Close process and thread handles. 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

void EnterDebugLoop(const LPDEBUG_EVENT DebugEv, PROCESS_INFORMATION pi)
{
	DWORD dwContinueStatus = DBG_CONTINUE; // exception continuation 
	EXCEPTION_RECORD x;
	for (;;)
	{
		// Wait for a debugging event to occur. The second parameter indicates
		// that the function does not return until a debugging event occurs. 

		WaitForDebugEvent(DebugEv, INFINITE);

		CONTEXT Context = { CONTEXT_CONTROL };
		
		if (!GetThreadContext(pi.hThread,&Context))
		{
			printf("the error code:%lu\n", GetLastError());
		}
		Context.EFlags |= 0x100;
		SetThreadContext(pi.hThread, &Context);
		printf("-------------------------The value of regesters-------------------------\n");
		printf("Eax:%lu\n", Context.Eax);
		printf("Ebx:%lu\n", Context.Ebx);
		printf("Ecx:%lu\n", Context.Ecx);
		printf("Edx:%lu\n", Context.Edx);
		printf("Esp:%lu\n", Context.Esp);
		printf("Ebp:%lu\n", Context.Ebp);
		printf("Esi:%lu\n", Context.Esi);
		printf("Edi:%lu\n", Context.Edi);
		printf("Eip:%lu\n", Context.Eip);
		// Process the debugging event code. 

		switch (DebugEv->dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			// Process the exception code. When handling 
			// exceptions, remember to set the continuation 
			// status parameter (dwContinueStatus). This value 
			// is used by the ContinueDebugEvent function. 

			switch (DebugEv->u.Exception.ExceptionRecord.ExceptionCode)
			{
			case EXCEPTION_ACCESS_VIOLATION:
				// First chance: Pass this on to the system. 
				// Last chance: Display an appropriate error. 
				/*definations*/
				//Exceptioncode:
				//ExceptionFlags:The exception flags.value:0 indicating a continuable exception;or EXCEPTION_NONCONTINUABLE, indicating a noncontinuable exception.
				//ExceptionAddress:The address where the exception occurred.
				//NumberParameters:The number of parameters associated with the exception
				//ExceptionInformation is an array,the first number's value indicates the error type.
				//If this value is zero, the thread attempted to read the inaccessible data.
				//If this value is 1, the thread attempted to write to an inaccessible address.

				//printf("ExceptionCode:%lu ExceptionFlags:%lu ExceptionAddress:%p NumberParameters:%lu ExceptionInformation:%lu\n", DebugEv->u.Exception.ExceptionRecord.ExceptionCode, DebugEv->u.Exception.ExceptionRecord.ExceptionFlags, DebugEv->u.Exception.ExceptionRecord.ExceptionAddress, DebugEv->u.Exception.ExceptionRecord.NumberParameters, DebugEv->u.Exception.ExceptionRecord.ExceptionInformation[0]);
				break;

			case EXCEPTION_BREAKPOINT:
				// First chance: Display the current 
				// instruction and register values. 
				// printf("EXCEPTION_BREAKPOINT\n");
				break;

			case EXCEPTION_DATATYPE_MISALIGNMENT:
				// First chance: Pass this on to the system. 
				// Last chance: Display an appropriate error. 
				break;

			case EXCEPTION_SINGLE_STEP:
			{
				break;
			}
				

			case DBG_CONTROL_C:
				// First chance: Pass this on to the system. 
				// Last chance: Display an appropriate error. 
				break;

			default:
				// Handle other exceptions. 
				break;
			}

			break;

		case CREATE_THREAD_DEBUG_EVENT:
			// As needed, examine or change the thread's registers 
			// with the GetThreadContext and SetThreadContext functions; 
			// and suspend and resume thread execution with the 
			// SuspendThread and ResumeThread functions. 

			dwContinueStatus = OnCreateThreadDebugEvent(DebugEv);
			break;

		case CREATE_PROCESS_DEBUG_EVENT:
			// As needed, examine or change the registers of the
			// process's initial thread with the GetThreadContext and
			// SetThreadContext functions; read from and write to the
			// process's virtual memory with the ReadProcessMemory and
			// WriteProcessMemory functions; and suspend and resume
			// thread execution with the SuspendThread and ResumeThread
			// functions. Be sure to close the handle to the process image
			// file with CloseHandle.

			dwContinueStatus = OnCreateProcessDebugEvent(DebugEv);
			break;

		case EXIT_THREAD_DEBUG_EVENT:
			// Display the thread's exit code. 

			dwContinueStatus = OnExitThreadDebugEvent(DebugEv);
			break;

		case EXIT_PROCESS_DEBUG_EVENT:
			// Display the process's exit code. 

			dwContinueStatus = OnExitProcessDebugEvent(DebugEv);
			break;

		case LOAD_DLL_DEBUG_EVENT:
			// Read the debugging information included in the newly 
			// loaded DLL. Be sure to close the handle to the loaded DLL 
			// with CloseHandle.

			dwContinueStatus = OnLoadDllDebugEvent(DebugEv);
			break;

		case UNLOAD_DLL_DEBUG_EVENT:
			// Display a message that the DLL has been unloaded. 

			dwContinueStatus = OnUnloadDllDebugEvent(DebugEv);
			break;

		case OUTPUT_DEBUG_STRING_EVENT:
			// Display the output debugging string. 

			dwContinueStatus = OnOutputDebugStringEvent(DebugEv);
			break;

		case RIP_EVENT:
			dwContinueStatus = OnRipEvent(DebugEv);
			break;
		}

		// Resume executing the thread that reported the debugging event. 
		ContinueDebugEvent(DebugEv->dwProcessId,
			DebugEv->dwThreadId,
			DBG_CONTINUE);
	}
}
