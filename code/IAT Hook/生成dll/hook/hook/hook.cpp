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
		// OriginalFirstThunk(Characteristics):����һ��IMAGE_THUNK_DATA�����RVA�������PE�ļ���ʼ����
		// (IMAGE_THUNK_DATA*)((UCHAR*)pHookBlock->pImageBase�ǻ�ַ��ַ
		//FirstThunk:ͨ��Ҳ��һ��IMAGE_THUNK_DATA�����RVA���������һ��ָ�룬�����Ǹù�����DLL�е���š�
		//OriginalFirstThunk��FirstThunkָ������������ͬ������IMAGE_THUNK_DATA�������Ʋ�ͬ��
		//�ֱ����������Ʊ�(Import Name Table, INT)�������ַ��(Import Address Table, IAT)��
		//ÿһ��IMAGE_THUNK_DATA��Ӧ��һ��������ĺ�����
		//PE װ������������ OriginalFirstThunk ���ҵ�֮����س���������������е�ÿ��ָ�룬�ҵ�ÿ�� IMAGE_IMPORT_BY_NAME �ṹ��ָ������뺯���ĵ�ַ��Ȼ��������ú���������ڵ�ַ������� FirstThunk �����е�һ����ڣ�������ǳ�Ϊ�����ַ��IAT����

		pOriginThunk = (IMAGE_THUNK_DATA*)((UCHAR*)pHookBlock->pImageBase + pImportDescriptor->OriginalFirstThunk);
		pRealThunk = (IMAGE_THUNK_DATA*)((UCHAR*)pHookBlock->pImageBase + pImportDescriptor->FirstThunk);

		//���� pOriginalRhunk�е�Function
		for (; 0 != pOriginThunk->u1.Function; pOriginThunk++, pRealThunk++)
		{
			//IAT�е�IMAGE_THUNK_DATA�д洢�������Ordinal ��λΪ1 ���Ϊ�� ��..
			if (IMAGE_ORDINAL_FLAG == (pOriginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
			{
				//���������� ���������ҵ���
				if ((USHORT)pHookBlock->pszRoutineName == LOWORD(pOriginThunk->u1.Ordinal))
				{
					//bHook->bool  hook or unhook
					if (bHook)
					{
						//�޸�origin trunk Function��������ĺ�������ڵ�ַ
						pHookBlock->pOrigin = (void*)pRealThunk->u1.Function;
						//��������������ַ �޸�ָ���ַ
						_IATHook_InterlockedExchangePointer((void**)&pRealThunk->u1.Function, pHookBlock->pFake);
					}
					else
					{
						//����Ҫiat�Ķ��� ���޸���ԭ��ַ
						_IATHook_InterlockedExchangePointer((void**)&pRealThunk->u1.Function, pHookBlock->pOrigin);
					}

					nFinalRet = 0;
					break;
				}
			}
			//IAT�е�IMAGE_THUNK_DATA�д洢�������AddressOfData
			else
			{
				pImportByName = (IMAGE_IMPORT_BY_NAME*)((char*)pHookBlock->pImageBase + pOriginThunk->u1.AddressOfData);

				//����������
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
	//PEͷ���ṹ��PE��ʶ�����ļ�ͷ���ѡͷ�������֡�
	/*typedef struct _IMAGE_NT_HEADERS {
	DWORD Signature;                              //λ����e_lfanew��
	IMAGE_FILE_HEADER FileHeader;                 //e_lfanew + 0x4         �ļ�ͷ�ṹ��
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;       //e_lfanew + 0x18        ��ѡͷ�ṹ��
	} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
	*/
	IMAGE_NT_HEADERS*	pNTHeaders = NULL;

	//IMAGE_IMPORT_DESCRIPTOR�ṹ���м�¼��PE�ļ�Ҫ������Щ���ļ�
	IMAGE_IMPORT_DESCRIPTOR*	pImportDescriptor = NULL;
	char*						pszImportDllName = NULL;


	do
	{
		if (NULL == pHookBlock)
		{
			break;
		}
		//����һ��PE�ļ���˵���ʼ��λ�þ���һ��DOS����DOS�������һ��DOSͷ��һ��DOS�����塣
		//DOSͷ������IMAGE_DOS_HEADER�ṹ��������ġ�e_magic �ֶ���һ��DOS��ִ���ļ��ı�ʶ��
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
		//����� ���ڻ�ַ��ַ���������ַ
		pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((UCHAR*)pHookBlock->pImageBase + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);


		// Find pszRoutineName in every Import descriptor
		nFinalRet = -1;
		//���� һ��PE�ļ���Ӧһ��IMAGE_IMPORT_DESCRIPTOR ���ҵ�ָ����dll Ҳ����system32.dll
		for (; (pImportDescriptor->Name != 0); pImportDescriptor++)
		{
			OutputDebugString((LPCWSTR)"_IATHook_Internal:in loop");
			//dll�ļ�����
			pszImportDllName = (char*)pHookBlock->pImageBase + pImportDescriptor->Name;

			if (NULL != pHookBlock->pszImportDllName)
			{
				//û�ҵ� ������
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
		//�ڴ����
		pHookBlock = (IATHOOK_BLOCK*)_IATHook_Alloc(sizeof(IATHOOK_BLOCK));
		if (NULL == pHookBlock)
		{
			break;
		}
		RtlZeroMemory(pHookBlock, sizeof(IATHOOK_BLOCK));
		//�ṹ���ʼ�� �����������
		pHookBlock->pImageBase = pImageBase;
		pHookBlock->pszImportDllName = pszImportDllName;
		pHookBlock->pszRoutineName = pszRoutineName;
		pHookBlock->pFake = pFakeRoutine;

		__try
		{
			//�޸�
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
	//ǿ������ת�� ��handle��תΪIATHOOK_BLOCK
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


//API�ĺ�����
typedef BOOL(WINAPI *LPFN_FindNextFile)
(
	_In_ HANDLE hFindFile,
	_Out_ LPWIN32_FIND_DATAW lpFindFileData);

HANDLE g_hHook_FindNextFile = NULL;
//////////////////////////////////////////////////////////////////////////
//��ѡ�������
extern "C" __declspec(dllexport)
BOOL WINAPI Fake_FindNextFile(_In_ HANDLE hFindFile, _Out_ LPWIN32_FIND_DATAW lpFindFileData)
{
	LPFN_FindNextFile fnOrigin = (LPFN_FindNextFile)GetIATHookOrign(g_hHook_FindNextFile);
	//�жϷ���ֵ
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
		//�ٵ���һ��
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
			//�������
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