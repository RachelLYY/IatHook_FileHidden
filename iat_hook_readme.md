#基于IAT hook的文件隐藏工具

- 基本原理

  - 通过dumpbin查看cmd.exe和explorer.exe的导入表，确定它们在查看文件时使用了哪些api。
  - 通过iathook的方法篡改其导入表中的api，实现其在查看文件时指定名称文件的隐藏。

- 程序整体思路

  - 分析

    - 利用dumpbin查看cmd.exe的导入表

      - ```shell
        dumpbin.exe /imports C:\WINDOWS\system32\cmd.exe
        ```

      - 搜索“find”关键词，猜测查看文件时可能用到了两个api。

        - ![text](img\2.png)
        - ![text](img\1.png)

      - 通过分析猜测，可得知这两个api在遍历文件时应该使用了FindFirstFile和FindNextFile。

      - iathook时需要对上述dll操作。

  - iathook

    - 基本流程

    - 核心代码

      - ```c
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
        		tf=(*fnOrigin)(hFindFile, lpFindFileData);
        	}
        	return tf;
        }
        ```

      - 这里是对FindNextFile进行hook。

      - FindNextFile接收一个上一个文件传来的句柄，并据此去找下一个文件，我们这里模拟cmd的寻找方式，当找到了指定要隐藏的文件（如本程序中是“2.jpg”）时，就再执行一次FindNextFile，即可实现文件隐藏。

  - 篡改导入表的api

    - 基本流程
      - 提权
      - 遍历当前进程获得指定exe（cmd）的pid
      - dll注入过程
        - 使用VirtualAllocEx给进程开辟虚拟空间
        - 使用WriteProcessMemory将数据写入刚刚开辟的内存区域
        - 使用CreateRemoteThread运行刚刚写入的进程

- 程序运行效果

  - hook之前，D:\\test文件夹下的文件
    - ![test](img\5.png)
  - 对cmd.exe进行hook
    - 自动遍历当前可执行程序，找到cmd.exe，获得其进程PID
      - ![text](img\3.png)
  - 查看D:\\test文件夹下文件
    - ![text](img\4.png)

- 遇到的问题

  - FindNextFile的hook过程

    - cmd在查看文件时，调用FindNextFile的过程是循环进行的。也就是说，cmd先调用FindFirstFile得到第一个文件的句柄，然后传给FindNextFile。FindNextFile根据这个句柄再去找下一个文件，直到当前文件夹下没有文件为止。
    - 正确实现过程：假的FindNextFile接收cmd那里传来的文件句柄，判断当前的文件名是否是要求隐藏的文件，如果是，则再执行一次FindNextFile，把下一个文件的句柄传下去。如果不是，则正常执行。
    - 之前错误地理解了这个过程，认为直接把FindNextFile重写即可，造成了在cmd窗口中输入dir后，文件会不停地显示。

  - dll导出

    - dll有固定的格式，程序与生成exe的程序不相同，主要区别在于入口函数.

      - dll入口函数格式

        - ```c
          extern "C" __declspec(dllexport)
          BOOL APIENTRY DllMain(HMODULE hModule,
          	DWORD ul_reason_for_call,
          	LPVOID lpReserved) {
          	switch (ul_reason_for_call) {
          	case DLL_PROCESS_ATTACH:
          	{
                	//创建线程 也就是调用FindFileThread函数
          		CreateThread(NULL, NULL, FindFileThread, NULL, NULL, NULL);
          		break;
          	}
          	case DLL_THREAD_ATTACH:
          	case DLL_THREAD_DETACH:
          	case DLL_PROCESS_DETACH:
          		break;
          	}
          	return TRUE;
          }
          ```

  - 字符比较

    - 宽字符类型和char类型不能直接比较，文件名比较过程中，我们可以拿到的是wchar类型的文件名，因此要定义一个wchar类型的文件名和当前文件名比较。

      - 解决方式

        - 直接定义wchar_t*类型的变量

          - ```c
            wchar_t chr1 = L'2.jpg';
            ```

        - char转wchar_t

          - ```c
            char *CStr = "2.jpg";
            size_t len = strlen(CStr) + 1;
            size_t converted = 0;
            wchar_t *WStr;
            WStr = (wchar_t*)malloc(len * sizeof(wchar_t));
            mbstowcs_s(&converted, WStr, len, CStr, _TRUNCATE);
            ```