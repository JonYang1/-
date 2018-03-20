// DLL.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "DLL.h"
#include <windows.h>
#include <stdio.h>

#define ZLIB_WINAPI
#include "zlib\\zlib.h"
#include <winuser.h>
#include <tchar.h>
#pragma comment(lib,"zlib/zlibstat.lib")

#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")
//#pragma comment(linker, "/merge:.idata=.RWE")
void  Start();
extern "C" _declspec(dllexport) PACKINFO g_PackInfo = { (DWORD)Start };

typedef FARPROC(WINAPI *MYGETPROCADDRESS)
(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);

typedef HMODULE(WINAPI *MYLOADLIBRARY)(
	_In_ LPCSTR lpLibFileName
	);

typedef HMODULE(WINAPI *MYGETMODULEHANDLEA)(
	_In_opt_ LPCSTR lpModuleName
	);
MYGETPROCADDRESS	g_GetProcAddress = nullptr;
MYLOADLIBRARY		g_LoadLibraryA = nullptr;
MYGETMODULEHANDLEA  g_GetModuleHandleA = nullptr;
MYVIRTUALPROTECT	g_VirtualProtect = nullptr;
MYVIRTUALALLOC		g_VirtualAlloc = nullptr;
MYVIRTUALFREE		g_VirtualFree = nullptr;

//////////////////////////////////////////////////////////////////////////

#include <shlwapi.h>  // StrStrI头文件

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
//通知链接器PE文件要创建TLS目录
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(lib, "shlwapi.lib")

BOOL CALLBACK EnumWindowsProc(
	HWND hwnd,      // handle to parent window
	LPARAM lParam)   // application-defined value
{
	char szOD[] = "0llydbg";
	char szIDA[] = "IDA";
	//如果要检测tls.exe，因为在console下面运行，自己程序就会显示
	//所以不检测自己程序名不适合控制台的。
	//char szExeName[]  = "Tls.exe";
	char szTemp[MAX_PATH] = "cc_.exe";

	if (IsWindowVisible(hwnd))
	{
		GetWindowText(hwnd, (LPWSTR)szTemp, MAX_PATH);
		if (strcmp(szTemp, szOD) || strcmp(szTemp, szIDA))
		{
			//ExitProcess(0);//退出
			return FALSE; //检测到调试器
		}
	}
	return TRUE;
}

void NTAPI My_Tls_Callback(PVOID h, DWORD dwReason, PVOID pv)
{
	//监测DLL_PROCESS_DETACH   DLL_PROCESS_ATTACH
	if (dwReason == DLL_PROCESS_DETACH)
	{
		MessageBox(NULL, L"TLS", L"监测到调试工具", 0);
		// 这里进行反调试
		
		//EnumWindows(EnumWindowsProc, NULL);
		
	}
	return;
}
//创建TLS段
#pragma data_seg(".CRT$XLB")
//定义回调函数
//定义多个回调函数
//PIMAGE_TLS_CALLBACK p_thread_callback [] = {tls_callback_A, tls_callback_B, tls_callback_C,0};
PIMAGE_TLS_CALLBACK p_thread_callback[] = { My_Tls_Callback, 0 };
#pragma data_seg()

//1      O0  l I 
//////////////////////////////////////////////////////////////////////////
////////////////////////////////调试器反/////////////////////////////////////
//

void tiaos()
{
	int nResult = 0;
	_asm
	{
		push eax;
		push ebx;
		mov eax, FS:[0x30];//得到PEB
		xor ebx, ebx;
		mov ebx, [eax + 0x68]; // 检测PEB的NtGlobalFlag字段,如果被调试,此字段值为x70
		mov nResult, ebx;
		pop ebx;
		pop eax;
	}
	if (nResult == 0x70)
	{
		MessageBox(0, L"正在被调试", L"正在被调试", 0);
		exit(0);
	}
}
//////////////////////////////////////////////////////////////////////////
void  MyGetProcAddress(LPVOID *pGetProc, LPVOID *pLoadLibrary)
{
	PCHAR pBuf = NULL;
	_asm
	{
		mov eax, fs:[0x30];//找到PEB
		mov eax, [eax + 0x0C];//找到了LDR
		mov eax, [eax + 0x0C];//找到了第一个节点
		mov eax, [eax];       //找到了ntdll
		mov eax, [eax];       //找到了kernel32.dll
		mov ebx, dword ptr ds : [eax + 0x18];
		mov pBuf, ebx;
	}

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);

	PIMAGE_DATA_DIRECTORY pExportDir =
		(pNt->OptionalHeader.DataDirectory + 0);

	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)
		(pExportDir->VirtualAddress + pBuf);
	//后面的步骤

	//1  找到三个表：名称，地址，序号
	PDWORD pAddress = (PDWORD)(pExport->AddressOfFunctions + pBuf);
	PDWORD pName = (PDWORD)(pExport->AddressOfNames + pBuf);
	PWORD  pId = (PWORD)(pExport->AddressOfNameOrdinals + pBuf);
	PVOID GetProAddress = 0;
	PVOID LoadLibry = 0;
	//2  在名称表中去遍历GetProcAddress这个字符串
	for (size_t i = 0; i < pExport->NumberOfNames; i++)
	{
		char* Name = (pName[i] + pBuf);
		if (strcmp(Name, "GetProcAddress") == 0)
		{
			GetProAddress = pAddress[pId[i]] + pBuf;
		}
		if (strcmp(Name, "LoadLibraryA") == 0)
		{
			LoadLibry = pAddress[pId[i]] + pBuf;
		}
	}
	*pGetProc = GetProAddress;
	*pLoadLibrary = LoadLibry;
}

//初始化
void Init()
{
	MyGetProcAddress((LPVOID*)&g_GetProcAddress, (LPVOID*)&g_LoadLibraryA);
	//动态获取需要的API，在这里初始化所有你需要的函数变量
	g_GetModuleHandleA = (MYGETMODULEHANDLEA)
		g_GetProcAddress(g_LoadLibraryA("kernel32.dll"), "GetModuleHandleA");
	g_VirtualProtect = (MYVIRTUALPROTECT)
		g_GetProcAddress(g_GetModuleHandleA("kernel32.dll"), "VirtualProtect");
	g_VirtualAlloc = (MYVIRTUALALLOC)
		g_GetProcAddress(g_GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
	g_VirtualFree = (MYVIRTUALFREE)
		g_GetProcAddress(g_GetModuleHandleA("kernel32.dll"), "VirtualFree");
}


//压缩区段
void YaSuo() {
	/*1.先找到代码段RVA*/
	HMODULE hBase = g_GetModuleHandleA(0);
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)hBase + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
	while (!pSec->SizeOfRawData)
	{
		pSec++;
	}
	/*代码段地址*/
	PBYTE pAddrUnComSrc = (PBYTE)hBase + pSec->VirtualAddress;
	/*2. 压缩前后大小*/
	/*压缩后的大小*/
	ULONG uCodeSizeComed = g_PackInfo.dwCodeSizeComed;
	/*压缩前的大小*/
	ULONG uCodeSizeUnCom = g_PackInfo.dwCodeSizeUnCom;
	if (!uCodeSizeComed || !uCodeSizeUnCom) {
		return;// 没有压缩
	}

	/*申请空间用于存放解压后的代码*/
	PBYTE pAddrUnComDes = (PBYTE)g_VirtualAlloc(NULL, uCodeSizeUnCom, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pAddrUnComDes == NULL) {
		return;
	}
	/*改变代码段读写属性，保证可读写*/
	DWORD dwOldProt = 0;
	g_VirtualProtect(pAddrUnComSrc, uCodeSizeUnCom, PAGE_READWRITE, &dwOldProt);
	/*开始解压缩*/
	ULONG uLen = uCodeSizeUnCom;
	if (uncompress(pAddrUnComDes, &uLen, pAddrUnComSrc, uCodeSizeComed)
		!= Z_OK) {
		// 失败
		g_VirtualFree(pAddrUnComDes, 0, MEM_RELEASE);
	}
	/*拷贝回去*/
	memcpy_s(pAddrUnComSrc, uCodeSizeUnCom, pAddrUnComDes, uLen);
	g_VirtualProtect(pAddrUnComSrc, uCodeSizeUnCom, dwOldProt, &dwOldProt);
	/*代码段大小给改回来*/
	/*保证可写*/
	g_VirtualProtect(pSec, 16, PAGE_READWRITE, &dwOldProt);
	pSec->SizeOfRawData = uCodeSizeUnCom;
	g_VirtualProtect(pSec, 16, dwOldProt, &dwOldProt);

}
//解密
void Jiemi()
{
	//获得基址
	HMODULE hBase = g_GetModuleHandleA(0);
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)hBase + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
	/*代码段RVA和size*/
	DWORD dwCodeRVA = 0, dwCodeSize = 0;
	while (true) 
	{
		if (pSec->PointerToRawData && pSec->SizeOfRawData) 
		{
			dwCodeRVA = pSec->VirtualAddress;
			dwCodeSize = pSec->SizeOfRawData;
			break;
		}
		pSec++;
	}
	PDWORD pDecryptAddr = (PDWORD)((DWORD)hBase + dwCodeRVA);
	DWORD dwCount = dwCodeSize / 4;
	DWORD dwOldProtect = 0;
	/*保证可写*/
	int a = 1;
	if (!g_VirtualProtect(pDecryptAddr, dwCodeSize, PAGE_READWRITE, &dwOldProtect)) 
		return;
	/*循环解密*/
	for (DWORD i = 0; i < dwCount; ++i) {
		a++;
		pDecryptAddr[i] ^=a;
	}
	if (!g_VirtualProtect(pDecryptAddr, dwCodeSize, dwOldProtect, &dwOldProtect))
		return;
}
//重定位
void FixSrcReloc() {
	// 找到原重定位表信息的地址
	HMODULE hBase = g_GetModuleHandleA(0);
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)hBase + pDos->e_lfanew);
	/*是否有重定位信息*/
	if (!g_PackInfo.dwOldRelocRva || !g_PackInfo.dwOldRelocSize) {
		return;
	}
	//找到重定位数据
	PIMAGE_BASE_RELOCATION  pRelocAddr = (PIMAGE_BASE_RELOCATION)((DWORD)hBase + g_PackInfo.dwOldRelocRva);
	DWORD dwCount = 0;
	while (pRelocAddr->SizeOfBlock != 0)
	{
		PRELOCTYPE pOffSetArr = (PRELOCTYPE)(pRelocAddr + 1);
		DWORD dwSize = sizeof(IMAGE_BASE_RELOCATION);
		DWORD dwCount = (pRelocAddr->SizeOfBlock - dwSize) / 2;
		for (DWORD i=0;i<dwCount;i++)
		{
				//3
			if (pOffSetArr[i].type==IMAGE_REL_BASED_HIGHLOW)
			{
				DWORD dwOffset = pOffSetArr[i].offset + pRelocAddr->VirtualAddress;
				PDWORD pAddr = (PDWORD)((DWORD)hBase + dwOffset);
				DWORD dwOldProtect = 0;
				//判断属性值
				if (!g_VirtualProtect(pAddr, 4, PAGE_READWRITE, &dwOldProtect))
					return;
				//修复后的值 = 修复前的值 - dwImageBase + hBase
				*pAddr = *pAddr - 0x400000 + (DWORD)hBase;
				if (!g_VirtualProtect(pAddr, 4, dwOldProtect, &dwOldProtect))
					return;
			}
		}
		// 已重定位数据大小
		dwCount += pRelocAddr->SizeOfBlock;
		// 定位到下一个区块
		pRelocAddr = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocAddr + pRelocAddr->SizeOfBlock);

	}
}
//修复IAT
void FixIAT() 
{
	// 获取INT的地址 直接修复旧的然后找到它的地址 
	DWORD dwRva = g_PackInfo.dwOldINTRva;
	HMODULE hBase = g_GetModuleHandleA(0);
	PIMAGE_IMPORT_DESCRIPTOR pImp = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hBase + dwRva);
	/*修复导入表*/
	while (pImp->Name)
	{
		/*导入DLL*/
		PCHAR pDllName = (PCHAR)((DWORD)hBase + pImp->Name);
		HMODULE hDll = g_LoadLibraryA(pDllName);
		/*获取名称数组起始地址和地址数组起始地址*/
		PIMAGE_THUNK_DATA parrFunName = (PIMAGE_THUNK_DATA)((DWORD)hBase + pImp->OriginalFirstThunk);
		PIMAGE_THUNK_DATA parrFunAddr = (PIMAGE_THUNK_DATA)((DWORD)hBase + pImp->FirstThunk);
		/*根据名字/序号获取函数地址，存入对应的地址数组内*/
		DWORD dwCount = 0;
		while (parrFunName->u1.Ordinal)
		{
			//函数地址
			DWORD dwFunAddr = 0;
			//IAT IMAGE_SNAP_BY_ORDINAL 结构体
			if (IMAGE_SNAP_BY_ORDINAL(parrFunName->u1.Ordinal)) 
			{
				dwFunAddr = (DWORD)g_GetProcAddress(hDll, (CHAR*)(parrFunName->u1.Ordinal & 0x0ffff));
			}
			else {
				//找到名称
				PIMAGE_IMPORT_BY_NAME pStcName = (PIMAGE_IMPORT_BY_NAME)
					((DWORD)hBase + parrFunName->u1.Function);
				dwFunAddr = (DWORD)g_GetProcAddress(hDll, pStcName->Name);
			}
			//有足够的权限
			DWORD dwOldProtect = 0;
			g_VirtualProtect(&parrFunAddr[dwCount], 4, PAGE_READWRITE, &dwOldProtect);
			//放入函数地址到IAT中
			parrFunAddr[dwCount].u1.AddressOfData = dwFunAddr;
			g_VirtualProtect(&parrFunAddr[dwCount], 4, dwOldProtect, &dwOldProtect);
			/*下一个函数*/
			parrFunName++;
			dwCount++;
		}
		/*下一个DLL*/
		pImp++;
	}
}

//MFC
LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	HDC hdc;
	static HWND hwndButton, hwndEdit;
	TCHAR  text[100];
	switch (message) {
	case WM_CREATE:
	{
		TEXTMETRIC tm;
		hdc = GetDC(hwnd);
		SelectObject(hdc, GetStockObject(SYSTEM_FIXED_FONT));
		GetTextMetrics(hdc, &tm);
		ReleaseDC(hwnd, hdc);
		hwndButton = CreateWindow(
			L"BUTTON",
			L"确定",
			WS_CHILD | WS_VISIBLE | BS_FLAT | WS_BORDER,
			8, 40, 296, 24,
			hwnd,
			(HMENU)1,
			((LPCREATESTRUCT)lParam)->hInstance,
			NULL
		);//创建按钮
		hwndEdit= CreateWindow(
			L"EDIT",
			NULL,
			WS_VISIBLE | WS_CHILD | WS_BORDER,
			8,
			8,
			296,
			24,
			hwnd,
			(HMENU)1,
			((LPCREATESTRUCT)lParam)->hInstance,
			NULL);//创建编辑框
		return 0;
		break;
	}
	case WM_COMMAND:
		if (LOWORD(wParam) == 1 &&
			HIWORD(wParam) == BN_CLICKED &&
			(HWND)lParam == hwndButton)//如果按钮被单击
		{
			GetWindowText(hwndEdit, text, 100);//获取编辑框内容至text
			

			if (!_tcscmp(text,L"1234"))
			{
				MessageBoxW(0,L"成功",L"成功",0);
				ShowWindow(hwnd, SW_HIDE);	
				__asm
				{

				}
				PostQuitMessage(0);
				return 0;
			}
			else {
				MessageBoxW(0, L"失败", L"失败", 0);
				exit(0);
				//PostQuitMessage(0);
			}
			
			
		}
	case WM_LBUTTONDOWN:
		return 0;
	case WM_DESTROY:
		exit(0);
		PostQuitMessage(0);
		return 0;
	case WM_PAINT:
	{
		PAINTSTRUCT ps = { 0 };
		BeginPaint(hwnd, &ps);
		EndPaint(hwnd, &ps);
		return 0;
	}
	}
	return DefWindowProc(hwnd, message, wParam, lParam);

}
void Sdk()
{
	HINSTANCE hInstance = (HINSTANCE)GetModuleHandle(NULL);
	static TCHAR szAppName[] = TEXT("HelloWin");
	HWND         hwnd;
	MSG          msg;
	WNDCLASS     wndclass;

	wndclass.style = CS_HREDRAW | CS_VREDRAW;
	wndclass.lpfnWndProc = WndProc;
	wndclass.cbClsExtra = 0;
	wndclass.cbWndExtra = 0;
	wndclass.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wndclass.hCursor = LoadCursor(NULL, IDC_ARROW);
	wndclass.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
	wndclass.lpszMenuName = NULL;
	wndclass.lpszClassName = szAppName;
	wndclass.hInstance = hInstance;
	if (!RegisterClass(&wndclass))
	{
		MessageBox(NULL, TEXT("对话框创建失败"),
			szAppName, MB_ICONERROR);
		return;
	}

	hwnd = CreateWindow(szAppName, TEXT("密码"),
		WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT,
		400, 200,
		NULL, NULL, hInstance, NULL);

	ShowWindow(hwnd, SW_SHOW);
	UpdateWindow(hwnd);
	

	
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
}
_declspec(naked) void  Start()
{
	
	//花指令就是干扰指令
	_asm {
		//调试器监测
		call tiaos;
		call Sdk;
		call Init;
		jmp  aa;
		_emit 0x01;
	aa:
		
		call YaSuo;
		call Jiemi;
	
		call FixSrcReloc;
		call FixIAT;
		jmp hehe;
		_emit 0x09;
	hehe:
	//~~~~~~~~~~~~
		push ebp
		mov ebp, esp
		pop esp
	//~~~~~~~~~~~~~~~~~~~
		push 0
		call g_GetModuleHandleA
		add eax, g_PackInfo.dwOldOepRVA;
		jmp eax; //OEP

	//~~~~~~~~~~~~~~~~~~~~~~~
		push ebp
		push esp
		pop ebp
		add esp, -0x0C
		add esp, 0x0C
		//~~~~~~~~~~~~~~~~~~~~~~~
		//  混淆
		cmp eax, eax; //相等跳转 代替jmp指令
		jmp eax;
	}
}