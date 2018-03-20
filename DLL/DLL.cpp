// DLL.cpp : ���� DLL Ӧ�ó���ĵ���������
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

#include <shlwapi.h>  // StrStrIͷ�ļ�

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
//֪ͨ������PE�ļ�Ҫ����TLSĿ¼
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(lib, "shlwapi.lib")

BOOL CALLBACK EnumWindowsProc(
	HWND hwnd,      // handle to parent window
	LPARAM lParam)   // application-defined value
{
	char szOD[] = "0llydbg";
	char szIDA[] = "IDA";
	//���Ҫ���tls.exe����Ϊ��console�������У��Լ�����ͻ���ʾ
	//���Բ�����Լ����������ʺϿ���̨�ġ�
	//char szExeName[]  = "Tls.exe";
	char szTemp[MAX_PATH] = "cc_.exe";

	if (IsWindowVisible(hwnd))
	{
		GetWindowText(hwnd, (LPWSTR)szTemp, MAX_PATH);
		if (strcmp(szTemp, szOD) || strcmp(szTemp, szIDA))
		{
			//ExitProcess(0);//�˳�
			return FALSE; //��⵽������
		}
	}
	return TRUE;
}

void NTAPI My_Tls_Callback(PVOID h, DWORD dwReason, PVOID pv)
{
	//���DLL_PROCESS_DETACH   DLL_PROCESS_ATTACH
	if (dwReason == DLL_PROCESS_DETACH)
	{
		MessageBox(NULL, L"TLS", L"��⵽���Թ���", 0);
		// ������з�����
		
		//EnumWindows(EnumWindowsProc, NULL);
		
	}
	return;
}
//����TLS��
#pragma data_seg(".CRT$XLB")
//����ص�����
//�������ص�����
//PIMAGE_TLS_CALLBACK p_thread_callback [] = {tls_callback_A, tls_callback_B, tls_callback_C,0};
PIMAGE_TLS_CALLBACK p_thread_callback[] = { My_Tls_Callback, 0 };
#pragma data_seg()

//1      O0  l I 
//////////////////////////////////////////////////////////////////////////
////////////////////////////////��������/////////////////////////////////////
//

void tiaos()
{
	int nResult = 0;
	_asm
	{
		push eax;
		push ebx;
		mov eax, FS:[0x30];//�õ�PEB
		xor ebx, ebx;
		mov ebx, [eax + 0x68]; // ���PEB��NtGlobalFlag�ֶ�,���������,���ֶ�ֵΪx70
		mov nResult, ebx;
		pop ebx;
		pop eax;
	}
	if (nResult == 0x70)
	{
		MessageBox(0, L"���ڱ�����", L"���ڱ�����", 0);
		exit(0);
	}
}
//////////////////////////////////////////////////////////////////////////
void  MyGetProcAddress(LPVOID *pGetProc, LPVOID *pLoadLibrary)
{
	PCHAR pBuf = NULL;
	_asm
	{
		mov eax, fs:[0x30];//�ҵ�PEB
		mov eax, [eax + 0x0C];//�ҵ���LDR
		mov eax, [eax + 0x0C];//�ҵ��˵�һ���ڵ�
		mov eax, [eax];       //�ҵ���ntdll
		mov eax, [eax];       //�ҵ���kernel32.dll
		mov ebx, dword ptr ds : [eax + 0x18];
		mov pBuf, ebx;
	}

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);

	PIMAGE_DATA_DIRECTORY pExportDir =
		(pNt->OptionalHeader.DataDirectory + 0);

	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)
		(pExportDir->VirtualAddress + pBuf);
	//����Ĳ���

	//1  �ҵ����������ƣ���ַ�����
	PDWORD pAddress = (PDWORD)(pExport->AddressOfFunctions + pBuf);
	PDWORD pName = (PDWORD)(pExport->AddressOfNames + pBuf);
	PWORD  pId = (PWORD)(pExport->AddressOfNameOrdinals + pBuf);
	PVOID GetProAddress = 0;
	PVOID LoadLibry = 0;
	//2  �����Ʊ���ȥ����GetProcAddress����ַ���
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

//��ʼ��
void Init()
{
	MyGetProcAddress((LPVOID*)&g_GetProcAddress, (LPVOID*)&g_LoadLibraryA);
	//��̬��ȡ��Ҫ��API���������ʼ����������Ҫ�ĺ�������
	g_GetModuleHandleA = (MYGETMODULEHANDLEA)
		g_GetProcAddress(g_LoadLibraryA("kernel32.dll"), "GetModuleHandleA");
	g_VirtualProtect = (MYVIRTUALPROTECT)
		g_GetProcAddress(g_GetModuleHandleA("kernel32.dll"), "VirtualProtect");
	g_VirtualAlloc = (MYVIRTUALALLOC)
		g_GetProcAddress(g_GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
	g_VirtualFree = (MYVIRTUALFREE)
		g_GetProcAddress(g_GetModuleHandleA("kernel32.dll"), "VirtualFree");
}


//ѹ������
void YaSuo() {
	/*1.���ҵ������RVA*/
	HMODULE hBase = g_GetModuleHandleA(0);
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)hBase + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
	while (!pSec->SizeOfRawData)
	{
		pSec++;
	}
	/*����ε�ַ*/
	PBYTE pAddrUnComSrc = (PBYTE)hBase + pSec->VirtualAddress;
	/*2. ѹ��ǰ���С*/
	/*ѹ����Ĵ�С*/
	ULONG uCodeSizeComed = g_PackInfo.dwCodeSizeComed;
	/*ѹ��ǰ�Ĵ�С*/
	ULONG uCodeSizeUnCom = g_PackInfo.dwCodeSizeUnCom;
	if (!uCodeSizeComed || !uCodeSizeUnCom) {
		return;// û��ѹ��
	}

	/*����ռ����ڴ�Ž�ѹ��Ĵ���*/
	PBYTE pAddrUnComDes = (PBYTE)g_VirtualAlloc(NULL, uCodeSizeUnCom, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pAddrUnComDes == NULL) {
		return;
	}
	/*�ı����ζ�д���ԣ���֤�ɶ�д*/
	DWORD dwOldProt = 0;
	g_VirtualProtect(pAddrUnComSrc, uCodeSizeUnCom, PAGE_READWRITE, &dwOldProt);
	/*��ʼ��ѹ��*/
	ULONG uLen = uCodeSizeUnCom;
	if (uncompress(pAddrUnComDes, &uLen, pAddrUnComSrc, uCodeSizeComed)
		!= Z_OK) {
		// ʧ��
		g_VirtualFree(pAddrUnComDes, 0, MEM_RELEASE);
	}
	/*������ȥ*/
	memcpy_s(pAddrUnComSrc, uCodeSizeUnCom, pAddrUnComDes, uLen);
	g_VirtualProtect(pAddrUnComSrc, uCodeSizeUnCom, dwOldProt, &dwOldProt);
	/*����δ�С���Ļ���*/
	/*��֤��д*/
	g_VirtualProtect(pSec, 16, PAGE_READWRITE, &dwOldProt);
	pSec->SizeOfRawData = uCodeSizeUnCom;
	g_VirtualProtect(pSec, 16, dwOldProt, &dwOldProt);

}
//����
void Jiemi()
{
	//��û�ַ
	HMODULE hBase = g_GetModuleHandleA(0);
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)hBase + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
	/*�����RVA��size*/
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
	/*��֤��д*/
	int a = 1;
	if (!g_VirtualProtect(pDecryptAddr, dwCodeSize, PAGE_READWRITE, &dwOldProtect)) 
		return;
	/*ѭ������*/
	for (DWORD i = 0; i < dwCount; ++i) {
		a++;
		pDecryptAddr[i] ^=a;
	}
	if (!g_VirtualProtect(pDecryptAddr, dwCodeSize, dwOldProtect, &dwOldProtect))
		return;
}
//�ض�λ
void FixSrcReloc() {
	// �ҵ�ԭ�ض�λ����Ϣ�ĵ�ַ
	HMODULE hBase = g_GetModuleHandleA(0);
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)hBase + pDos->e_lfanew);
	/*�Ƿ����ض�λ��Ϣ*/
	if (!g_PackInfo.dwOldRelocRva || !g_PackInfo.dwOldRelocSize) {
		return;
	}
	//�ҵ��ض�λ����
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
				//�ж�����ֵ
				if (!g_VirtualProtect(pAddr, 4, PAGE_READWRITE, &dwOldProtect))
					return;
				//�޸����ֵ = �޸�ǰ��ֵ - dwImageBase + hBase
				*pAddr = *pAddr - 0x400000 + (DWORD)hBase;
				if (!g_VirtualProtect(pAddr, 4, dwOldProtect, &dwOldProtect))
					return;
			}
		}
		// ���ض�λ���ݴ�С
		dwCount += pRelocAddr->SizeOfBlock;
		// ��λ����һ������
		pRelocAddr = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocAddr + pRelocAddr->SizeOfBlock);

	}
}
//�޸�IAT
void FixIAT() 
{
	// ��ȡINT�ĵ�ַ ֱ���޸��ɵ�Ȼ���ҵ����ĵ�ַ 
	DWORD dwRva = g_PackInfo.dwOldINTRva;
	HMODULE hBase = g_GetModuleHandleA(0);
	PIMAGE_IMPORT_DESCRIPTOR pImp = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hBase + dwRva);
	/*�޸������*/
	while (pImp->Name)
	{
		/*����DLL*/
		PCHAR pDllName = (PCHAR)((DWORD)hBase + pImp->Name);
		HMODULE hDll = g_LoadLibraryA(pDllName);
		/*��ȡ����������ʼ��ַ�͵�ַ������ʼ��ַ*/
		PIMAGE_THUNK_DATA parrFunName = (PIMAGE_THUNK_DATA)((DWORD)hBase + pImp->OriginalFirstThunk);
		PIMAGE_THUNK_DATA parrFunAddr = (PIMAGE_THUNK_DATA)((DWORD)hBase + pImp->FirstThunk);
		/*��������/��Ż�ȡ������ַ�������Ӧ�ĵ�ַ������*/
		DWORD dwCount = 0;
		while (parrFunName->u1.Ordinal)
		{
			//������ַ
			DWORD dwFunAddr = 0;
			//IAT IMAGE_SNAP_BY_ORDINAL �ṹ��
			if (IMAGE_SNAP_BY_ORDINAL(parrFunName->u1.Ordinal)) 
			{
				dwFunAddr = (DWORD)g_GetProcAddress(hDll, (CHAR*)(parrFunName->u1.Ordinal & 0x0ffff));
			}
			else {
				//�ҵ�����
				PIMAGE_IMPORT_BY_NAME pStcName = (PIMAGE_IMPORT_BY_NAME)
					((DWORD)hBase + parrFunName->u1.Function);
				dwFunAddr = (DWORD)g_GetProcAddress(hDll, pStcName->Name);
			}
			//���㹻��Ȩ��
			DWORD dwOldProtect = 0;
			g_VirtualProtect(&parrFunAddr[dwCount], 4, PAGE_READWRITE, &dwOldProtect);
			//���뺯����ַ��IAT��
			parrFunAddr[dwCount].u1.AddressOfData = dwFunAddr;
			g_VirtualProtect(&parrFunAddr[dwCount], 4, dwOldProtect, &dwOldProtect);
			/*��һ������*/
			parrFunName++;
			dwCount++;
		}
		/*��һ��DLL*/
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
			L"ȷ��",
			WS_CHILD | WS_VISIBLE | BS_FLAT | WS_BORDER,
			8, 40, 296, 24,
			hwnd,
			(HMENU)1,
			((LPCREATESTRUCT)lParam)->hInstance,
			NULL
		);//������ť
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
			NULL);//�����༭��
		return 0;
		break;
	}
	case WM_COMMAND:
		if (LOWORD(wParam) == 1 &&
			HIWORD(wParam) == BN_CLICKED &&
			(HWND)lParam == hwndButton)//�����ť������
		{
			GetWindowText(hwndEdit, text, 100);//��ȡ�༭��������text
			

			if (!_tcscmp(text,L"1234"))
			{
				MessageBoxW(0,L"�ɹ�",L"�ɹ�",0);
				ShowWindow(hwnd, SW_HIDE);	
				__asm
				{

				}
				PostQuitMessage(0);
				return 0;
			}
			else {
				MessageBoxW(0, L"ʧ��", L"ʧ��", 0);
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
		MessageBox(NULL, TEXT("�Ի��򴴽�ʧ��"),
			szAppName, MB_ICONERROR);
		return;
	}

	hwnd = CreateWindow(szAppName, TEXT("����"),
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
	
	//��ָ����Ǹ���ָ��
	_asm {
		//���������
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
		//  ����
		cmp eax, eax; //�����ת ����jmpָ��
		jmp eax;
	}
}