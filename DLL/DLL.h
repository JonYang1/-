#pragma once
#define ZLIB_WINAPI
#include "zlib\\zlib.h"
#pragma comment(lib,"zlib/zlibstat.lib")
////////////////////////////////////////////////////////////////////



////////////////////////////////////////////





// 重定位信息用到的结构体
typedef struct _RELOCTYPE {
	unsigned short offset : 12;
	unsigned short type : 4;
}RELOCTYPE, *PRELOCTYPE;
typedef struct _PACKINFO {
	DWORD dwNewOep;  //它存储起始函数地址
	DWORD dwOldOepRVA;  //用来存储目标程序的OEP的RVA
	DWORD dwOldRelocRva;// 旧的重定位表的RVA
	DWORD dwOldRelocSize;// 旧的重定位表的size
	DWORD dwCodeSizeUnCom;//dwSizeUnCom压缩前的字节数
	DWORD dwCodeSizeComed;//dwSizeComed压缩后的字节数
	DWORD dwOldINTRva;// 旧的INT的RVA

}PACKINFO, *PPACKINFO;
typedef FARPROC(WINAPI *MYGETPROCADDRESS)
(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);

typedef HMODULE(WINAPI *MYLOADLIBRARY)(
	_In_ LPCSTR lpLibFileName
	);

typedef HMODULE(WINAPI *MYGETMODULEHANDLEA)(
	_In_opt_ LPCSTR lpModuleName
	);

typedef BOOL(WINAPI *MYVIRTUALPROTECT)(
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect
	);

typedef LPVOID(WINAPI *MYVIRTUALALLOC)(
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect
	);

typedef BOOL(WINAPI *MYVIRTUALFREE)(
	_Pre_notnull_ _When_(dwFreeType == MEM_DECOMMIT, _Post_invalid_) _When_(dwFreeType == MEM_RELEASE, _Post_ptr_invalid_) LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD dwFreeType
	);