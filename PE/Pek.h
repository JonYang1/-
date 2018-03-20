#pragma once
#include <windows.h>

typedef struct _SECINFO {
	BYTE pName[8];
	DWORD dwRawSize;
	DWORD dwCharacteristics;
}SECINFO;

typedef struct _PACKINFO {
	DWORD dwNewOep;  //它存储起始函数地址
	DWORD dwOldOepRVA;  //用来存储目标程序的OEP的RVA
	DWORD dwOldRelocRva;// 旧的重定位表的RVA
	DWORD dwOldRelocSize;// 旧的重定位表的size
	DWORD dwCodeSizeUnCom;//dwSizeUnCom压缩前的字节数
	DWORD dwCodeSizeComed;//dwSizeComed压缩后的字节数
	DWORD dwOldINTRva;// 旧的INT的RVA
}PACKINFO, *PPACKINFO;

typedef struct _RELOCTYPE {
	unsigned short offset : 12;
	unsigned short type : 4;
}RELOCTYPE, *PRELOCTYPE;

class Pek {
public:
	Pek();
	~Pek();
	bool OpenSourceFile(TCHAR* szExe);
	bool OpenStubFile(TCHAR* szDll);
	bool AddSection(SECINFO* pNewSecInfo, PBYTE pNewSecByte);
	void GetOldOep();
	void AddStubText();
	void AddStubRelocSeg();
	void SetNewOep();
	bool SaveAsNewPe(TCHAR *szNewFile);
	/*修复导入表*/
	bool FixStubReloc();
	/*修复Stub的INT表，并使新EXE的导入表指向Stub的导入表*/
	bool FixAndResetINT();
	/*重定位INT的信息*/
	void FixINT();
	/*设置Stub的导入表为新EXE程序的导入表
	包括INT和IAT，IAT数组可以不修复，但数据目录表必须修复*/
	void ResetINT();
	/*取消重定位*/
	void CancleRandomBase();
	/*更改原EXE程序的重定位信息为stub的重定位信息段 */
	void SetRelocDataDir();
	/*加密代码段，代码段不一定是第1个区段*/
	void jiami();
	/*压缩区段,返回压缩后的字节数*/
	int ComPressSegment(PIMAGE_NT_HEADERS pNt, DWORD dwIndex);
	/*压缩代码段*/
	bool CompressCodeSeg();
	void CopyInfo();
	void TLS();
public:
	PBYTE m_pSource;
	DWORD m_dwNewSize;
	PBYTE m_pStub;
	PBYTE m_pStubBase;
	DWORD m_dwPackInfoOffset;
	PIMAGE_DATA_DIRECTORY g_Stub_pTLS;

};

