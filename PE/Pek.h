#pragma once
#include <windows.h>

typedef struct _SECINFO {
	BYTE pName[8];
	DWORD dwRawSize;
	DWORD dwCharacteristics;
}SECINFO;

typedef struct _PACKINFO {
	DWORD dwNewOep;  //���洢��ʼ������ַ
	DWORD dwOldOepRVA;  //�����洢Ŀ������OEP��RVA
	DWORD dwOldRelocRva;// �ɵ��ض�λ���RVA
	DWORD dwOldRelocSize;// �ɵ��ض�λ���size
	DWORD dwCodeSizeUnCom;//dwSizeUnComѹ��ǰ���ֽ���
	DWORD dwCodeSizeComed;//dwSizeComedѹ������ֽ���
	DWORD dwOldINTRva;// �ɵ�INT��RVA
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
	/*�޸������*/
	bool FixStubReloc();
	/*�޸�Stub��INT����ʹ��EXE�ĵ����ָ��Stub�ĵ����*/
	bool FixAndResetINT();
	/*�ض�λINT����Ϣ*/
	void FixINT();
	/*����Stub�ĵ����Ϊ��EXE����ĵ����
	����INT��IAT��IAT������Բ��޸���������Ŀ¼������޸�*/
	void ResetINT();
	/*ȡ���ض�λ*/
	void CancleRandomBase();
	/*����ԭEXE������ض�λ��ϢΪstub���ض�λ��Ϣ�� */
	void SetRelocDataDir();
	/*���ܴ���Σ�����β�һ���ǵ�1������*/
	void jiami();
	/*ѹ������,����ѹ������ֽ���*/
	int ComPressSegment(PIMAGE_NT_HEADERS pNt, DWORD dwIndex);
	/*ѹ�������*/
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

