#include "stdio.h"
#include "Pek.h"
#include <windows.h>
#define ZLIB_WINAPI
#include "zlib\\zlib.h"
#pragma comment(lib,"zlib/zlibstat.lib")
// Release����ʱ�����������Ԥ����ָ��
//#pragma comment(linker,"/NODEFAULTLIB:msvcrtd.lib")

Pek::Pek() {
}


Pek::~Pek() {
}

//���ļ�
bool Pek::OpenSourceFile(TCHAR* szExe)
{
	HANDLE hFile = CreateFile(szExe, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;
	m_dwNewSize = GetFileSize(hFile, NULL);
	m_pSource = (PBYTE)VirtualAlloc(NULL, m_dwNewSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	DWORD dwRead = 0;
	ReadFile(hFile, m_pSource, m_dwNewSize, &dwRead, NULL);
	CloseHandle(hFile);
	return true;
}

//��DLL�ļ�
bool Pek::OpenStubFile(TCHAR* szDll) {
	HMODULE hStub = LoadLibrary(szDll);
	if (hStub == NULL) 
		return false;
	/*����һ��pPackInfo��ƫ��ֵ����������*/
	PPACKINFO pPackInfo = (PPACKINFO)GetProcAddress((HMODULE)hStub, "g_PackInfo");
	m_dwPackInfoOffset = (DWORD)pPackInfo - (DWORD)hStub;
	m_pStubBase = (PBYTE)hStub;
	/*������DLL�����ݵ������������д*/
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hStub;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + (DWORD)hStub);
	DWORD dwSize = (pNt->OptionalHeader.SizeOfImage + 0x0fff) / 0x1000 * 0x01000;
	m_pStub = (PBYTE)VirtualAlloc(NULL, dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	memcpy_s(m_pStub, dwSize, hStub, dwSize);
	FreeLibrary(hStub);
	return true;
}

//�������
bool Pek::AddSection(SECINFO* pNewSecInfo, PBYTE pNewSecByte) 
{
	// ����ԭ�ռ��С�����ڴ���µ�����
	PBYTE pNew = (PBYTE)VirtualAlloc(NULL, m_dwNewSize + pNewSecInfo->dwRawSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	//����ڴ��0
	ZeroMemory(pNew, m_dwNewSize + pNewSecInfo->dwRawSize);
	memcpy_s(pNew, m_dwNewSize, m_pSource, m_dwNewSize);
	m_dwNewSize += pNewSecInfo->dwRawSize;
	VirtualFree(m_pSource, 0, MEM_RELEASE);
	m_pSource = pNew;
	// 1.�ռ��Ѿ������ˣ������µ�������Ϣ
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pSource);
	PIMAGE_SECTION_HEADER pSrcSec = IMAGE_FIRST_SECTION(pNt);
	//ԭʼ�ε���Ŀ
	DWORD dwSecCount = pNt->FileHeader.NumberOfSections;
	//������������ ��,
	// 1.1������
	memcpy_s(pSrcSec[dwSecCount].Name, 8, pNewSecInfo->pName, 8);
	// 1.2��RawAddr
	pSrcSec[dwSecCount].PointerToRawData = pSrcSec[dwSecCount - 1].PointerToRawData + pSrcSec[dwSecCount - 1].SizeOfRawData;
	// 1.3��RSize
	pSrcSec[dwSecCount].SizeOfRawData = pNewSecInfo->dwRawSize;
	// 1.4��VSize
	pSrcSec[dwSecCount].Misc.VirtualSize = pNewSecInfo->dwRawSize;
	// 1.5��RVA
	pSrcSec[dwSecCount].VirtualAddress = pSrcSec[dwSecCount - 1].VirtualAddress
		+ (pSrcSec[dwSecCount - 1].Misc.VirtualSize + 0x0fff) / 0x1000 * 0x1000;
	// 1.1�α�������
	pSrcSec[dwSecCount].Characteristics = pNewSecInfo->dwCharacteristics;
	// 2.���������ε����ݵ��ļ�ĩβ
	PBYTE pAddrToAdd = m_pSource + pSrcSec[dwSecCount].PointerToRawData;
	memcpy_s(pAddrToAdd, pNewSecInfo->dwRawSize, pNewSecByte, pNewSecInfo->dwRawSize);
	// 3.������Ŀ+1
	pNt->FileHeader.NumberOfSections++;
	// 4. �����ܴ�С�ı�
	pNt->OptionalHeader.SizeOfImage = pSrcSec[dwSecCount].VirtualAddress + pNewSecInfo->dwRawSize;
	return true;
}

//���DLL��text��
void Pek::AddStubText() 
{
	// ���ڴ����ҵ� g_PackInfo
	PPACKINFO pPackInfo = (PPACKINFO)(m_pStub + m_dwPackInfoOffset);
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pSource);
	/*����ɵ�ԭʼOEP��RVA*/
	pPackInfo->dwOldOepRVA = pNt->OptionalHeader.AddressOfEntryPoint;
	/* ���DLL��text��,
	��ȡDLL�Ĵ������Ϣ����ӵ�PE�����
	��ȡ��λ�á���С�������Լ���*/
	PIMAGE_DOS_HEADER pDosStub = (PIMAGE_DOS_HEADER)m_pStub;
	PIMAGE_NT_HEADERS pNtStub = (PIMAGE_NT_HEADERS)(m_pStub + pDosStub->e_lfanew);
	PIMAGE_SECTION_HEADER pText = IMAGE_FIRST_SECTION(pNtStub);
	SECINFO stcSecText = {};
	memcpy_s(stcSecText.pName, 8, "yang", 8);
	stcSecText.dwRawSize = pText->SizeOfRawData;
	stcSecText.dwCharacteristics = pText->Characteristics;
	AddSection(&stcSecText, m_pStub + pText->VirtualAddress);
	/*�����µ�OEP�������text��֮��������(reloc)֮ǰ���*/
	SetNewOep();
	//���DLL��idata��,
	PIMAGE_SECTION_HEADER pIdata = IMAGE_FIRST_SECTION(pNtStub) + 1;
	SECINFO stcSecIdata = {};
	memcpy_s(stcSecIdata.pName, 8, "sidata", 8);
	stcSecIdata.dwRawSize = pIdata->SizeOfRawData;
	stcSecIdata.dwCharacteristics = pIdata->Characteristics;
	//���������
	AddSection(&stcSecIdata, m_pStub + pIdata->VirtualAddress);

}

void Pek::TLS()
{
	/*typedef struct_IMAGE_DATA_DIRECTORY{
		DWORDVirtualAddress;
	DWORDSize;
	}IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;*/

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pSource);
	//����TLS
	PIMAGE_DATA_DIRECTORY pTLS = &pNt->OptionalHeader.DataDirectory[9];
	pTLS->VirtualAddress = g_Stub_pTLS->VirtualAddress+pNt->OptionalHeader.ImageBase;
	//pTLS->Size = g_Stub_pTLS->Size;
}

/*���DLL���ض�λ�ε��µ�exe*/
void Pek::AddStubRelocSeg()
{
	/*DLL���ض�λ������Ϣ*/
	PIMAGE_DOS_HEADER pDosStub = (PIMAGE_DOS_HEADER)m_pStub;
	PIMAGE_NT_HEADERS pNtStub = (PIMAGE_NT_HEADERS)(m_pStub + pDosStub->e_lfanew);
	PIMAGE_SECTION_HEADER pText = IMAGE_FIRST_SECTION(pNtStub);
	//////////////////////////////////////////////////////////////////////////
	g_Stub_pTLS = &pNtStub->OptionalHeader.DataDirectory[9];
	//////////////////////////////////////////////////////////////////////////
	PIMAGE_SECTION_HEADER pSecReloc = pText + pNtStub->FileHeader.NumberOfSections - 1;
	/*�������ε���Ϣ*/
	SECINFO stcSecReloc = {};
	memcpy_s(stcSecReloc.pName, 8, "sreloc", 8);
	stcSecReloc.dwRawSize = pSecReloc->SizeOfRawData;
	stcSecReloc.dwCharacteristics = pSecReloc->Characteristics;
	/*���Stub���ض�λ���ε���EXE*/
	AddSection(&stcSecReloc, m_pStub + pSecReloc->VirtualAddress);
	/*�����µ��ض�λ��Ϣ*/
	SetRelocDataDir();
	
}


// �����µ�OEP
void Pek::SetNewOep() 
{
	// ���ڴ����ҵ� g_PackInfo
	PPACKINFO pPackInfo = (PPACKINFO)(m_pStub + m_dwPackInfoOffset);
	// ����RVA
	DWORD dwNewOep = pPackInfo->dwNewOep - (DWORD)m_pStubBase;
	// �����ƫ��
	DWORD dwOffset = dwNewOep - 0x1000;
	// ����ƫ�ƣ������һ������(��û����ض�λ����)rva�����µ�OEP��RVA
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pSource);
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
	dwNewOep = dwOffset + pSec[pNt->FileHeader.NumberOfSections - 1].VirtualAddress;
	// �����µ�OEP
	pNt->OptionalHeader.AddressOfEntryPoint = dwNewOep;
}

//�����ļ�
bool Pek::SaveAsNewPe(TCHAR *szNewFile) {
	HANDLE hNewFile = CreateFile(szNewFile, GENERIC_READ | GENERIC_WRITE,
						0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hNewFile == INVALID_HANDLE_VALUE)  
		return false;
	DWORD dwWrite = 0;
	WriteFile(hNewFile, m_pSource, m_dwNewSize, &dwWrite, NULL);
	CloseHandle(hNewFile);
	return true;
}


//�ض�λ
bool Pek::FixStubReloc() 
{
	/*���α���Ϣ,ע������������κ��EXE��������Ϣ*/
	PIMAGE_DOS_HEADER pDosExe = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNtExe = (PIMAGE_NT_HEADERS)(m_pSource + pDosExe->e_lfanew);
	PIMAGE_SECTION_HEADER pSecFirExe = IMAGE_FIRST_SECTION(pNtExe);
	// �ȶ�λ��DLL���ض�λ����
	PIMAGE_DOS_HEADER pDosStub = (PIMAGE_DOS_HEADER)m_pStub;
	PIMAGE_NT_HEADERS pNtStub = (PIMAGE_NT_HEADERS)(m_pStub + pDosStub->e_lfanew);
	PIMAGE_SECTION_HEADER pSecFirStub = IMAGE_FIRST_SECTION(pNtStub);
	PIMAGE_DATA_DIRECTORY pDataRelocStub = &pNtStub->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	/*exe��������������RVA*/
	DWORD dwNewSecCode =  pSecFirExe[pNtExe->FileHeader.NumberOfSections - 2].VirtualAddress;
	DWORD dwNewSecIdata = pSecFirExe[pNtExe->FileHeader.NumberOfSections - 1].VirtualAddress;
	/*stub��text�κ�idata�ε�RVA*/
	DWORD dwStubSecCode =  pSecFirStub[0].VirtualAddress;
	DWORD dwStubSecIdata = pSecFirStub[1].VirtualAddress;
	// ��λ�ض�λ���� 
	PIMAGE_BASE_RELOCATION pRelocInfoStub = (PIMAGE_BASE_RELOCATION)(m_pStub + pDataRelocStub->VirtualAddress);
	// ��Ҫ�޸����ض�λ��Ϣ��Ĵ�С
	DWORD dwSizeCount = 0;
	while (pRelocInfoStub->SizeOfBlock != 0)
	{
		PRELOCTYPE arrOffset = (PRELOCTYPE)(pRelocInfoStub + 1);
		DWORD dwSize = sizeof(IMAGE_BASE_RELOCATION);
		DWORD dwCount = (pRelocInfoStub->SizeOfBlock - dwSize) / 2;
		for (DWORD i = 0; i < dwCount; ++i) 
		{
			//								3
			if (arrOffset[i].type == IMAGE_REL_BASED_HIGHLOW)
			{
				/*�ҵ���ֵ*/
				PDWORD pAddr = (PDWORD)(m_pStub + pRelocInfoStub->VirtualAddress + arrOffset[i].offset);
				/*����������
				����ƫ�� = 0x10001234 - load��ַ - stub��Ӧ�λ�ַ = 234
				RVA = ����ƫ��+������RVA = 234 +  exe��Ӧ�λ�ַ
				����ֵ = exeImageBase + RVA;*/
				DWORD dwValueRva = *pAddr - (DWORD)m_pStubBase;
				if (dwValueRva < dwStubSecIdata) 
				{
					*pAddr = dwValueRva - dwStubSecCode + dwNewSecCode + 0x400000;
				}
				else {
					*pAddr = dwValueRva - dwStubSecIdata + dwNewSecIdata + 0x400000;
				}
			}
		}
		// 2. �޸�ÿ����Ļ�ֵpRelocInfoStub->VirtualAddress
		if (pRelocInfoStub->VirtualAddress < dwStubSecIdata)
		{
			pRelocInfoStub->VirtualAddress = dwNewSecCode - dwStubSecCode + pRelocInfoStub->VirtualAddress;
		}
		else {
			pRelocInfoStub->VirtualAddress = dwNewSecIdata - dwStubSecIdata + pRelocInfoStub->VirtualAddress;
		}
		// �����Ѿ��ض�λ���ݸ���
		dwSizeCount += pRelocInfoStub->SizeOfBlock;
		// ��λ����һ������
		pRelocInfoStub = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocInfoStub + pRelocInfoStub->SizeOfBlock);
	}
	return true;
}


/*����Exe�ĵ����ָ��DLL�ĵ����*/
bool Pek::FixAndResetINT() 
{
	/*��EXE��������Ϣ*/
	PIMAGE_DOS_HEADER pDosExe = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNtExe = (PIMAGE_NT_HEADERS)(m_pSource + pDosExe->e_lfanew);
	PIMAGE_SECTION_HEADER pSecFirExe = IMAGE_FIRST_SECTION(pNtExe);
	/*��λStub��������Ϣ*/
	PIMAGE_DOS_HEADER pDosStub = (PIMAGE_DOS_HEADER)m_pStub;
	PIMAGE_NT_HEADERS pNtStub = (PIMAGE_NT_HEADERS)((DWORD)m_pStub + pDosStub->e_lfanew);
	PIMAGE_SECTION_HEADER pSecFirStub = IMAGE_FIRST_SECTION(pNtStub);
	/*�¾ɶλ�ַ����������RVA*/
	/*exe������3������,ֻҪcode�κ�idata�ε�RVA*/
	DWORD dwNewSecCode = pSecFirExe[pNtExe->FileHeader.NumberOfSections - 3].VirtualAddress;
	DWORD dwNewSecIdata = pSecFirExe[pNtExe->FileHeader.NumberOfSections - 2].VirtualAddress;
	/*dll��text�κ�idata�ε�RVA*/
	DWORD dwStubSecCode = pSecFirStub[0].VirtualAddress;
	DWORD dwStubSecIdata = pSecFirStub[1].VirtualAddress;
	/*INT������Ŀ¼��*/
	PIMAGE_DATA_DIRECTORY pDataDirImpStub = &pNtStub->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	/*dll��Ϣ������ʼ��ַ*/
	PIMAGE_IMPORT_DESCRIPTOR pDllInfo = (PIMAGE_IMPORT_DESCRIPTOR)(m_pStub + pDataDirImpStub->VirtualAddress);
	//dll��Ϣ�ṹ��������3��RVAֵ��Ҫ�޸�
	while (pDllInfo->Name) {
		/*���޸������������޸�DLL��Ϣ*/
		PIMAGE_THUNK_DATA parrNameOrOrdir = (PIMAGE_THUNK_DATA)(m_pStub + pDllInfo->OriginalFirstThunk);
		//Ordinal ��ŵ���
		while (parrNameOrOrdir->u1.Ordinal)
		{
			/*ֻ��������RVA����������ŵ���*/
			if (!IMAGE_SNAP_BY_ORDINAL(parrNameOrOrdir->u1.Ordinal))
			{		//���뺯���ĵ�ַ       
				if (parrNameOrOrdir->u1.Function < dwStubSecIdata)
				{
					// ��code��,�λ�ַ+����ƫ��
					parrNameOrOrdir->u1.Function = dwNewSecCode + parrNameOrOrdir->u1.Function - dwStubSecCode;
				}
				else {
					// ��idata��
					parrNameOrOrdir->u1.Function = dwNewSecIdata + parrNameOrOrdir->u1.Function - dwStubSecIdata;
				}
			}
			parrNameOrOrdir++;
		}
		//pDllInfo dll��Ϣ������ʼ��ַ
		PDWORD pTemp[] = { &pDllInfo->Name,&pDllInfo->OriginalFirstThunk,&pDllInfo->FirstThunk };
		//�ܹ���Ҫ��3��,����,��ַ,���
		for (int i = 0; i < 3; ++i)
		{
			if (*pTemp[i] < dwStubSecIdata)
			{
				// ��code��,�λ�ַ+����ƫ��
				*pTemp[i] = dwNewSecCode + *pTemp[i] - dwStubSecCode;
			}
			else {
				// ��idata��
				*pTemp[i] = dwNewSecIdata + *pTemp[i] - dwStubSecIdata;
			}
		}
		/*��һ��DLL*/
		pDllInfo++;
	}

	//exe 
	PIMAGE_DATA_DIRECTORY pDataDirINTStub = &pNtStub->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_DATA_DIRECTORY pDataDirINTExe = &pNtExe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	/*�ȱ���ɵ�INT��RVA*/
	PPACKINFO pPackInfo = (PPACKINFO)((DWORD)m_pStub + m_dwPackInfoOffset);
	pPackInfo->dwOldINTRva = pDataDirINTExe->VirtualAddress;
	/*�����µ�INTΪStub��INT��RVA��size*/
	pDataDirINTExe->Size = pDataDirINTStub->Size;
	//�޸����ֵ = �λ�ַ+����ƫ��
	if (pDataDirINTStub->VirtualAddress < dwStubSecIdata) 
	{
		pDataDirINTExe->VirtualAddress = dwNewSecCode
			+ pDataDirINTStub->VirtualAddress - dwStubSecCode;
	}
	else {
		pDataDirINTExe->VirtualAddress = dwNewSecIdata
			+ pDataDirINTStub->VirtualAddress - dwStubSecIdata;
	}
	/*�µ�IATĿ¼*/
	/*Stub����EXE�ļ���IAT����Ŀ¼��*/
	PIMAGE_DATA_DIRECTORY pDataDirIATStub = &pNtStub->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
	PIMAGE_DATA_DIRECTORY pDataDirIATExe = &pNtExe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
	/*�����µ�IATΪStub��IAT��RVA��size*/
	pDataDirIATExe->Size = pDataDirIATStub->Size;
	if (pDataDirIATStub->VirtualAddress < dwStubSecIdata) {
		pDataDirIATExe->VirtualAddress = dwNewSecCode
			+ pDataDirIATStub->VirtualAddress - dwStubSecCode;
	}
	else {
		pDataDirIATExe->VirtualAddress = dwNewSecIdata
			+ pDataDirIATStub->VirtualAddress - dwStubSecIdata;
	}
	return true;
}

//�����ַ
void Pek::CancleRandomBase() {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(m_pSource + pDos->e_lfanew);
	pNt->OptionalHeader.DllCharacteristics &=
		~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;//0x0040     // DLL can move.
}

//�����޸��ض�λ��Ϣ
void Pek::SetRelocDataDir() 
{
	//�ҵ�exe������ض�λ��Ϣ
	PIMAGE_DOS_HEADER pDosExe = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNtExe = (PIMAGE_NT_HEADERS)(m_pSource + pDosExe->e_lfanew);
	PIMAGE_DATA_DIRECTORY pDataDirRelocExe = &pNtExe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	PIMAGE_SECTION_HEADER pSecFirstExe = IMAGE_FIRST_SECTION(pNtExe);
	//����exe�ļ���ƫ�ƺʹ�С
	PPACKINFO pPackInfo = (PPACKINFO)((DWORD)m_pStub + m_dwPackInfoOffset);
	pPackInfo->dwOldRelocRva = pDataDirRelocExe->VirtualAddress;
	pPackInfo->dwOldRelocSize = pDataDirRelocExe->Size;
	/*Stub���ض�λ����Ϣ�Ѿ���Ϊ���һ������ӵ�β����
	ָ����EXE���һ�����ε�RVA��Ϊ�µ��ض�λĿ¼��RVA
	ָ��Stub���ض�λ��Size��Ϊ�µ��ض�λĿ¼��Size*/
	PIMAGE_SECTION_HEADER pSecRelocExe = pSecFirstExe + pNtExe->FileHeader.NumberOfSections - 1;
	pDataDirRelocExe->VirtualAddress = pSecRelocExe->VirtualAddress;
	/*�ҵ�Stub���ض�λsize��Ϊ�µ��ض�λĿ¼��Size*/
	PIMAGE_DOS_HEADER pDosStub = (PIMAGE_DOS_HEADER)m_pStub;
	PIMAGE_NT_HEADERS pNtStub = (PIMAGE_NT_HEADERS)(m_pStub + pDosStub->e_lfanew);
	PIMAGE_DATA_DIRECTORY pDataDirRelocStub = &pNtStub->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	pDataDirRelocExe->Size = pDataDirRelocStub->Size;
}

//���ܶ�
void Pek::jiami() 
{
	/*NTͷ�ҵ������λ�úʹ�С*/
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(m_pSource + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSecond = IMAGE_FIRST_SECTION(pNt);
	DWORD dwCodeFOA = 0, dwCodeSize = 0;
	//����Ҫ������һ������
	while (true)
	{	
		//����ƫ��							���С
		if (pSecond->PointerToRawData && pSecond->SizeOfRawData)
		{
			dwCodeFOA = pSecond->PointerToRawData;
			dwCodeSize = pSecond->SizeOfRawData;
			break;
		}
		pSecond++;
	}
	/*���ܴ����,4�ֽڼ���1�Σ���Ϊ����δ�С��0x200����ģ�������4�ı���*/
	PDWORD pEncryptBegin = (PDWORD)(m_pSource + dwCodeFOA);
	DWORD dwCount = dwCodeSize / 4;
	int a = 1;
	for (DWORD i = 0; i < dwCount; ++i) {
		a++;
		pEncryptBegin[i] ^= a;
	}
}

//************************************
// FullName:  Pek::ComPressSegment
// Returns:   int -> ѹ������ֽ������Ƕ���
// Parameter: PIMAGE_NT_HEADERS pNt
// Parameter: DWORD dwIndex->���������±�����ֵ
//************************************
int Pek::ComPressSegment(PIMAGE_NT_HEADERS pNt, DWORD dwIndex) {
	/*1.�ȶ�λ������ʼλ��Ϊѹ����ʼ��ַ
	2.�����ļ���СΪѹ���ֽڴ�С
	3.ѹ������ֶ��ȷ�����ʱ��������ٿ�����������
	4.���������ļ���СΪѹ����Ĵ�С0x200�������ֽ���
	5.���θ��ĺ����������ԣ��ֶ�ǰ��
	6.�����ļ���С
	7.�ͷ���ʱ�ռ�
	ע�����������ڴ��ַ�ʹ�С����Ҫ����~~
	*/
	/*���α���ʼ��ַ*/
	PIMAGE_SECTION_HEADER pSecFir = IMAGE_FIRST_SECTION(pNt);
	/*1.Ҫѹ�������α���Ϣ��ַ*/
	PIMAGE_SECTION_HEADER pSecCompress = pSecFir + dwIndex;
	/*1.1�ҵ�Ҫѹ���������׵�ַ->�ļ��ڵ�ַ*/
	PBYTE pAddrSrcCompress = m_pSource + pSecCompress->PointerToRawData;
	/*1.2Ҫѹ�����ֽ���*/
	ULONG uLen = pSecCompress->SizeOfRawData;
	/*2.������Ҫ�Ŀռ��С,����ǻ����С����������ѹ����Ĵ�С*/
	ULONG uLenNeed = compressBound(uLen);
	/*2.1 �����ڴ棬���ڴ��ѹ������ֽ�*/
	PBYTE pAddrDesCompress = nullptr;
	if ((pAddrDesCompress = (PBYTE)malloc(sizeof(BYTE) * uLenNeed)) == NULL) {
		printf("����ռ�ʧ��!\n");
		return -1;
	}
	ZeroMemory(pAddrDesCompress, uLenNeed);
	/*3.ѹ����ע�Ᵽ��ѹ��ǰ���ֽ���*/
	if (compress(pAddrDesCompress, &uLenNeed, pAddrSrcCompress, uLen) != Z_OK) {
		printf("ѹ��ʧ��!\n");
		return -1;
	}
	/*4.���¹������α��PE�ļ�*/
	/*4.1 �Ȱ�ѹ����Ķ����ݿ�������ǰ��*/
	memcpy_s(m_pSource + pSecFir[dwIndex].PointerToRawData,// ��������ǰ����
		pSecFir[dwIndex].SizeOfRawData,// ���δ�С
		pAddrDesCompress, uLenNeed);// ѹ����Ļ�����
									/*4.2 ��������ѹ�����ε��ļ���С*/
	DWORD dwNewSize = (uLenNeed + 0x1ff) / 0x200 * 0x200;
	/*4.3 ��¼ѹ��ǰ���ֵ�����������������ǰ�Ʋ�ֵ��С��ƫ��*/
	DWORD dwDiff = pSecFir[dwIndex].SizeOfRawData - dwNewSize;
	pSecFir[dwIndex].SizeOfRawData = dwNewSize;
	/*���⿪ʼǰ�ƺ�������*/
	/*4.3������������ǰ��,���ı������*/
	if (dwDiff == 0) {
		return (int)uLenNeed;
	}
	DWORD dwSecCount = pNt->FileHeader.NumberOfSections;
	for (DWORD i = dwIndex + 1; i < dwSecCount; ++i) {
		/*Ŀ���ַ*/
		PBYTE pAddrDes = m_pSource // PE�ļ��׵�ַ
			+ pSecFir[i].PointerToRawData - dwDiff;// �����׵�ַǰ��dwDiff
												   /*Դ��ַ*/
		PBYTE pAddrSrc = m_pSource // PE�ļ��׵�ַ
			+ pSecFir[i].PointerToRawData; // ��ǰ���εĶ���ƫ��
										   /*������С = ��ǰ�εĴ�С*/
		DWORD dwSize = pSecFir[i].SizeOfRawData;
		memcpy_s(pAddrDes, dwSize, pAddrSrc, dwSize);
		/*���Ķ���ƫ�Ƶ�ַ*/
		pSecFir[i].PointerToRawData -= dwDiff;
	}
	/*�����ļ���С*/
	m_dwNewSize -= dwDiff;
	/*����λ���ƶ�������Ϣ����*/
	/*�ͷſռ�*/
	if (pAddrDesCompress != nullptr) 
	{
		free(pAddrDesCompress);
		pAddrDesCompress = nullptr;
	}
	return (int)uLenNeed;
}



//ѹ������
bool Pek::CompressCodeSeg() 
{
	/*���ҵ�����Σ��еĳ����1���ֲ����Ǵ����*/
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(m_pSource + pDos->e_lfanew);
	/*���Ҵ����*/
	PIMAGE_SECTION_HEADER pSecFir = IMAGE_FIRST_SECTION(pNt);

	DWORD dwCount = pNt->FileHeader.NumberOfSections;
	DWORD dwIndex = 0;
	for (; dwIndex < dwCount; ++dwIndex) 
	{
		if (pSecFir[dwIndex].SizeOfRawData != 0)
		{
			break;
		}
	}
	/*ѹ�������
	dwSizeUnComѹ��ǰ���ֽ���
	dwSizeComedѹ������ֽ���
	����stub�����ڽ�ѹ*/
	DWORD dwSizeUnCom = pSecFir[dwIndex].SizeOfRawData;
	DWORD dwSizeComed = ComPressSegment(pNt, dwIndex);
	/*��������ֵ���ݸ�packinfo*/
	PPACKINFO pPackinfo = (PPACKINFO)(m_pStub + m_dwPackInfoOffset);
	pPackinfo->dwCodeSizeComed = dwSizeComed;
	pPackinfo->dwCodeSizeUnCom = dwSizeUnCom;
	return true;
}

//��DLL��������Ϣ���������µ�EXE������
void Pek::CopyInfo() {
	/*Stub����ʼ���ε�ַ*/
	PIMAGE_DOS_HEADER pDosStub = (PIMAGE_DOS_HEADER)m_pStub;
	PIMAGE_NT_HEADERS pNtStub = (PIMAGE_NT_HEADERS)((DWORD)m_pStub + pDosStub->e_lfanew);
	PIMAGE_SECTION_HEADER pFirSecStub = IMAGE_FIRST_SECTION(pNtStub);
	/*��EXE����ʼ���ε�ַ*/
	PIMAGE_DOS_HEADER pDosExe = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNtExe = (PIMAGE_NT_HEADERS)((DWORD)m_pSource + pDosExe->e_lfanew);
	PIMAGE_SECTION_HEADER pFirSecExe = IMAGE_FIRST_SECTION(pNtExe);
	/*����������ʼ��ַ*/
	/*������3�����Σ�
	��1�����1������reloc
	��2��idata��
	��3��text��*/
	PIMAGE_SECTION_HEADER pNewSec = pFirSecExe + pNtExe->FileHeader.NumberOfSections - 3;
	/*text*/
	memcpy_s(m_pSource + pNewSec->PointerToRawData,// Ŀ��
		pNewSec->SizeOfRawData,// ��С
		m_pStub + pFirSecStub->VirtualAddress,// Դ
		pFirSecStub->SizeOfRawData);// ��С
									/*idata*/
	memcpy_s(m_pSource + (pNewSec + 1)->PointerToRawData,// Ŀ��
		(pNewSec + 1)->SizeOfRawData,// ��С
		m_pStub + (pFirSecStub + 1)->VirtualAddress,// Դ
		(pFirSecStub + 1)->SizeOfRawData);// ��С
										  /*reloc,��stub�ĵ�4�����Σ���exe�����ĵ�3������*/
	memcpy_s(m_pSource + (pNewSec + 2)->PointerToRawData,// Ŀ��
		(pNewSec + 2)->SizeOfRawData,// ��С
		m_pStub + (pFirSecStub + 3)->VirtualAddress,// Դ
		(pFirSecStub + 3)->SizeOfRawData);// ��С
	PPACKINFO zise = (PPACKINFO)pNtExe->FileHeader.NumberOfSections;
}


