#include "stdio.h"
#include "Pek.h"
#include <windows.h>
#define ZLIB_WINAPI
#include "zlib\\zlib.h"
#pragma comment(lib,"zlib/zlibstat.lib")
// Release编译时加上下面这句预编译指令
//#pragma comment(linker,"/NODEFAULTLIB:msvcrtd.lib")

Pek::Pek() {
}


Pek::~Pek() {
}

//读文件
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

//打开DLL文件
bool Pek::OpenStubFile(TCHAR* szDll) {
	HMODULE hStub = LoadLibrary(szDll);
	if (hStub == NULL) 
		return false;
	/*保存一下pPackInfo的偏移值，后面有用*/
	PPACKINFO pPackInfo = (PPACKINFO)GetProcAddress((HMODULE)hStub, "g_PackInfo");
	m_dwPackInfoOffset = (DWORD)pPackInfo - (DWORD)hStub;
	m_pStubBase = (PBYTE)hStub;
	/*拷贝该DLL的内容到堆区，方便读写*/
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hStub;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + (DWORD)hStub);
	DWORD dwSize = (pNt->OptionalHeader.SizeOfImage + 0x0fff) / 0x1000 * 0x01000;
	m_pStub = (PBYTE)VirtualAlloc(NULL, dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	memcpy_s(m_pStub, dwSize, hStub, dwSize);
	FreeLibrary(hStub);
	return true;
}

//添加区段
bool Pek::AddSection(SECINFO* pNewSecInfo, PBYTE pNewSecByte) 
{
	// 增大原空间大小，用于存放新的区段
	PBYTE pNew = (PBYTE)VirtualAlloc(NULL, m_dwNewSize + pNewSecInfo->dwRawSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	//填充内存块0
	ZeroMemory(pNew, m_dwNewSize + pNewSecInfo->dwRawSize);
	memcpy_s(pNew, m_dwNewSize, m_pSource, m_dwNewSize);
	m_dwNewSize += pNewSecInfo->dwRawSize;
	VirtualFree(m_pSource, 0, MEM_RELEASE);
	m_pSource = pNew;
	// 1.空间已经增加了，增加新的区段信息
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pSource);
	PIMAGE_SECTION_HEADER pSrcSec = IMAGE_FIRST_SECTION(pNt);
	//原始段的数目
	DWORD dwSecCount = pNt->FileHeader.NumberOfSections;
	//依次向后面添加 段,
	// 1.1段名称
	memcpy_s(pSrcSec[dwSecCount].Name, 8, pNewSecInfo->pName, 8);
	// 1.2段RawAddr
	pSrcSec[dwSecCount].PointerToRawData = pSrcSec[dwSecCount - 1].PointerToRawData + pSrcSec[dwSecCount - 1].SizeOfRawData;
	// 1.3段RSize
	pSrcSec[dwSecCount].SizeOfRawData = pNewSecInfo->dwRawSize;
	// 1.4段VSize
	pSrcSec[dwSecCount].Misc.VirtualSize = pNewSecInfo->dwRawSize;
	// 1.5段RVA
	pSrcSec[dwSecCount].VirtualAddress = pSrcSec[dwSecCount - 1].VirtualAddress
		+ (pSrcSec[dwSecCount - 1].Misc.VirtualSize + 0x0fff) / 0x1000 * 0x1000;
	// 1.1段保护属性
	pSrcSec[dwSecCount].Characteristics = pNewSecInfo->dwCharacteristics;
	// 2.拷贝新区段的内容到文件末尾
	PBYTE pAddrToAdd = m_pSource + pSrcSec[dwSecCount].PointerToRawData;
	memcpy_s(pAddrToAdd, pNewSecInfo->dwRawSize, pNewSecByte, pNewSecInfo->dwRawSize);
	// 3.区段数目+1
	pNt->FileHeader.NumberOfSections++;
	// 4. 镜像总大小改变
	pNt->OptionalHeader.SizeOfImage = pSrcSec[dwSecCount].VirtualAddress + pNewSecInfo->dwRawSize;
	return true;
}

//添加DLL的text段
void Pek::AddStubText() 
{
	// 在内存中找到 g_PackInfo
	PPACKINFO pPackInfo = (PPACKINFO)(m_pStub + m_dwPackInfoOffset);
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pSource);
	/*保存旧的原始OEP的RVA*/
	pPackInfo->dwOldOepRVA = pNt->OptionalHeader.AddressOfEntryPoint;
	/* 添加DLL的text段,
	获取DLL的代码段信息，添加到PE段最后
	获取其位置、大小、段属性即可*/
	PIMAGE_DOS_HEADER pDosStub = (PIMAGE_DOS_HEADER)m_pStub;
	PIMAGE_NT_HEADERS pNtStub = (PIMAGE_NT_HEADERS)(m_pStub + pDosStub->e_lfanew);
	PIMAGE_SECTION_HEADER pText = IMAGE_FIRST_SECTION(pNtStub);
	SECINFO stcSecText = {};
	memcpy_s(stcSecText.pName, 8, "yang", 8);
	stcSecText.dwRawSize = pText->SizeOfRawData;
	stcSecText.dwCharacteristics = pText->Characteristics;
	AddSection(&stcSecText, m_pStub + pText->VirtualAddress);
	/*设置新的OEP，在添加text段之后，其他段(reloc)之前完成*/
	SetNewOep();
	//添加DLL的idata段,
	PIMAGE_SECTION_HEADER pIdata = IMAGE_FIRST_SECTION(pNtStub) + 1;
	SECINFO stcSecIdata = {};
	memcpy_s(stcSecIdata.pName, 8, "sidata", 8);
	stcSecIdata.dwRawSize = pIdata->SizeOfRawData;
	stcSecIdata.dwCharacteristics = pIdata->Characteristics;
	//添加新区段
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
	//拷贝TLS
	PIMAGE_DATA_DIRECTORY pTLS = &pNt->OptionalHeader.DataDirectory[9];
	pTLS->VirtualAddress = g_Stub_pTLS->VirtualAddress+pNt->OptionalHeader.ImageBase;
	//pTLS->Size = g_Stub_pTLS->Size;
}

/*添加DLL的重定位段到新的exe*/
void Pek::AddStubRelocSeg()
{
	/*DLL的重定位区段信息*/
	PIMAGE_DOS_HEADER pDosStub = (PIMAGE_DOS_HEADER)m_pStub;
	PIMAGE_NT_HEADERS pNtStub = (PIMAGE_NT_HEADERS)(m_pStub + pDosStub->e_lfanew);
	PIMAGE_SECTION_HEADER pText = IMAGE_FIRST_SECTION(pNtStub);
	//////////////////////////////////////////////////////////////////////////
	g_Stub_pTLS = &pNtStub->OptionalHeader.DataDirectory[9];
	//////////////////////////////////////////////////////////////////////////
	PIMAGE_SECTION_HEADER pSecReloc = pText + pNtStub->FileHeader.NumberOfSections - 1;
	/*新增区段的信息*/
	SECINFO stcSecReloc = {};
	memcpy_s(stcSecReloc.pName, 8, "sreloc", 8);
	stcSecReloc.dwRawSize = pSecReloc->SizeOfRawData;
	stcSecReloc.dwCharacteristics = pSecReloc->Characteristics;
	/*添加Stub的重定位区段到新EXE*/
	AddSection(&stcSecReloc, m_pStub + pSecReloc->VirtualAddress);
	/*设置新的重定位信息*/
	SetRelocDataDir();
	
}


// 设置新的OEP
void Pek::SetNewOep() 
{
	// 在内存中找到 g_PackInfo
	PPACKINFO pPackInfo = (PPACKINFO)(m_pStub + m_dwPackInfoOffset);
	// 先求RVA
	DWORD dwNewOep = pPackInfo->dwNewOep - (DWORD)m_pStubBase;
	// 求段内偏移
	DWORD dwOffset = dwNewOep - 0x1000;
	// 段内偏移，加最后一个区段(还没添加重定位区段)rva就是新的OEP的RVA
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pSource);
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
	dwNewOep = dwOffset + pSec[pNt->FileHeader.NumberOfSections - 1].VirtualAddress;
	// 设置新的OEP
	pNt->OptionalHeader.AddressOfEntryPoint = dwNewOep;
}

//保存文件
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


//重定位
bool Pek::FixStubReloc() 
{
	/*区段表信息,注意是添加新区段后的EXE的区段信息*/
	PIMAGE_DOS_HEADER pDosExe = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNtExe = (PIMAGE_NT_HEADERS)(m_pSource + pDosExe->e_lfanew);
	PIMAGE_SECTION_HEADER pSecFirExe = IMAGE_FIRST_SECTION(pNtExe);
	// 先定位到DLL的重定位区段
	PIMAGE_DOS_HEADER pDosStub = (PIMAGE_DOS_HEADER)m_pStub;
	PIMAGE_NT_HEADERS pNtStub = (PIMAGE_NT_HEADERS)(m_pStub + pDosStub->e_lfanew);
	PIMAGE_SECTION_HEADER pSecFirStub = IMAGE_FIRST_SECTION(pNtStub);
	PIMAGE_DATA_DIRECTORY pDataRelocStub = &pNtStub->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	/*exe新增的两个区段RVA*/
	DWORD dwNewSecCode =  pSecFirExe[pNtExe->FileHeader.NumberOfSections - 2].VirtualAddress;
	DWORD dwNewSecIdata = pSecFirExe[pNtExe->FileHeader.NumberOfSections - 1].VirtualAddress;
	/*stub的text段和idata段的RVA*/
	DWORD dwStubSecCode =  pSecFirStub[0].VirtualAddress;
	DWORD dwStubSecIdata = pSecFirStub[1].VirtualAddress;
	// 定位重定位区段 
	PIMAGE_BASE_RELOCATION pRelocInfoStub = (PIMAGE_BASE_RELOCATION)(m_pStub + pDataRelocStub->VirtualAddress);
	// 需要修复的重定位信息块的大小
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
				/*找到该值*/
				PDWORD pAddr = (PDWORD)(m_pStub + pRelocInfoStub->VirtualAddress + arrOffset[i].offset);
				/*修正其内容
				段内偏移 = 0x10001234 - load基址 - stub相应段基址 = 234
				RVA = 段内偏移+新增段RVA = 234 +  exe相应段基址
				最终值 = exeImageBase + RVA;*/
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
		// 2. 修复每个块的基值pRelocInfoStub->VirtualAddress
		if (pRelocInfoStub->VirtualAddress < dwStubSecIdata)
		{
			pRelocInfoStub->VirtualAddress = dwNewSecCode - dwStubSecCode + pRelocInfoStub->VirtualAddress;
		}
		else {
			pRelocInfoStub->VirtualAddress = dwNewSecIdata - dwStubSecIdata + pRelocInfoStub->VirtualAddress;
		}
		// 计算已经重定位数据个数
		dwSizeCount += pRelocInfoStub->SizeOfBlock;
		// 定位到下一个区块
		pRelocInfoStub = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocInfoStub + pRelocInfoStub->SizeOfBlock);
	}
	return true;
}


/*把新Exe的导入表指向DLL的导入表*/
bool Pek::FixAndResetINT() 
{
	/*新EXE的区段信息*/
	PIMAGE_DOS_HEADER pDosExe = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNtExe = (PIMAGE_NT_HEADERS)(m_pSource + pDosExe->e_lfanew);
	PIMAGE_SECTION_HEADER pSecFirExe = IMAGE_FIRST_SECTION(pNtExe);
	/*定位Stub的区段信息*/
	PIMAGE_DOS_HEADER pDosStub = (PIMAGE_DOS_HEADER)m_pStub;
	PIMAGE_NT_HEADERS pNtStub = (PIMAGE_NT_HEADERS)((DWORD)m_pStub + pDosStub->e_lfanew);
	PIMAGE_SECTION_HEADER pSecFirStub = IMAGE_FIRST_SECTION(pNtStub);
	/*新旧段基址，用于修正RVA*/
	/*exe新增的3个区段,只要code段和idata段的RVA*/
	DWORD dwNewSecCode = pSecFirExe[pNtExe->FileHeader.NumberOfSections - 3].VirtualAddress;
	DWORD dwNewSecIdata = pSecFirExe[pNtExe->FileHeader.NumberOfSections - 2].VirtualAddress;
	/*dll的text段和idata段的RVA*/
	DWORD dwStubSecCode = pSecFirStub[0].VirtualAddress;
	DWORD dwStubSecIdata = pSecFirStub[1].VirtualAddress;
	/*INT的数据目录表*/
	PIMAGE_DATA_DIRECTORY pDataDirImpStub = &pNtStub->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	/*dll信息数组起始地址*/
	PIMAGE_IMPORT_DESCRIPTOR pDllInfo = (PIMAGE_IMPORT_DESCRIPTOR)(m_pStub + pDataDirImpStub->VirtualAddress);
	//dll信息结构体里面有3个RVA值需要修复
	while (pDllInfo->Name) {
		/*先修复名称数组再修复DLL信息*/
		PIMAGE_THUNK_DATA parrNameOrOrdir = (PIMAGE_THUNK_DATA)(m_pStub + pDllInfo->OriginalFirstThunk);
		//Ordinal 序号导入
		while (parrNameOrOrdir->u1.Ordinal)
		{
			/*只修正名称RVA，不修正序号导入*/
			if (!IMAGE_SNAP_BY_ORDINAL(parrNameOrOrdir->u1.Ordinal))
			{		//导入函数的地址       
				if (parrNameOrOrdir->u1.Function < dwStubSecIdata)
				{
					// 在code段,段基址+段内偏移
					parrNameOrOrdir->u1.Function = dwNewSecCode + parrNameOrOrdir->u1.Function - dwStubSecCode;
				}
				else {
					// 在idata段
					parrNameOrOrdir->u1.Function = dwNewSecIdata + parrNameOrOrdir->u1.Function - dwStubSecIdata;
				}
			}
			parrNameOrOrdir++;
		}
		//pDllInfo dll信息数组起始地址
		PDWORD pTemp[] = { &pDllInfo->Name,&pDllInfo->OriginalFirstThunk,&pDllInfo->FirstThunk };
		//总共需要修3次,名称,地址,序号
		for (int i = 0; i < 3; ++i)
		{
			if (*pTemp[i] < dwStubSecIdata)
			{
				// 在code段,段基址+段内偏移
				*pTemp[i] = dwNewSecCode + *pTemp[i] - dwStubSecCode;
			}
			else {
				// 在idata段
				*pTemp[i] = dwNewSecIdata + *pTemp[i] - dwStubSecIdata;
			}
		}
		/*下一个DLL*/
		pDllInfo++;
	}

	//exe 
	PIMAGE_DATA_DIRECTORY pDataDirINTStub = &pNtStub->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_DATA_DIRECTORY pDataDirINTExe = &pNtExe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	/*先保存旧的INT的RVA*/
	PPACKINFO pPackInfo = (PPACKINFO)((DWORD)m_pStub + m_dwPackInfoOffset);
	pPackInfo->dwOldINTRva = pDataDirINTExe->VirtualAddress;
	/*设置新的INT为Stub的INT的RVA和size*/
	pDataDirINTExe->Size = pDataDirINTStub->Size;
	//修复后的值 = 段基址+段内偏移
	if (pDataDirINTStub->VirtualAddress < dwStubSecIdata) 
	{
		pDataDirINTExe->VirtualAddress = dwNewSecCode
			+ pDataDirINTStub->VirtualAddress - dwStubSecCode;
	}
	else {
		pDataDirINTExe->VirtualAddress = dwNewSecIdata
			+ pDataDirINTStub->VirtualAddress - dwStubSecIdata;
	}
	/*新的IAT目录*/
	/*Stub和新EXE文件的IAT数据目录表*/
	PIMAGE_DATA_DIRECTORY pDataDirIATStub = &pNtStub->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
	PIMAGE_DATA_DIRECTORY pDataDirIATExe = &pNtExe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
	/*设置新的IAT为Stub的IAT的RVA和size*/
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

//随机基址
void Pek::CancleRandomBase() {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(m_pSource + pDos->e_lfanew);
	pNt->OptionalHeader.DllCharacteristics &=
		~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;//0x0040     // DLL can move.
}

//保存修改重定位信息
void Pek::SetRelocDataDir() 
{
	//找到exe程序的重定位信息
	PIMAGE_DOS_HEADER pDosExe = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNtExe = (PIMAGE_NT_HEADERS)(m_pSource + pDosExe->e_lfanew);
	PIMAGE_DATA_DIRECTORY pDataDirRelocExe = &pNtExe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	PIMAGE_SECTION_HEADER pSecFirstExe = IMAGE_FIRST_SECTION(pNtExe);
	//保存exe文件的偏移和大小
	PPACKINFO pPackInfo = (PPACKINFO)((DWORD)m_pStub + m_dwPackInfoOffset);
	pPackInfo->dwOldRelocRva = pDataDirRelocExe->VirtualAddress;
	pPackInfo->dwOldRelocSize = pDataDirRelocExe->Size;
	/*Stub的重定位表信息已经作为最后一个段添加到尾段了
	指定新EXE最后一个区段的RVA作为新的重定位目录的RVA
	指定Stub的重定位的Size作为新的重定位目录的Size*/
	PIMAGE_SECTION_HEADER pSecRelocExe = pSecFirstExe + pNtExe->FileHeader.NumberOfSections - 1;
	pDataDirRelocExe->VirtualAddress = pSecRelocExe->VirtualAddress;
	/*找到Stub的重定位size作为新的重定位目录的Size*/
	PIMAGE_DOS_HEADER pDosStub = (PIMAGE_DOS_HEADER)m_pStub;
	PIMAGE_NT_HEADERS pNtStub = (PIMAGE_NT_HEADERS)(m_pStub + pDosStub->e_lfanew);
	PIMAGE_DATA_DIRECTORY pDataDirRelocStub = &pNtStub->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	pDataDirRelocExe->Size = pDataDirRelocStub->Size;
}

//加密段
void Pek::jiami() 
{
	/*NT头找到代码段位置和大小*/
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(m_pSource + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSecond = IMAGE_FIRST_SECTION(pNt);
	DWORD dwCodeFOA = 0, dwCodeSize = 0;
	//必须要跳过第一个区段
	while (true)
	{	
		//计算偏移							与大小
		if (pSecond->PointerToRawData && pSecond->SizeOfRawData)
		{
			dwCodeFOA = pSecond->PointerToRawData;
			dwCodeSize = pSecond->SizeOfRawData;
			break;
		}
		pSecond++;
	}
	/*加密代码段,4字节加密1次，因为代码段大小是0x200对齐的，所以是4的倍数*/
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
// Returns:   int -> 压缩后的字节数，非对齐
// Parameter: PIMAGE_NT_HEADERS pNt
// Parameter: DWORD dwIndex->区段数组下标索引值
//************************************
int Pek::ComPressSegment(PIMAGE_NT_HEADERS pNt, DWORD dwIndex) {
	/*1.先定位区段起始位置为压缩开始地址
	2.区段文件大小为压缩字节大小
	3.压缩后的字段先放在临时缓冲区里，再拷贝到区段内
	4.更改区段文件大小为压缩后的大小0x200对齐后的字节数
	5.依次更改后面区段属性，分段前移
	6.更改文件大小
	7.释放临时空间
	注：区段虚拟内存地址和大小不需要更改~~
	*/
	/*区段表起始地址*/
	PIMAGE_SECTION_HEADER pSecFir = IMAGE_FIRST_SECTION(pNt);
	/*1.要压缩的区段表信息地址*/
	PIMAGE_SECTION_HEADER pSecCompress = pSecFir + dwIndex;
	/*1.1找到要压缩的区段首地址->文件内地址*/
	PBYTE pAddrSrcCompress = m_pSource + pSecCompress->PointerToRawData;
	/*1.2要压缩的字节数*/
	ULONG uLen = pSecCompress->SizeOfRawData;
	/*2.计算需要的空间大小,这个是缓冲大小，不是最终压缩后的大小*/
	ULONG uLenNeed = compressBound(uLen);
	/*2.1 申请内存，用于存放压缩后的字节*/
	PBYTE pAddrDesCompress = nullptr;
	if ((pAddrDesCompress = (PBYTE)malloc(sizeof(BYTE) * uLenNeed)) == NULL) {
		printf("分配空间失败!\n");
		return -1;
	}
	ZeroMemory(pAddrDesCompress, uLenNeed);
	/*3.压缩，注意保存压缩前后字节数*/
	if (compress(pAddrDesCompress, &uLenNeed, pAddrSrcCompress, uLen) != Z_OK) {
		printf("压缩失败!\n");
		return -1;
	}
	/*4.重新构建区段表和PE文件*/
	/*4.1 先把压缩后的段内容拷贝到当前段*/
	memcpy_s(m_pSource + pSecFir[dwIndex].PointerToRawData,// 拷贝到当前区段
		pSecFir[dwIndex].SizeOfRawData,// 区段大小
		pAddrDesCompress, uLenNeed);// 压缩后的缓冲区
									/*4.2 重新设置压缩区段的文件大小*/
	DWORD dwNewSize = (uLenNeed + 0x1ff) / 0x200 * 0x200;
	/*4.3 记录压缩前后差值，方便后面区段依次前移差值大小的偏移*/
	DWORD dwDiff = pSecFir[dwIndex].SizeOfRawData - dwNewSize;
	pSecFir[dwIndex].SizeOfRawData = dwNewSize;
	/*从这开始前移后面区段*/
	/*4.3后续区段依次前移,并改变段属性*/
	if (dwDiff == 0) {
		return (int)uLenNeed;
	}
	DWORD dwSecCount = pNt->FileHeader.NumberOfSections;
	for (DWORD i = dwIndex + 1; i < dwSecCount; ++i) {
		/*目标地址*/
		PBYTE pAddrDes = m_pSource // PE文件首地址
			+ pSecFir[i].PointerToRawData - dwDiff;// 区段首地址前移dwDiff
												   /*源地址*/
		PBYTE pAddrSrc = m_pSource // PE文件首地址
			+ pSecFir[i].PointerToRawData; // 当前区段的段首偏移
										   /*拷贝大小 = 当前段的大小*/
		DWORD dwSize = pSecFir[i].SizeOfRawData;
		memcpy_s(pAddrDes, dwSize, pAddrSrc, dwSize);
		/*更改段首偏移地址*/
		pSecFir[i].PointerToRawData -= dwDiff;
	}
	/*更改文件大小*/
	m_dwNewSize -= dwDiff;
	/*到此位置移动区段信息结束*/
	/*释放空间*/
	if (pAddrDesCompress != nullptr) 
	{
		free(pAddrDesCompress);
		pAddrDesCompress = nullptr;
	}
	return (int)uLenNeed;
}



//压缩区段
bool Pek::CompressCodeSeg() 
{
	/*先找到代码段，有的程序第1部分并不是代码段*/
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(m_pSource + pDos->e_lfanew);
	/*查找代码段*/
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
	/*压缩代码段
	dwSizeUnCom压缩前的字节数
	dwSizeComed压缩后的字节数
	传给stub，用于解压*/
	DWORD dwSizeUnCom = pSecFir[dwIndex].SizeOfRawData;
	DWORD dwSizeComed = ComPressSegment(pNt, dwIndex);
	/*将这两个值传递给packinfo*/
	PPACKINFO pPackinfo = (PPACKINFO)(m_pStub + m_dwPackInfoOffset);
	pPackinfo->dwCodeSizeComed = dwSizeComed;
	pPackinfo->dwCodeSizeUnCom = dwSizeUnCom;
	return true;
}

//把DLL的区段信息都拷贝到新的EXE区段里
void Pek::CopyInfo() {
	/*Stub的起始区段地址*/
	PIMAGE_DOS_HEADER pDosStub = (PIMAGE_DOS_HEADER)m_pStub;
	PIMAGE_NT_HEADERS pNtStub = (PIMAGE_NT_HEADERS)((DWORD)m_pStub + pDosStub->e_lfanew);
	PIMAGE_SECTION_HEADER pFirSecStub = IMAGE_FIRST_SECTION(pNtStub);
	/*新EXE的起始区段地址*/
	PIMAGE_DOS_HEADER pDosExe = (PIMAGE_DOS_HEADER)m_pSource;
	PIMAGE_NT_HEADERS pNtExe = (PIMAGE_NT_HEADERS)((DWORD)m_pSource + pDosExe->e_lfanew);
	PIMAGE_SECTION_HEADER pFirSecExe = IMAGE_FIRST_SECTION(pNtExe);
	/*新增区段起始地址*/
	/*新增了3个区段，
	减1是最后1个区段reloc
	减2是idata段
	减3是text段*/
	PIMAGE_SECTION_HEADER pNewSec = pFirSecExe + pNtExe->FileHeader.NumberOfSections - 3;
	/*text*/
	memcpy_s(m_pSource + pNewSec->PointerToRawData,// 目的
		pNewSec->SizeOfRawData,// 大小
		m_pStub + pFirSecStub->VirtualAddress,// 源
		pFirSecStub->SizeOfRawData);// 大小
									/*idata*/
	memcpy_s(m_pSource + (pNewSec + 1)->PointerToRawData,// 目的
		(pNewSec + 1)->SizeOfRawData,// 大小
		m_pStub + (pFirSecStub + 1)->VirtualAddress,// 源
		(pFirSecStub + 1)->SizeOfRawData);// 大小
										  /*reloc,是stub的第4个区段，是exe新增的第3个区段*/
	memcpy_s(m_pSource + (pNewSec + 2)->PointerToRawData,// 目的
		(pNewSec + 2)->SizeOfRawData,// 大小
		m_pStub + (pFirSecStub + 3)->VirtualAddress,// 源
		(pFirSecStub + 3)->SizeOfRawData);// 大小
	PPACKINFO zise = (PPACKINFO)pNtExe->FileHeader.NumberOfSections;
}


