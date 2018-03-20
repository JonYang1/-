#include <stdio.h>
#include "Pek.h"


bool PackInterface(TCHAR* szExe, TCHAR* szDll, TCHAR * szNewExe)
{
	Pek obj;
	// ���������ļ�
	if (!obj.OpenSourceFile(szExe)) 
	{
		return 0;
	}
	if (!obj.OpenStubFile(szDll))
	{
		return 0;
	}
	
	// ���ܴ����
	obj.jiami();
	//ѹ��
	obj.CompressCodeSeg();
	//�������
	obj.AddStubText();
	//�޸�DLL���ض�λ
	obj.FixStubReloc();
	//����ض�λ����
	obj.AddStubRelocSeg();
	/*����Exe�ĵ����ָ��Stub�ĵ����*/
	obj.FixAndResetINT();
	/*��stub��������Ϣ���������µ�EXE������*/
	obj.CopyInfo();
	// ȥ���ض�λ����
	//obj.TLS();
	/*����Ϊ�µ�PE�ļ�*/
	obj.SaveAsNewPe(szNewExe);
	return true;
}

int main() 
{
	// 1. ���ļ�,���ļ���ȡ���ڴ�.
	// CreateFile,ReadFile.
	printf("������һ����Ҫ�ӿǵĳ���: ");
	char path[MAX_PATH];
	gets_s(path, MAX_PATH);
	if (PackInterface(path, "DLL.dll", "f:\\cc_.exe"))
	{
		printf("�����ļ��ɹ��ļ� f:\\cc_.exe \n");
	}
	else
	{
		printf("�����ļ�ʧ��\n");
	}
	
	
	system("pause");

	return 0;
}