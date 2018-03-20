#include <stdio.h>
#include "Pek.h"


bool PackInterface(TCHAR* szExe, TCHAR* szDll, TCHAR * szNewExe)
{
	Pek obj;
	// 读入两个文件
	if (!obj.OpenSourceFile(szExe)) 
	{
		return 0;
	}
	if (!obj.OpenStubFile(szDll))
	{
		return 0;
	}
	
	// 加密代码段
	obj.jiami();
	//压缩
	obj.CompressCodeSeg();
	//添加区段
	obj.AddStubText();
	//修复DLL的重定位
	obj.FixStubReloc();
	//添加重定位区段
	obj.AddStubRelocSeg();
	/*把新Exe的导入表指向Stub的导入表*/
	obj.FixAndResetINT();
	/*把stub的区段信息都拷贝到新的EXE区段里*/
	obj.CopyInfo();
	// 去除重定位属性
	//obj.TLS();
	/*保存为新的PE文件*/
	obj.SaveAsNewPe(szNewExe);
	return true;
}

int main() 
{
	// 1. 打开文件,将文件读取到内存.
	// CreateFile,ReadFile.
	printf("请拖入一个需要加壳的程序: ");
	char path[MAX_PATH];
	gets_s(path, MAX_PATH);
	if (PackInterface(path, "DLL.dll", "f:\\cc_.exe"))
	{
		printf("生成文件成功文件 f:\\cc_.exe \n");
	}
	else
	{
		printf("生成文件失败\n");
	}
	
	
	system("pause");

	return 0;
}