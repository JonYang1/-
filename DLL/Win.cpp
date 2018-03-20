#include "stdafx.h"
#include <windows.h>
#include "resource.h"
#include <Commctrl.h>
#pragma comment(lib,"Comctl32.lib")

// 主窗口回调函数
INT_PTR CALLBACK DialogProc(
	_In_ HWND   hwndDlg,
	_In_ UINT   uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
);
// command 消息
INT_PTR CALLBACK OnCommandMsg(
	_In_ HWND   hwndDlg,
	_In_ UINT   uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
);

int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nShowCmd)
{
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL, DialogProc);
	return 0;
}



INT_PTR CALLBACK DialogProc(
	HWND   hwndDlg, UINT   uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{

	case WM_COMMAND:
		return OnCommandMsg(hwndDlg, uMsg, wParam, lParam);
	default:
		return 0;
	}
	return TRUE;
}




// command 消息
INT_PTR CALLBACK OnCommandMsg(
	_In_ HWND   hwndDlg,
	_In_ UINT   uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
)
{
	WORD wId = LOWORD(wParam);
	switch (wId)
	{
	case IDC_BUTTON1:
	{
		char szText =0;

		GetDlgItemText(hwndDlg,IDC_EDIT1,(LPWSTR)szText,0);
		if (szText!=123456)
		{
			MessageBoxW(hwndDlg, L"不可以进入", L"密码不正确", MB_OK);
			Sleep(2000);
			EndDialog(hwndDlg, 0);
		}
		MessageBoxW(hwndDlg, L"可以进入", L"密码正确", MB_OK);
	}
	break;
	default:
		return false;
	}
	return true;
}

