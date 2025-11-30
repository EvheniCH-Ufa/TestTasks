
// ProcessManagerDlg.h: файл заголовка
//

#pragma once

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wininet.lib") 
#pragma comment(lib, "psapi.lib")


// Диалоговое окно CProcessManagerDlg
class CProcessManagerDlg : public CDialogEx
{

public:
	CProcessManagerDlg(CWnd* pParent = nullptr);	// стандартный конструктор


	// Определяем пользовательское сообщение
	static const UINT WM_TRAYICON = WM_USER + 1;
		

// Данные диалогового окна
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_PROCESSMANAGER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// поддержка DDX/DDV


private:
	void RefreshProcessList();
	bool IsRunningAsAdmin();
	void UpdateAdminButton();

	CString GetDllsForProcess(DWORD pid);

	// блок для шифрования 
	CStringA EncryptString(const CStringA& input);
	CStringA DecryptString(const CStringA& input);
	CStringA GenerateRID();

	// blok otpravki/priemki dannyh s servera na server
	BOOL SendDataToServer(const CStringA& rid, const CStringA& encryptedData);
	BOOL GetDataFromServer(const CStringA& rid);

	void CreateTrayIcon();
	void RemoveTrayIcon();
	void ShowContextMenu();
	NOTIFYICONDATA m_trayData = {0};


	// авто-обновлени е в таймере
	void StartAutoRefresh();
	void StopAutoRefresh();

		
protected:
	HICON m_hIcon;

	// Созданные функции схемы сообщений
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

	// для ресайза
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnGetMinMaxInfo(MINMAXINFO* lpMMI);

	// для сист трея
	afx_msg LRESULT OnTrayIcon(WPARAM wParam, LPARAM lParam);
	afx_msg void OnClose();

	// для обновления процессов в таймере
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	bool m_isRefreshing = false;


public:
	// компоненты
	CButton m_btnRefresh;
	CButton m_btnEndTask;
	CButton m_btnAdmin;
	CButton m_btnSend;
	CButton m_btnGet;
	CButton m_btnOk;

	CListCtrl m_listProcesses;


	afx_msg void OnLvnItemchangedListProcesses(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnBnClickedButtonRefresh();
	afx_msg void OnBnClickedButtonEndtask();
	afx_msg void OnBnClickedButtonAdmin();
	afx_msg void OnBnClickedButtonSend();
	afx_msg void OnBnClickedButtonGet();


	void UpdateLayout(int cx, int cy);
	CRect m_originalListRect;
	CRect m_originalButtonsRect[6];
	int m_buttonCount = 0;
	afx_msg void OnBnClickedOk();
	
};
