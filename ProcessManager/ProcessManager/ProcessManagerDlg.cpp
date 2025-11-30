
// ProcessManagerDlg.cpp: файл реализации
//

#include "pch.h"
#include "afxdialogex.h"
#include "framework.h"
#include "ProcessManager.h"
#include "ProcessManagerDlg.h"
#include "tlhelp32.h"
#include "wincrypt.h"
#include "wininet.h"
#include <windows.h>
#include <shellapi.h>





#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// Диалоговое окно CAboutDlg используется для описания сведений о приложении

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Данные диалогового окна
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // поддержка DDX/DDV

// Реализация
protected:
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButtonRefresh();
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
	ON_BN_CLICKED(IDC_BUTTON_REFRESH, &CAboutDlg::OnBnClickedButtonRefresh)
END_MESSAGE_MAP()


// Диалоговое окно CProcessManagerDlg
CProcessManagerDlg::CProcessManagerDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_PROCESSMANAGER_DIALOG, pParent)
{
	m_trayData = { 0 };
	m_buttonCount = 0;

	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CProcessManagerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	//  DDX_Control(pDX, IDC_LIST_PROCESSES, xdfgh);
	DDX_Control(pDX, IDC_BUTTON_REFRESH, m_btnRefresh);
	DDX_Control(pDX, IDC_BUTTON_ENDTASK, m_btnEndTask);
	DDX_Control(pDX, IDC_BUTTON_ADMIN, m_btnAdmin);
	DDX_Control(pDX, IDC_BUTTON_SEND, m_btnSend);
	DDX_Control(pDX, IDC_BUTTON_GET, m_btnGet);
	DDX_Control(pDX, IDC_LIST_PROCESSES, m_listProcesses);
	DDX_Control(pDX, IDOK, m_btnOk);
}

BEGIN_MESSAGE_MAP(CProcessManagerDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST_PROCESSES, &CProcessManagerDlg::OnLvnItemchangedListProcesses)
	ON_BN_CLICKED(IDC_BUTTON_REFRESH, &CProcessManagerDlg::OnBnClickedButtonRefresh)
	ON_BN_CLICKED(IDC_BUTTON_ENDTASK, &CProcessManagerDlg::OnBnClickedButtonEndtask)
	ON_BN_CLICKED(IDC_BUTTON_ADMIN, &CProcessManagerDlg::OnBnClickedButtonAdmin)
	ON_BN_CLICKED(IDC_BUTTON_SEND, &CProcessManagerDlg::OnBnClickedButtonSend)

	// события ресайза
	ON_WM_SIZE()
	ON_WM_GETMINMAXINFO()

	// для спрятки в трей
	ON_WM_CLOSE()
	ON_MESSAGE(WM_TRAYICON, &CProcessManagerDlg::OnTrayIcon)

	// атво обновление
	ON_WM_TIMER()
	ON_BN_CLICKED(IDOK, &CProcessManagerDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// Обработчики сообщений CProcessManagerDlg

BOOL CProcessManagerDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Добавление пункта "О программе..." в системное меню.

	// IDM_ABOUTBOX должен быть в пределах системной команды.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Задает значок для этого диалогового окна.  Среда делает это автоматически,
	//  если главное окно приложения не является диалоговым
	SetIcon(m_hIcon, TRUE);			// Крупный значок
	SetIcon(m_hIcon, FALSE);		// Мелкий значок
	
	// Добавляем колонки в ListView
	m_listProcesses.InsertColumn(0, _T("PID"), LVCFMT_LEFT, 80);
	m_listProcesses.InsertColumn(1, _T("Имя процесса"), LVCFMT_LEFT, 300);


	// выделение всей строки
	DWORD exStyle = m_listProcesses.GetExtendedStyle();
	exStyle |= LVS_EX_FULLROWSELECT;  // Выделение всей строки
	exStyle |= LVS_EX_GRIDLINES;      // Линии сетки
	m_listProcesses.SetExtendedStyle(exStyle);


	// Сохраняем оригинальные размеры контролов
	m_listProcesses.GetWindowRect(&m_originalListRect);
	ScreenToClient(&m_originalListRect);

	//Сохраняем размеры кнопок
	CWnd* buttons[] = { &m_btnRefresh, &m_btnEndTask, &m_btnAdmin, &m_btnSend, &m_btnGet, &m_btnOk };
	m_buttonCount = 6;

	for (int i = 0; i < m_buttonCount; i++)
	{
		buttons[i]->GetWindowRect(&m_originalButtonsRect[i]);
		ScreenToClient(&m_originalButtonsRect[i]);
	}

	CRect rect;
	GetClientRect(&rect);
	UpdateLayout(rect.Width(), rect.Height());


	// получаем процессы
	RefreshProcessList();

	// если обновляем кнопку, если под админом
	UpdateAdminButton();	   	

	// Запускаем автообновление 
	StartAutoRefresh();
			
	return TRUE;  // возврат значения TRUE, если фокус не передан элементу управления
}


void CProcessManagerDlg::OnSize(UINT nType, int cx, int cy)
{
	CDialogEx::OnSize(nType, cx, cy);
	UpdateLayout(cx, cy);
}

// Устанавливаем минимальный размер окна
void CProcessManagerDlg::OnGetMinMaxInfo(MINMAXINFO* lpMMI)
{
	lpMMI->ptMinTrackSize.x = 600; // минимальная ширина
	lpMMI->ptMinTrackSize.y = 400; // минимальная высота
	CDialogEx::OnGetMinMaxInfo(lpMMI);
}

// Обновляем layout
void CProcessManagerDlg::UpdateLayout(int cx, int cy)
{
	if (m_listProcesses.m_hWnd == NULL)
		return;

	// ListView занимает 70% ширины и всю высоту кроме места для кнопок
	int listWidth = cx * 70 / 100;
	m_listProcesses.SetWindowPos(NULL, 0, 0, listWidth, cy - 40, SWP_NOZORDER);

	// Кнопки размещаем справа
	int buttonWidth = cx - listWidth - 10;
	int buttonHeight = 25;
	int buttonSpacing = 5;
	int startY = 10;

	CWnd* buttons[] = { &m_btnRefresh, &m_btnEndTask, &m_btnAdmin, &m_btnSend, &m_btnGet,  &m_btnOk};

	for (int i = 0; i < m_buttonCount; i++)
	{
		int yPos = startY + i * (buttonHeight + buttonSpacing);
		buttons[i]->SetWindowPos(NULL, listWidth + 5, yPos, buttonWidth - 10, buttonHeight, SWP_NOZORDER);
	}
}


// Обработчик системных команд
void CProcessManagerDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == SC_CLOSE)
	{
		OnClose();
	}
	else if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// При добавлении кнопки свертывания в диалоговое окно нужно воспользоваться приведенным ниже кодом,
//  чтобы нарисовать значок.  Для приложений MFC, использующих модель документов или представлений,
//  это автоматически выполняется рабочей областью.

void CProcessManagerDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // контекст устройства для рисования

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Выравнивание значка по центру клиентского прямоугольника
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Нарисуйте значок
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// Система вызывает эту функцию для получения отображения курсора при перемещении
//  свернутого окна.
HCURSOR CProcessManagerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CProcessManagerDlg::OnLvnItemchangedListProcesses(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: добавьте свой код обработчика уведомлений
	*pResult = 0;
}

// Обновляем RefreshProcessList для оптимизации
void CProcessManagerDlg::RefreshProcessList()
{
	// Запрещаем обновление во время уже идущего обновления
	if (m_isRefreshing)
		return;

	m_isRefreshing = true;

	// ЗАПРЕЩАЕМ перерисовку ListView
	m_listProcesses.SetRedraw(FALSE);

	// Сохраняем выбранный элемент чтобы восстановить позицию
	int selectedIndex = m_listProcesses.GetSelectionMark();
	CString selectedPid;
	if (selectedIndex != -1)
	{
		selectedPid = m_listProcesses.GetItemText(selectedIndex, 0);
	}

	// Очищаем список
	m_listProcesses.DeleteAllItems();

	// Получаем снимок процессов
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		m_isRefreshing = false;
		return;
	}
		
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Перечисляем процессы
	if (Process32First(hSnapshot, &pe32))
	{
		int index = 0;
		int newSelectedIndex = -1;

		do
		{
			// Добавляем процесс в список
			CString strPid;
			strPid.Format(_T("%d"), pe32.th32ProcessID);

			int itemIndex = m_listProcesses.InsertItem(index, strPid);
			m_listProcesses.SetItemText(itemIndex, 1, pe32.szExeFile);

			// Восстанавливаем выделение
			if (strPid == selectedPid)
			{
				newSelectedIndex = index;
			}

			index++;
		} while (Process32Next(hSnapshot, &pe32));

		// Восстанавливаем выделенный элемент
		if (newSelectedIndex != -1)
		{
			m_listProcesses.SetItemState(newSelectedIndex, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
			m_listProcesses.EnsureVisible(newSelectedIndex, FALSE);
		}
	}

	CloseHandle(hSnapshot);

	// РАЗРЕШАЕМ перерисовку и принудительно обновляем
	m_listProcesses.SetRedraw(TRUE);
	m_listProcesses.Invalidate();
	m_listProcesses.UpdateWindow();

	m_isRefreshing = false;
}

bool CProcessManagerDlg::IsRunningAsAdmin()
{
	BOOL isAdmin = FALSE;
	PSID adminGroup = NULL;

	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
	if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup))
	{
		if (!CheckTokenMembership(NULL, adminGroup, &isAdmin))
		{
			isAdmin = FALSE;
		}
		FreeSid(adminGroup);
	}
	return isAdmin == TRUE;
}

void CProcessManagerDlg::UpdateAdminButton()
{
	if (IsRunningAsAdmin())
	{
		m_btnAdmin.EnableWindow(FALSE);
		m_btnAdmin.SetWindowText(_T("Запущено под админом"));
	}
	else
	{
		m_btnAdmin.EnableWindow(TRUE);
		m_btnAdmin.SetWindowText(_T("Restart with Admin"));
	}
}

CString CProcessManagerDlg::GetDllsForProcess(DWORD pid)
{
	CString result;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 me32;
		me32.dwSize = sizeof(MODULEENTRY32);

		if (Module32First(hSnapshot, &me32))
		{
			do
			{
				if (result.GetLength() > 0)
					result += _T(";");
				result += me32.szModule;
			} while (Module32Next(hSnapshot, &me32));
		}

		CloseHandle(hSnapshot);
	}

	return result;
}

CStringA CProcessManagerDlg::EncryptString(const CStringA& input)
{
	CStringA result = input;

	// Используем текущую дату как ключ
	SYSTEMTIME st;
	GetLocalTime(&st);
	// ключ на основе даты: год + месяц + день 
	BYTE key = (BYTE)((st.wYear + st.wMonth + st.wDay) % 256);

	// Шифруем
	for (int i = 0; i < result.GetLength(); i++)
	{
		result.GetBuffer()[i] ^= key + i; // Добавляем индекс для уникальности
	}

	// Кодируем в base64
	DWORD base64Len = 0;
	CryptBinaryToStringA((BYTE*)result.GetString(), result.GetLength(),
		CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64Len);

	CStringA base64Result;
	CryptBinaryToStringA((BYTE*)result.GetString(), result.GetLength(),
		CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
		base64Result.GetBufferSetLength(base64Len), &base64Len);
	base64Result.ReleaseBufferSetLength(base64Len - 1);

	return base64Result;
}

CStringA CProcessManagerDlg::DecryptString(const CStringA& input)
{
	// Декодируем из base64
	DWORD binaryLen = 0;
	CryptStringToBinaryA(input, input.GetLength(), CRYPT_STRING_BASE64,
		NULL, &binaryLen, NULL, NULL);

	CStringA binaryData;
	CryptStringToBinaryA(input, input.GetLength(), CRYPT_STRING_BASE64,
		(BYTE*)binaryData.GetBufferSetLength(binaryLen), &binaryLen, NULL, NULL);
	binaryData.ReleaseBufferSetLength(binaryLen);

	// Используем ТУ ЖЕ ДАТУ для дешифровки (должна быть известна)
	SYSTEMTIME st;
	GetLocalTime(&st);
	BYTE key = (BYTE)((st.wYear + st.wMonth + st.wDay + st.wHour + st.wMinute) % 256);

	// Дешифруем
	CStringA result = binaryData;
	for (int i = 0; i < result.GetLength(); i++)
	{
		result.GetBuffer()[i] ^= key + i;
	}

	return result;
}

CStringA CProcessManagerDlg::GenerateRID()
{
	// Генерируем уникальный идентификатор на основе времени и случайных чисел
	CStringA rid;
	SYSTEMTIME st;
	GetSystemTime(&st);

	rid.Format("%04d%02d%02d%02d%02d%02d%03d%04d",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
		st.wMilliseconds, rand() % 10000);

	return rid;
}

void CProcessManagerDlg::OnBnClickedButtonRefresh()
{
	// TODO: добавьте свой код обработчика уведомлений
	RefreshProcessList();
}

void CAboutDlg::OnBnClickedButtonRefresh()
{
	// TODO: добавьте свой код обработчика уведомлений
	
}

void CProcessManagerDlg::OnBnClickedButtonEndtask()
{
	// TODO: добавьте свой код обработчика уведомлений
	auto selected_list_index = m_listProcesses.GetSelectionMark();
	if (selected_list_index < 0)
	{
		AfxMessageBox(_T("Выберите процесс"));
		return;
	}

	// Получаем PID выбранного процесса
	CString str_process_id = m_listProcesses.GetItemText(selected_list_index, 0);
	DWORD process_id = _ttoi(str_process_id);

	CString message_text;
	message_text.Format(_T("Вы уверены, что хотите завершить процесс: PID %d?"), process_id);


	if (AfxMessageBox(message_text, MB_YESNO | MB_ICONQUESTION) == IDYES)
	{
		HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, process_id);
		if (hProcess)
		{
			if (TerminateProcess(hProcess, 0))
			{
				AfxMessageBox(_T("Процесс завершен."));
				RefreshProcessList();
			}
			else
			{
				AfxMessageBox(_T("Ошибка при завершении процесса."));
			}
			CloseHandle(hProcess);
		}
		else
		{
			AfxMessageBox(_T("Невозможно открыть процесс. Ошибка доступа."));
		}
	}	   
}

void CProcessManagerDlg::OnBnClickedButtonAdmin()
{
	// ОСВОБОЖДАЕМ!!!! мьютекс перед перезапуском, а то не получится
	if (AfxGetApp())
	{
		// Закрываем мьютекс приложения
		HANDLE hMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, _T("ProcessManagerUniqueInstance"));
		if (hMutex)
		{
			ReleaseMutex(hMutex);
			CloseHandle(hMutex);
		}
	}

	// Получаем путь к текущему исполняемому файлу
	TCHAR szPath[MAX_PATH];
	if (GetModuleFileName(NULL, szPath, MAX_PATH))
	{
		// Запускаем себя с правами администратора
		SHELLEXECUTEINFO sei = { sizeof(sei) };
		sei.lpVerb = _T("runas"); // ключевое слово для запроса прав администратора
		sei.lpFile = szPath;
		sei.hwnd = NULL;
		sei.nShow = SW_NORMAL;

		if (ShellExecuteEx(&sei))
		{
			// Закрываем текущее приложение
			CDialogEx::OnOK();
		}
		else
		{
			DWORD error = GetLastError();
			if (error == ERROR_CANCELLED)
			{
				AfxMessageBox(_T("Для выполнения этой операции требуются права администратора."));
			}
			else
			{
				CString errorMsg;
				errorMsg.Format(_T("Не удалось запуститься от имени администратора. Код ошибки: %d"), error);
				AfxMessageBox(errorMsg);
			}
		}
	}
}

void CProcessManagerDlg::OnBnClickedButtonSend()
{
	// выбранный процесс
	int selectedIndex = m_listProcesses.GetSelectionMark();
	if (selectedIndex == -1)
	{
		AfxMessageBox(_T("Выберите процесс"));
		return;
	}

	// PID выбранного процесса
	CString strPid = m_listProcesses.GetItemText(selectedIndex, 0);
	DWORD pid = _ttoi(strPid);

	// DLL для процесса
	CString dlls = GetDllsForProcess(pid);

	if (dlls.IsEmpty())
	{
		AfxMessageBox(_T("Библиотеки DLL для этого процесса не найдены, или доступ запрещен"));
		return;
	}

	// Генерируем RID и шифруем данные, в качестве ключа используетяс текущ. дата, хотя можно было и волшебное слово
	CStringA rid = GenerateRID();
	CStringA encryptedData = EncryptString(CStringA(dlls));

	// Отправляем на сервер
	if (SendDataToServer(rid, encryptedData))
	{
		CString message;
		message.Format(_T("Данные отправлены успешно!\nRID: %s\nПроцесс: %s (PID: %d)"),
						  CString(rid).GetString(),
						  m_listProcesses.GetItemText(selectedIndex, 1).GetString(),
						  pid);
		AfxMessageBox(message);
	}

}

void CProcessManagerDlg::OnBnClickedButtonGet()
{
	// Генерируем RID для запроса
	CStringA rid = GenerateRID();

	// Получаем данные с сервера
	if (GetDataFromServer(rid))
	{
		// Данные будут расшифрованы с той же датой (текущее время)
		AfxMessageBox(_T("Данные успешно получены с сервера"));
	}
}

BOOL CProcessManagerDlg::SendDataToServer(const CStringA& rid, const CStringA& encryptedData)
{
	HINTERNET hInternet = InternetOpen(_T("ProcessManager"), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (!hInternet)
	{
		AfxMessageBox(_T("Не удалось подключиться к интернету"));
		return FALSE;
	}

	HINTERNET hConnect = InternetConnectA(hInternet, "172.245.127.93", INTERNET_DEFAULT_HTTP_PORT,
		NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (!hConnect)
	{
		InternetCloseHandle(hInternet);
		AfxMessageBox(_T("Не удалось подключиться к серверу"));
		return FALSE;
	}

	HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", "/p/applicants.php",
		NULL, NULL, NULL, INTERNET_FLAG_RELOAD, 0);
	if (!hRequest)
	{
		InternetCloseHandle(hConnect);
		InternetCloseHandle(hInternet);
		AfxMessageBox(_T("Не удалось создать HTTP-запрос"));
		return FALSE;
	}

	// Формируем JSON данные
	CStringA jsonData;
	jsonData.Format("{\"cmd\": 1, \"rid\": \"%s\", \"data\": \"%s\"}",
					rid.GetString(),
					encryptedData.GetString());

	// Устанавливаем заголовки
	CStringA headers = "Content-Type: application/json\r\n";

	// Отправляем запрос
	BOOL bSent = HttpSendRequestA(hRequest, headers, headers.GetLength(),
		(LPVOID)jsonData.GetString(), jsonData.GetLength());

	if (bSent)
	{
		// Читаем ответ
		CHAR buffer[4096];
		DWORD bytesRead;
		CStringA response;

		while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0)
		{
			buffer[bytesRead] = 0;
			response += buffer;
		}

		// Парсим ответ (простая проверка)
		if (response.Find("\"status\":\"true\"") != -1)
		{
			AfxMessageBox(_T("Данные мотправлены на сервер"));
		}
		else
		{
			CString msg;
			msg.Format(_T("Server response: %s"),
						CString(response).GetString());
			AfxMessageBox(msg);
		}
	}
	else
	{
		DWORD error = GetLastError();
		CString errorMsg;
		errorMsg.Format(_T("Ошибка отправки данных на сервер. Error: %d"), error);
		AfxMessageBox(errorMsg);
	}

	InternetCloseHandle(hRequest);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hInternet);

	return bSent;
}


BOOL CProcessManagerDlg::GetDataFromServer(const CStringA& rid)
{
	
	HINTERNET hInternet = InternetOpen(_T("ProcessManager"), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (!hInternet)
	{
		AfxMessageBox(_T("Не удалось подключиться к интернету"));
		return FALSE;
	}

	HINTERNET hConnect = InternetConnectA(hInternet, "172.245.127.93", INTERNET_DEFAULT_HTTP_PORT,
		NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (!hConnect)
	{
		InternetCloseHandle(hInternet);
		AfxMessageBox(_T("Не удалось подключиться к серверу"));
		return FALSE;
	}
	
	

	HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", "/p/applicants.php",
		NULL, NULL, NULL, INTERNET_FLAG_RELOAD, 0);
	if (!hRequest)
	{
		InternetCloseHandle(hConnect);
		InternetCloseHandle(hInternet);
		AfxMessageBox(_T("Не удалось создать HTTP-запрос"));
		return FALSE;
	}

	// Формируем JSON данные для запроса
	CStringA jsonData;
	jsonData.Format("{\"cmd\": 2, \"rid\": \"%s\"}",
					rid.GetString());

	CStringA headers = "Content-Type: application/json\r\n";

	// Отправляем запрос
	BOOL bSent = HttpSendRequestA(hRequest, headers, headers.GetLength(),
		(LPVOID)jsonData.GetString(), jsonData.GetLength());

	if (bSent)
	{
		// Читаем ответ
		CHAR buffer[4096];
		DWORD bytesRead;
		CStringA response;

		while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0)
		{
			buffer[bytesRead] = 0;
			response += buffer;
		}

		// Парсим JSON ответ и расшифровываем данные
		int dataStart = response.Find("\"data\":\"");
		if (dataStart != -1)
		{
			dataStart += 8; // Длина "\"data\":\""
			int dataEnd = response.Find("\"", dataStart);
			if (dataEnd != -1)
			{
				CStringA encryptedData = response.Mid(dataStart, dataEnd - dataStart);
				CStringA decryptedData = DecryptString(encryptedData);

				CString message;
				message.Format(_T("Получены данные от сервера:\n\n%s"),
								CString(decryptedData).GetString());
				AfxMessageBox(message);
			}
			else
			{
				AfxMessageBox(_T("Не правильный формат ответа с сервера"));
			}
		}
		else
		{
			CString msg;
			msg.Format(_T("Ответ сервеера: %s"),
						CString(response).GetString());
			AfxMessageBox(msg);
		}
	}
	else
	{
		DWORD error = GetLastError();
		CString errorMsg;
		errorMsg.Format(_T("Ошибка получения данных с сервера. Error: %d"), error);
		AfxMessageBox(errorMsg);
	}

	InternetCloseHandle(hRequest);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hInternet);

	return bSent;
}


// Создание иконки в трее
void CProcessManagerDlg::CreateTrayIcon()
{
	m_trayData.cbSize = sizeof(NOTIFYICONDATA);
	m_trayData.hWnd = m_hWnd;
	m_trayData.uID = 1;
	m_trayData.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
	m_trayData.uCallbackMessage = WM_TRAYICON;
	m_trayData.hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	_tcscpy_s(m_trayData.szTip, _T("Process Manager"));

	Shell_NotifyIcon(NIM_ADD, &m_trayData);
}

void CProcessManagerDlg::RemoveTrayIcon()
{
	Shell_NotifyIcon(NIM_DELETE, &m_trayData);
}

// Обработчик сообщений от трея
LRESULT CProcessManagerDlg::OnTrayIcon(WPARAM wParam, LPARAM lParam)
{
	if (lParam == WM_RBUTTONUP)
	{
		ShowContextMenu();
	}
	else if (lParam == WM_LBUTTONDBLCLK)
	{
		ShowWindow(SW_SHOW);
		RemoveTrayIcon();
	}
	return 0;
}

// Контекстное меню трея
void CProcessManagerDlg::ShowContextMenu()
{
	CMenu menu;
	menu.CreatePopupMenu();
	menu.AppendMenu(MF_STRING, 1, _T("Show"));
	menu.AppendMenu(MF_STRING, 2, _T("Exit"));

	POINT pt;
	GetCursorPos(&pt);

	int cmd = menu.TrackPopupMenu(TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, this);

	if (cmd == 1)
	{
		ShowWindow(SW_SHOW);
		RemoveTrayIcon();
	}
	else if (cmd == 2)
	{
		RemoveTrayIcon();
		CDialogEx::OnOK();
	}
}

// Обработчик закрытия окна - сворачиваем в трей
void CProcessManagerDlg::OnClose()
{
	ShowWindow(SW_HIDE);
	CreateTrayIcon();
}


// Запуск автообновления
void CProcessManagerDlg::StartAutoRefresh()
{
	SetTimer(1, 3000, NULL); // Обновление каждую секунду
}

// Остановка автообновления
void CProcessManagerDlg::StopAutoRefresh()
{
	KillTimer(1);
}

// Обработчик таймера
void CProcessManagerDlg::OnTimer(UINT_PTR nIDEvent)
{
	if (nIDEvent == 1)
	{
		// Автоматическое обновление списка процессов
		RefreshProcessList();
	}

	CDialogEx::OnTimer(nIDEvent);
}


void CProcessManagerDlg::OnBnClickedOk()
{
	// TODO: добавьте свой код обработчика уведомлений
	CDialogEx::OnOK();
}
