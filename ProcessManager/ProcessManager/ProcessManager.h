
// ProcessManager.h: главный файл заголовка для приложения PROJECT_NAME
//

#pragma once

#ifndef __AFXWIN_H__
	#error "включить pch.h до включения этого файла в PCH"
#endif

#include "resource.h"		// основные символы


// CProcessManagerApp:
// Сведения о реализации этого класса: ProcessManager.cpp
//

class CProcessManagerApp : public CWinApp
{
public:
	CProcessManagerApp();

// Переопределение
public:
	virtual BOOL InitInstance();

// Реализация

	DECLARE_MESSAGE_MAP()
};

extern CProcessManagerApp theApp;
