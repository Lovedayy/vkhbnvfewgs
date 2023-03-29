﻿
// SnifferDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "Sniffer.h"
#include "SnifferDlg.h"
#include "afxdialogex.h"

#include "CAdpDlg.h"
#include "CFilterDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();
	CAdpDlg m_adpDlg;
	CFilterDlg m_filterDlg;

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CSnifferDlg 对话框
CSnifferDlg::CSnifferDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_SNIFFER_DIALOG, pParent)
	, m_adpDlg(this)
	, m_filterDlg(this)
	, m_tcpnum(_T(""))
	, m_udpnum(_T(""))
	, m_arpum(_T(""))
	, m_icmpnum(_T(""))
	, m_httpnum(_T(""))
	, m_dnsnum(_T(""))
	, m_totalnum(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CSnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, m_edit1);
	DDX_Text(pDX, IDC_EDIT2, m_tcpnum);
	DDX_Text(pDX, IDC_EDIT3, m_udpnum);
	DDX_Text(pDX, IDC_EDIT4, m_arpum);
	DDX_Text(pDX, IDC_EDIT5, m_icmpnum);
	DDX_Text(pDX, IDC_EDIT6, m_httpnum);
	DDX_Text(pDX, IDC_EDIT7, m_dnsnum);
	DDX_Text(pDX, IDC_EDIT8, m_totalnum);
	DDX_Control(pDX, IDC_LIST1, m_list1);
	DDX_Control(pDX, IDC_TREE1, m_tree1);
}

BEGIN_MESSAGE_MAP(CSnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_EN_CHANGE(IDC_EDIT1, &CSnifferDlg::OnEnChangeEdit1)
//	ON_COMMAND(ID_32771, &CSnifferDlg::OnAdp)
//	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &CSnifferDlg::OnLvnItemchangedList1)
//ON_COMMAND(ID_32772, &CSnifferDlg::On32772)
//ON_COMMAND(ID_32772, &CSnifferDlg::OnFilter)
END_MESSAGE_MAP()


// CSnifferDlg 消息处理程序

BOOL CSnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
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

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	m_list1.SetExtendedStyle(m_list1.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);// 为列表视图控件添加全行选中和栅格风格
	m_list1.InsertColumn(0, _T("序号"), LVCFMT_CENTER, 50);
	m_list1.InsertColumn(1, _T("时间"), LVCFMT_CENTER, 120);
	m_list1.InsertColumn(2, _T("源MAC地址"), LVCFMT_CENTER, 120);
	m_list1.InsertColumn(3, _T("目的MAC地址"), LVCFMT_CENTER, 120);
	m_list1.InsertColumn(4, _T("长度"), LVCFMT_CENTER, 50);
	m_list1.InsertColumn(5, _T("协议"), LVCFMT_CENTER, 70);
	m_list1.InsertColumn(6, _T("源IP地址"), LVCFMT_CENTER, 120);
	m_list1.InsertColumn(7, _T("目的IP地址"), LVCFMT_CENTER, 120);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CSnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CSnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CSnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CSnifferDlg::OnEnChangeEdit1()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}

