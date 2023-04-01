
// SnifferDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "Sniffer.h"
#include "SnifferDlg.h"
#include "afxdialogex.h"
#include "head.h"

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
	//CAdpDlg m_adpDlg;
	//CFilterDlg m_filterDlg;

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
	ON_COMMAND(ID_Adp, &CSnifferDlg::OnAdp)
	ON_COMMAND(ID_Filter, &CSnifferDlg::OnFilter)
	ON_COMMAND(ID_Start, &CSnifferDlg::OnStart)
	ON_COMMAND(ID_Stop, &CSnifferDlg::OnStop)
	ON_COMMAND(ID_Save, &CSnifferDlg::OnSave)
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

	// 初始化数据包链表
	m_localDataList.RemoveAll();

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

void CSnifferDlg::OnAdp()
{
	// TODO: 在此添加命令处理程序代码
	CAdpDlg adpdlg;
	if (adpdlg.DoModal() == IDOK)
	{
		m_pDevice = adpdlg.returnd();
	}
}

void CSnifferDlg::OnFilter()
{
	// TODO: 在此添加命令处理程序代码
	CFilterDlg filterdlg;
	if (filterdlg.DoModal() == IDOK)
	{
		int len = WideCharToMultiByte(CP_ACP, 0, filterdlg.GetFilterName(), -1, NULL, 0, NULL, NULL);
		WideCharToMultiByte(CP_ACP, 0, filterdlg.GetFilterName(), -1, m_filtername, len, NULL, NULL);
	}
}

DWORD __stdcall CSnifferDlg::CapturePacket(LPVOID lpParam)
{
	CSnifferDlg* pDlg = (CSnifferDlg*)lpParam;
	pcap_t* pCap;
	char    strErrorBuf[PCAP_ERRBUF_SIZE];
	int res;
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	u_int netmask;
	struct bpf_program fcode;

	if ((pCap = pcap_open_live(pDlg->m_pDevice->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, strErrorBuf)) == NULL)
	{
		return -1;
	}

	if (pDlg->m_pDevice->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in*)(pDlg->m_pDevice->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;
	//编译过滤器
	if (pcap_compile(pCap, &fcode, pDlg->m_filtername, 1, netmask) < 0)
	{
		AfxMessageBox(_T("请设置过滤规则"));
		return -1;
	}
	//设置过滤器
	if (pcap_setfilter(pCap, &fcode) < 0)
		return -1;

	while ((res = pcap_next_ex(pCap, &pkt_header, &pkt_data)) >= 0)
	{

		if (res == 0)
			continue;
		if (!pDlg->m_shouldStop)
			break;
		CSnifferDlg* pDlg = (CSnifferDlg*)AfxGetApp()->GetMainWnd();
		pDlg->ShowPacketList(pkt_header, pkt_data);
		pDlg = NULL;
	}

	pcap_close(pCap);
	pDlg = NULL;
	return 1;
}

//数据包另存为
int CSnifferDlg::savefile()
{
	CFileFind findfile;
	if (findfile.FindFile(CString(filepath)) == NULL)
	{
		MessageBox(_T("没有找到文件保存路径"));
		return -1;
	}
	//false 表示另存为
	CFileDialog FileDlg(FALSE, _T("pkt"), NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT);
	FileDlg.m_ofn.lpstrInitialDir = _T("c:\\");
	if (FileDlg.DoModal() == IDOK)
		CopyFile(CString(filepath), FileDlg.GetPathName(), TRUE);
	return 0;
}

void CSnifferDlg::OnSave()
{
	// TODO: 在此添加命令处理程序代码
}

void CSnifferDlg::OnStop()
{
	// 没有线程不需要处理
	if (m_hThread == NULL)
		return;

	// 标记需要停止抓包
	m_shouldStop = TRUE;

	// 等待线程结束
	WaitForSingleObject(m_hThread, INFINITE);
	// 关闭 pcap 实例
	if (m_adhandle)
		pcap_close(m_adhandle);
	m_adhandle = NULL;

	// 释放设备列表
	if (m_allDevs)
		pcap_freealldevs(m_allDevs);
	m_allDevs = NULL;

	// 更新UI状态
	GetDlgItem(ID_Start)->EnableWindow(TRUE);
	GetDlgItem(ID_Stop)->EnableWindow(FALSE);

	// 重置标记
	m_shouldStop = FALSE;
}

void CSnifferDlg::OnStart()
{
	// 是否保存上次抓包数据
	if (!m_localDataList.IsEmpty())
	{
		if (MessageBox(_T("是否存储当前抓包数据？"), _T("警告"), MB_YESNO) == IDYES)
			this->OnSave();
	}

	/* init */
	this->n_pkt = 0; //重新计数
	this->m_localDataList.RemoveAll(); //列表清空
	this->m_netDataList.RemoveAll();
	memset(&(this->pkcount_T), 0, sizeof(struct pktcount));

	// 清空界面
	m_list1.DeleteAllItems();
	m_tree1.DeleteAllItems();
	m_edit1.SetWindowText(_T(""));

	if (pkcount_T.n_sum == -1)
		return;

	// 获取网卡列表
	pcap_if_t* alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		MessageBox(_T("获取网卡列表失败"));
		return;
	}

	// 选择网卡
	CAdpDlg adpDlg;
	if (adpDlg.DoModal() != IDOK)
		return;
	m_pDevice = adpDlg.returnd();

	// 选择协议过滤
	CFilterDlg filterDlg;
	if (filterDlg.DoModal() != IDOK)
		return;
	CString filterStr = filterDlg.GetFilterName();

	// 打开网卡并设置过滤规则
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	pcap_t* adhandle = pcap_open_live(m_pDevice->name, 65536, 1, 1000, errbuf);
	if (adhandle == NULL)
	{
		MessageBox(_T("网卡打开失败"));
		return;
	}

	// 添加 PCAP_OPENFLAG_PROMISCUOUS 标志
	if (pcap_setmode(adhandle, PCAP_OPENFLAG_PROMISCUOUS) != 0)
	{
		MessageBox(_T("设置网卡为混杂模式失败"));
		pcap_close(adhandle);
		return;
	}

	bpf_program filterCode;
	CStringA filterStrA(filterStr); // 将 CString 转换成 CStringA
	if (pcap_compile(adhandle, &filterCode, filterStrA, 1, 0xffffff) == -1)
	{
		MessageBox(_T("过滤规则编译失败"));
		return;
	}
	if (pcap_setfilter(adhandle, &filterCode) == -1)
	{
		MessageBox(_T("过滤规则设置失败"));
		return;
	}

	// 开始抓包
	m_shouldStop = FALSE;
	m_hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CapturePacket, this, 0, NULL);
	if (m_hThread == NULL)
	{
		MessageBox(_T("线程启动失败"));
		return;
	}

	// 更新UI状态
	CWnd* pStartButton = GetDlgItem(ID_Start);
	CWnd* pStopButton = GetDlgItem(ID_Stop);

	if (pStartButton != NULL && pStopButton != NULL) {
		pStartButton->EnableWindow(FALSE);
		pStopButton->EnableWindow(TRUE);
	}
	else {
		AfxMessageBox(_T("控件ID可能不正确或对话框创建失败！"));
	}

}

void CSnifferDlg::ShowPacketList(const struct pcap_pkthdr* pkt_header, const u_char* pkt_data) 
{
	int pkt_length = pkt_header->len;

	// 将数据包长度转换成字符串格式
	CString strPktLength;
	strPktLength.Format(_T("%d"), pkt_length);

	// 获取系统当前时间
	CString strTime;
	CTime t = CTime::GetCurrentTime();
	strTime = t.Format("%H:%M:%S");

	// 解析数据包的以太网头部(链路层-网络层-传输层-应用层）
	//前14个字节为以太网帧头部
	const struct eth_hdr* ether_hdr;
	ether_hdr = (const struct eth_hdr*)pkt_data;

	// 获取源MAC地址
	//%02X表示将一个无符号整数以16进制形式输出
	CString strSrcMacAddr;
	strSrcMacAddr.Format(_T("%02X:%02X:%02X:%02X:%02X:%02X"),
		ether_hdr->src[0], ether_hdr->src[1],
		ether_hdr->src[2], ether_hdr->src[3],
		ether_hdr->src[4], ether_hdr->src[5]);

	// 获取目的MAC地址
	CString strDstMacAddr;
	strDstMacAddr.Format(_T("%02X:%02X:%02X:%02X:%02X:%02X"),
		ether_hdr->dest[0], ether_hdr->dest[1],
		ether_hdr->dest[2], ether_hdr->dest[3],
		ether_hdr->dest[4], ether_hdr->dest[5]);

	// 判断数据包的类型，并解析出对应的协议头部信息
	CString strProtocol;
	CString strSrcIpAddr;
	CString strDstIpAddr;
	switch (ntohs(ether_hdr->type))
	{
	case IP:      // IPv4协议
	{
		strProtocol = _T("IPv4");

		// 解析IPv4头部
		const struct ip_hdr* ip_hdr;
		ip_hdr = (const struct ip_hdr*)(pkt_data + sizeof(struct eth_hdr));

		char strSrcIp[INET_ADDRSTRLEN];
		char strDstIp[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(ip_hdr->ip_saddr), strSrcIp, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ip_hdr->ip_daddr), strDstIp, INET_ADDRSTRLEN);
		strSrcIpAddr = CString(strSrcIp);
		strDstIpAddr = CString(strDstIp);

		//获取协议类型
		switch (ip_hdr->ip_type)
		{
		case ICMP:
		{
			strProtocol += _T(" (ICMP)");
			break;
		}
		case TCP:    // TCP协议
		{
			strProtocol += _T(" (TCP)");

			// 解析TCP头部
			const struct tcp_hdr* tcp_hdr;
			tcp_hdr = (const struct tcp_hdr*)(pkt_data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));
			u_short srcPort = ntohs(tcp_hdr->tcp_sport);
			u_short dstPort = ntohs(tcp_hdr->tcp_dport);

			CString strSrcPort;
			strSrcPort.Format(_T("%u"), srcPort);

			CString strDstPort;
			strDstPort.Format(_T("%u"), dstPort);

			strSrcIpAddr.Format(_T("%s:%s"), strSrcIpAddr, strSrcPort);
			strDstIpAddr.Format(_T("%s:%s"), strDstIpAddr, strDstPort);
			break;
		}
		case UDP:    // UDP协议
		{
			strProtocol += _T(" (UDP)");

			// 解析UDP头部
			const struct udp_hdr* udp_hdr;
			udp_hdr = (const struct udp_hdr*)(pkt_data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));
			u_short srcPort = ntohs(udp_hdr->udp_sport);
			u_short dstPort = ntohs(udp_hdr->udp_dport);

			CString strSrcPort;
			strSrcPort.Format(_T("%u"), srcPort);

			CString strDstPort;
			strDstPort.Format(_T("%u"), dstPort);

			strSrcIpAddr.Format(_T("%s:%s"), strSrcIpAddr, strSrcPort);
			strDstIpAddr.Format(_T("%s:%s"), strDstIpAddr, strDstPort);
			break;
		}
		break;
		}
	}
	case IPv6:    // IPv6协议
	{
		strProtocol = _T("IPv6");
		strSrcIpAddr = _T("");
		strDstIpAddr = _T("");
		break;
	}
	case ARP:     // ARP协议
	{
		strProtocol = _T("ARP");
		strSrcIpAddr = _T("");
		strDstIpAddr = _T("");
		break;
	}
	default:                // 未知协议
	{
		strProtocol = _T("Unknown");
		strSrcIpAddr = _T("");
		strDstIpAddr = _T("");
		break;
	}
	}

	// 将数据包信息添加到列表视图中
	int nItemIndex = m_list1.GetItemCount();
	CString strIndex;
	strIndex.Format(_T("%d"), nItemIndex + 1);
	m_list1.InsertItem(nItemIndex, strIndex);

	m_list1.SetItemText(nItemIndex, 1, strTime);
	m_list1.SetItemText(nItemIndex, 2, strPktLength);
	m_list1.SetItemText(nItemIndex, 3, strSrcMacAddr);
	m_list1.SetItemText(nItemIndex, 4, strDstMacAddr);
	m_list1.SetItemText(nItemIndex, 5, strProtocol);
	m_list1.SetItemText(nItemIndex, 6, strSrcIpAddr);
	m_list1.SetItemText(nItemIndex, 7, strDstIpAddr);
}




