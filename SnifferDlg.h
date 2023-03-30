
// SnifferDlg.h: 头文件
//

#pragma once


// CSnifferDlg 对话框
class CSnifferDlg : public CDialogEx
{
// 构造
public:
	CSnifferDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SNIFFER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

public:
	CEdit m_edit1;
	CString m_tcpnum;
	CString m_udpnum;
	CString m_arpum;
	CString m_icmpnum;
	CString m_httpnum;
	CString m_dnsnum;
	CString m_totalnum;
	CListCtrl m_list1;
	CTreeCtrl m_tree1;
	pcap_if_t* m_pDevice = NULL;
	char m_filtername[100];  // 声明 m_filtername 变量
	bool m_bFlag;
	HANDLE m_hThread; // 线程句柄


	afx_msg void OnEnChangeEdit1();
	afx_msg void OnAdp();
	afx_msg void OnFilter();
	static DWORD WINAPI CapturePacket(LPVOID lpParam);
	afx_msg void OnStart();
	afx_msg void OnStop();
};
