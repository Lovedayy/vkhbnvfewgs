// CAdpDlg.cpp: 实现文件
//

#include "pch.h"
#include "Sniffer.h"
#include "CAdpDlg.h"
#include "afxdialogex.h"


// CAdpDlg 对话框

IMPLEMENT_DYNAMIC(CAdpDlg, CDialogEx)

CAdpDlg::CAdpDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG1, pParent)
{
}

CAdpDlg::~CAdpDlg()
{
}

void CAdpDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_LIST1, m_list1);
}


BEGIN_MESSAGE_MAP(CAdpDlg, CDialogEx)
    ON_NOTIFY(NM_CLICK, IDC_LIST1, &CAdpDlg::OnNMClickList1)
    ON_BN_CLICKED(IDOK, &CAdpDlg::OnBnClickedOk)
END_MESSAGE_MAP()

// CAdpDlg 消息处理程序
BOOL CAdpDlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();

    // Add extra initialization here
    m_list1.SetExtendedStyle(m_list1.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    m_list1.InsertColumn(0, _T("设备名"), LVCFMT_LEFT, 350);
    m_list1.InsertColumn(1, _T("设备描述"), LVCFMT_LEFT, 250);

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        printf("Error in pcap_findalldevs_ex function: %s\n", errbuf);
        return FALSE;
    }

    for (d = alldevs; d; d = d->next)
    {
        m_list1.InsertItem(0, (CString)d->name);
        m_list1.SetItemText(0, 1, (CString)d->description);

        pcap_t* adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
        if (adhandle == NULL)
        {
            fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
            continue;
        }

        // 添加 PCAP_OPENFLAG_PROMISCUOUS 标志
        if (pcap_setmode(adhandle, PCAP_OPENFLAG_PROMISCUOUS) != 0)
        {
            fprintf(stderr, "\nError setting adapter to promiscuous mode: %s\n", pcap_geterr(adhandle));
            pcap_close(adhandle);
            continue;
        }

        // 这里可以添加对 adhandle 的其他操作
        // ...

        pcap_close(adhandle);
    }

    pcap_freealldevs(alldevs);
    d = NULL;

    return TRUE;
}


void CAdpDlg::OnNMClickList1(NMHDR* pNMHDR, LRESULT* pResult)
{
    LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
    // TODO: 在此添加控件通知处理程序代码
    *pResult = 0;


    NMLISTVIEW* pNMListView = (NMLISTVIEW*)pNMHDR;

    if (-1 != pNMListView->iItem)        // 如果iItem不是-1，就说明有列表项被选择
    {
        // 获取被选择列表项第一个子项的文本
        adpname = m_list1.GetItemText(pNMListView->iItem, 0);
        // 将选择的语言显示与编辑框中
        SetDlgItemText(IDC_EDIT1, adpname);
    }
}

//返回已选中设备
pcap_if_t* CAdpDlg::GetDevice()
{
    for (d = alldevs; d; d = d->next)
    {
        m_list1.InsertItem(0, (CString)d->name);
        m_list1.SetItemText(0, 1, (CString)d->description);

        pcap_t* adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
        if (adhandle == NULL)
        {
            fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
            continue;
        }

        // 添加 PCAP_OPENFLAG_PROMISCUOUS 标志
        if (pcap_setmode(adhandle, PCAP_OPENFLAG_PROMISCUOUS) != 0)
        {
            fprintf(stderr, "\nError setting adapter to promiscuous mode: %s\n", pcap_geterr(adhandle));
            pcap_close(adhandle);
            continue;
        }

        // 这里可以添加对 adhandle 的其他操作
        // ...

        pcap_close(adhandle);
    }

    pcap_freealldevs(alldevs);
    return NULL;
}

void CAdpDlg::OnBnClickedOk()
{
    // TODO: 在此添加控件通知处理程序代码
    d = GetDevice();
    if (d)
    {
        MessageBox(_T("网卡绑定成功!"));
        CDialogEx::OnOK();
    }
    else
        MessageBox(_T("请选择要绑定的网卡"));
}


