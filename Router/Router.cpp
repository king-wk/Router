#include <iostream>
#include "pcap.h"
#include <string>
#include <list>
#include <iterator>
#include <WinSock2.h>
using namespace std;
#pragma comment(lib,"ws2_32.lib")

#pragma pack(1)		            // 进入字节对齐方式

typedef struct FrameHeader_t {	// 帧首部
    BYTE	DesMAC[6];	        // 目的地址
    BYTE 	SrcMAC[6];	        // 源地址
    WORD	FrameType;	        // 帧类型
} FrameHeader_t;

typedef struct ARPFrame_t {     // ARP帧
    FrameHeader_t FrameHeader;  // 帧头部结构体
    WORD HardwareType;          // 硬件类型
    WORD ProtocolType;          // 协议类型
    BYTE HLen;                  // 硬件地址长度
    BYTE PLen;                  // 协议地址长度
    WORD Operation;             // 操作字段
    BYTE SendHa[6];             // 源MAC地址
    DWORD SendIP;               // 源IP地址
    BYTE RecvHa[6];             // 目的MAC地址
    DWORD RecvIP;               // 目的IP地址
} ARPFrame_t;

typedef struct IPHeader_t {		// IP首部
    BYTE Ver_HLen;              // 版本+头部长度
    BYTE TOS;                   // 服务类型
    WORD TotalLen;              // 总长度
    WORD ID;                    // 标识
    WORD Flag_Segment;          // 标志+片偏移
    BYTE TTL;                   // 生存时间
    BYTE Protocol;              // 协议
    WORD Checksum;              // 头部校验和
    ULONG SrcIP;                // 源IP地址
    ULONG DstIP;                // 目的IP地址
} IPHeader_t;

typedef struct Data_t {	        // 包含帧首部和IP首部的数据包
    FrameHeader_t FrameHeader;  // 帧首部
    IPHeader_t IPHeader;        // IP首部
} Data_t;

#pragma pack()	                // 恢复默认对齐方式

typedef struct Packet_t {       // 缓存队列的数据包
    DWORD ip;                   // 目的IP地址
    int IfNo;                   // 接口序号
    int len;                    // 数据包长度
    char data[65535];           // 数据包
} Packet_t;

typedef struct IfInfo_t {	    // 接口信息
    char DeviceName[64];        // 设备名
    char Description[128];      // 设备描述
    BYTE MACAddr[6];            // MAC地址
    DWORD ip[5];                // IP地址列表
    DWORD netmask[5];           // 掩码地址列表
    pcap_t* adhandle;           // pcap句柄
} IfInfo_t;

typedef struct RouteTable_t {	// 路由表表项
    DWORD Mask;                 // 子网掩码
    DWORD DstIP;                // 目的地址
    DWORD NextHop;              // 下一跳步
    int	IfNo;                   // 接口序号
} RouteTable_t;

typedef struct IP_MAC_t {       // IP-MAC地址映射表表项
    DWORD IPAddr;               // IP地址
    BYTE MACAddr[6];            // MAC地址
} IP_MAC_t;

// 共享变量
const int MaxInterface = 5;              // 最大接口数
IfInfo_t IfInfo[MaxInterface];	         // 接口信息数组
int InterfaceCount = 0;                  // 记录接口个数
pcap_if_t* alldevs;                      // 指向设备列表首部的指针
char errbuf[PCAP_ERRBUF_SIZE];           // 错误信息
pcap_if_t* d;                            // 指向选定设备的指针
list<Packet_t> PacketQueue;              // 数据包缓存队列
list<IP_MAC_t> IPMACTable;               // MAC地址映射表
list<RouteTable_t> RouteTable;           // 路由表
string info;                             // 日志

// 获得本机接口并捕获数据包
int GetLocalInterface();
// 获取本地接口MAC地址线程
DWORD WINAPI CaptureLocalARP(LPVOID lpParameter);
// 捕获数据报
DWORD WINAPI CapturePacket(LPVOID lpParameter);
// 处理IP数据报
void DealIPPacket(struct pcap_pkthdr* header, const u_char* pkt_data);
// 查询路由表
DWORD RouteSearch(int& IfNo, DWORD DstIP);
// 查询MAC地址映射表
bool MACTableSearch(DWORD ip, BYTE* MAC);
// 更新MAC地址映射表
void MACTableUpdate(DWORD ip, BYTE* MAC);
// 处理ARP数据报
void DealARPPacket(struct pcap_pkthdr* header, const u_char* pkt_data);
// 发送ARP请求
void ARPRequest(pcap_t* adhandle, BYTE* SrcMAC, DWORD SendIp, DWORD RecvIp);
// 显示工作日志
void ShowRecord();
// 显示路由表
void ShowRouteTable();
// 增加路由表项
void AddRoute();
// 删除路由表项
void DeleteRoute();
// 将MAC地址转换成xx:xx:xx:xx:xx:xx
char* MACFormat(BYTE* mac);
// 将IP地址转换成xxx.xxx.xxx.xxx
char* IPFormat(DWORD ip);
// 检验IP数据报头部校验和
bool checkIPHeader(char* buff);
// 检验校验和
u_short checksum(u_short* buffer, int size);

int main()
{
    cout << "start router..." << endl;
    GetLocalInterface();
    cout << "open " << InterfaceCount << " interface..." << endl;
    cout << "start capture and forward packets..." << endl;
    // 开启捕获数据包线程
    for (int i = 0;i < InterfaceCount;i++) {
        CreateThread(NULL, 0, &CapturePacket, &IfInfo[i], 0, NULL);
    }
    int menu;
    while (1) {
        cout << "-------------------Router-------------------" << endl;
        cout << "1.显示日志" << endl;
        cout << "2.显示路由表" << endl;
        cout << "3.增加路由表项" << endl;
        cout << "4.删除路由表项" << endl;
        cin >> menu;
        switch (menu)
        {
        case 1:
            ShowRecord();
            break;
        case 2:
            ShowRouteTable();
            break;
        case 3:
            AddRoute();
            break;
        case 4:
            DeleteRoute();
            break;
        default:
            cout << "error order, choose again..." << endl;
            break;
        }
    }
    return 0;
}
// 获得本机接口
int GetLocalInterface() {
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        cout << stderr << "Error in pcap_findalldevs_ex :" << errbuf << endl;
        return -1;
    }
    for (d = alldevs;d != NULL;d = d->next) {
        int flag = 0;
        int j = 0;
        for (pcap_addr_t* a = d->addresses; a != NULL; a = a->next) {
            if (a->addr->sa_family == AF_INET) {
                flag = 1;
                strcpy(IfInfo[InterfaceCount].DeviceName, d->name);
                if (d->description) {
                    strcpy(IfInfo[InterfaceCount].Description, d->description);
                }
                else {
                    strcpy(IfInfo[InterfaceCount].Description, "(No description available)");
                }
                IfInfo[InterfaceCount].ip[j] = ((struct sockaddr_in*)a->addr)->sin_addr.S_un.S_addr;
                IfInfo[InterfaceCount].netmask[j] = ((struct sockaddr_in*)a->netmask)->sin_addr.S_un.S_addr;
                j++;
            }
        }
        if (flag) {
            InterfaceCount++;
        }
    }
    for (int i = 0;i < InterfaceCount;i++) {
        if ((IfInfo[i].adhandle = 
            pcap_open(IfInfo[i].DeviceName, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) {
            cout << IfInfo[i].DeviceName << " cannot open." << endl;
            return -1;
        }
        CreateThread(NULL, 0, &CaptureLocalARP, &IfInfo[i], 0, NULL);
    }
    Sleep(3000);// 休眠3s获得本机设备MAC地址
    info.append("路由器设备接口：\n\n");
    for (int i = 0;i < InterfaceCount;i++) {
        info.append("设备名：");
        info.append(IfInfo[i].DeviceName);
        info.append("\n");
        info.append("MAC地址：");
        info.append(MACFormat(IfInfo[i].MACAddr));
        info.append("\n");
        for (int j = 0;IfInfo[i].ip[j] != '\0';j++) {
            info.append("IP地址：");
            info.append(IPFormat(IfInfo[i].ip[j]));
            info.append("\n");
        }
        info.append("\n");
    }
    // 初始化路由表
    RouteTable_t rt;
    for (int i = 0;i < InterfaceCount;i++) {
        for (int j = 0;IfInfo[i].ip[j] != '\0';j++) {
            rt.IfNo = i;
            rt.Mask = IfInfo[i].netmask[j];
            rt.DstIP = (IfInfo[i].netmask[j] & IfInfo[i].ip[j]);
            rt.NextHop = 0;// 直接投递
            RouteTable.push_back(rt);
        }
    }
    pcap_freealldevs(alldevs);
    return 1;
}
// 发送ARP请求
void ARPRequest(pcap_t* adhandle, BYTE* SrcMAC, DWORD SendIp, DWORD RecvIp) {
    ARPFrame_t  ARPFrame;
    ARPFrame.FrameHeader.FrameType = htons(0x0806);	//帧类型为ARP
    ARPFrame.HardwareType = htons(0x0001);			//硬件类型为以太网
    ARPFrame.ProtocolType = htons(0x0800);			//协议类型为IP
    ARPFrame.HLen = 6;								//硬件地址长度为6
    ARPFrame.PLen = 4;								//协议地址长度为4
    ARPFrame.Operation = htons(0x0001);				//操作为ARP请求
    ARPFrame.SendIP = SendIp;                       //将ARPFrame.SendIP设置为本机网卡上绑定的IP地址。	
    ARPFrame.RecvIP = RecvIp;		                //将ARPFrame.RecvIP设置为请求的IP地址;

    for (int i = 0;i < 6;i++)
    {
        ARPFrame.FrameHeader.DesMAC[i] = 0xff;	    //将ARPFrame.FrameHeader.DesMAC设置为广播地址
        ARPFrame.FrameHeader.SrcMAC[i] = SrcMAC[i]; //将ARPFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址
        ARPFrame.SendHa[i] = SrcMAC[i];	            //将ARPFrame.SendHa设置为本机网卡的MAC地址
        ARPFrame.RecvHa[i] = 0x00;		            //将ARPFrame.RecvHa设置为0
    }
    if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0) {
        return;
    }
}
// 获取本地接口MAC地址线程
DWORD WINAPI CaptureLocalARP(LPVOID lpParameter) {
    IfInfo_t* pIfInfo;
    pIfInfo = (IfInfo_t*)lpParameter;
    ARPFrame_t* ARPFrame;
    struct pcap_pkthdr* header; 
    const u_char* pkt_data;
    UCHAR SrcMAC[6];
    DWORD SrcIP;
    for (int i = 0; i < 6; i++) {
        SrcMAC[i] = 0x66;
    }
    SrcIP = inet_addr("112.112.112.112");
    ARPRequest(pIfInfo->adhandle, SrcMAC, SrcIP, pIfInfo->ip[0]);
    int res;
    while (true) {
        res = pcap_next_ex(pIfInfo->adhandle, &header, &pkt_data);
        if (res == 0) {
            // 超时时间到
            continue;
        }
        else if (res == 1) {
            ARPFrame = (ARPFrame_t*)(pkt_data);
            if (ARPFrame->FrameHeader.FrameType == htons(0x0806)
                && ARPFrame->Operation == htons(0x0002)
                && ARPFrame->SendIP == pIfInfo->ip[0]) {
                for (int i = 0;i < 6;i++) {
                    pIfInfo->MACAddr[i] = ARPFrame->SendHa[i];
                }
                return 0;
            }
        }
    }
    return 0;
}
// 捕获数据包线程
DWORD WINAPI CapturePacket(LPVOID lpParameter) {
    IfInfo_t* pIfInfo;
    pIfInfo = (IfInfo_t*)lpParameter;
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    int res;
    while (true) {
        // 捕获接口的数据包
        res = pcap_next_ex(pIfInfo->adhandle, &header, &pkt_data);
        if (res == 0) {
            // 超时时间到
            continue;
        }
        else if (res == 1) {
            FrameHeader_t* FrameHeader;
            FrameHeader = (FrameHeader_t*)pkt_data;
            // 发给端口的数据报（目的MAC地址为接口MAC地址）
            if (memcmp(FrameHeader->DesMAC, pIfInfo->MACAddr, 6) == 0) {
                switch (ntohs(FrameHeader->FrameType))
                {
                // 如果是ARP数据报
                case 0x0806:
                    DealARPPacket(header, pkt_data);
                    break;
                // 如果是IP数据报
                case 0x0800:
                    DealIPPacket(header, pkt_data);
                    break;
                default:
                    break;
                }
            }
        }
    }
    return 0;
}
// 处理IP数据报
void DealIPPacket(struct pcap_pkthdr* header, const u_char* pkt_data) {
    Data_t* IPFrame;
    IPFrame = (Data_t*)pkt_data;
    info.append("收到IP数据报：");
    info.append(IPFormat(IPFrame->IPHeader.SrcIP));
    info.append("->");
    info.append(IPFormat(IPFrame->IPHeader.DstIP));
    info.append("\n");
    if (IPFrame->IPHeader.TTL <= 0) {// 超时
        return;
    }
    IPHeader_t* IpHeader = &(IPFrame->IPHeader);
    if (checkIPHeader((char*)IpHeader) == 0) {
        info.append("数据报头部校验和出错，丢弃数据报。\n");
        return;
    }
    // 路由查询
    DWORD NextHop;		// 经过路由选择算法得到的下一站目的IP地址
    int IfNo;			// 下一跳的接口序号
    // 查询路由表，返回下一站目的IP地址，更新下一跳接口序号，
    if ((NextHop = RouteSearch(IfNo, (DWORD)IPFrame->IPHeader.DstIP)) == -1) {
        // 找不到对应路由表项，抛弃数据报
        info.append("路由选择失败，抛弃报文!\n\n");
        return;
    }
    else {
        // 转发数据帧的源MAC地址变成路由器端口MAC地址，目的地址将在MAC地址映射表中查询
        for (int i = 0;i < 6;i++) {
            IPFrame->FrameHeader.SrcMAC[i] = IfInfo[IfNo].MACAddr[i];
        }
        IPFrame->IPHeader.TTL -= 1;// TTL减一
        u_short check_buff[sizeof(IPHeader_t)];
        // 设IP头中的校验和为0
        IPFrame->IPHeader.Checksum = 0;
        memset(check_buff, 0, sizeof(IPHeader_t));
        IPHeader_t* ip_header = &(IPFrame->IPHeader);
        memcpy(check_buff, ip_header, sizeof(IPHeader_t));
        // 计算IP头部校验和
        IPFrame->IPHeader.Checksum = checksum(check_buff, sizeof(IPHeader_t));
        // 查询MAC地址映射表，更新数据帧头目的MAC地址
        if (MACTableSearch(NextHop, IPFrame->FrameHeader.DesMAC)) {
            int res = pcap_sendpacket(IfInfo[IfNo].adhandle, (u_char*)pkt_data, header->len);
            if ( res == -1) {
                info.append("转发IP数据报时出错!\n\n");
            }
            else if (res == 0) {
                info.append("IP数据报转发：");
                info.append(IPFormat(IPFrame->IPHeader.SrcIP));
                info.append("->");
                info.append(IPFormat(NextHop));
                info.append("\n");
                info.append(MACFormat(IPFrame->FrameHeader.SrcMAC));
                info.append("->");
                info.append(MACFormat(IPFrame->FrameHeader.DesMAC));
                info.append("\n\n");
            }
        }
        else {// MAC地址映射表不存在映射关系
            /*
            info.append("缺少目的MAC地址，已丢弃：");
            info.append(IPFormat(IPFrame->IPHeader.SrcIP));
            info.append("->");
            info.append(IPFormat(IPFrame->IPHeader.DstIP));
            info.append("\n");
            info.append(MACFormat(IPFrame->FrameHeader.SrcMAC));
            info.append("->");
            info.append("xx:xx:xx:xx:xx:xx\n");
            info.append("已发送ARP请求:");
            info.append(IPFormat(NextHop));
            info.append("\n\n");
            ARPRequest(IfInfo[IfNo].adhandle, IfInfo[IfNo].MACAddr, IfInfo[IfNo].ip[0], NextHop);
            */
            // 记录数据报对应信息，以便转发
            Packet_t* Packet = new Packet_t();
            Packet->ip = NextHop;
            Packet->IfNo = IfNo;
            Packet->len = header->len;
            memset(Packet->data, 0, Packet->len);
            memcpy(Packet->data, pkt_data, Packet->len);
            if (PacketQueue.size() < 65535) {// 存入缓存队列
                PacketQueue.push_back(*Packet);
                info.append("缺少目的MAC地址，已存入缓冲区：\n");
                info.append(IPFormat(IPFrame->IPHeader.SrcIP));
                info.append("->");
                info.append(IPFormat(IPFrame->IPHeader.DstIP));
                info.append(" ");
                info.append(MACFormat(IPFrame->FrameHeader.SrcMAC));
                info.append("->");
                info.append("xx:xx:xx:xx:xx:xx");
                info.append("已发送ARP请求:");
                info.append(IPFormat(Packet->ip));
                info.append("\n\n");
                ARPRequest(IfInfo[Packet->IfNo].adhandle, IfInfo[Packet->IfNo].MACAddr, IfInfo[Packet->IfNo].ip[0], Packet->ip);
            }
            else {
                info.append("转发缓冲区溢出，丢弃IP数据包：\n");
                info.append(IPFormat(IPFrame->IPHeader.SrcIP));
                info.append("->");
                info.append(IPFormat(IPFrame->IPHeader.DstIP));
                info.append(" ");
                info.append(MACFormat(IPFrame->FrameHeader.SrcMAC));
                info.append("->");
                info.append("xx:xx:xx:xx:xx:xx\n\n");
            }
            delete Packet;
        }
    }
}
// 查询路由表
DWORD RouteSearch(int& IfNo, DWORD DstIP) {
    DWORD temp;
    int flag = 0;// 标志是否选择到路由
    DWORD maxmask = 0;
    list<RouteTable_t>::iterator i;
    for (i = RouteTable.begin();i != RouteTable.end();i++) {
        if ((DstIP & i->Mask) == i->DstIP) {
            if (i->Mask >= maxmask) {// 如果表项掩码大于当前匹配最大掩码
                flag = 1;
                IfNo = i->IfNo;
                if (i->NextHop == 0) {// 直接投递
                    temp = DstIP;
                }
                else {
                    temp = i->NextHop;
                }
                maxmask = i->Mask;
            }
        }
    }
    if (flag) {
        return temp;
    }
    return -1;
}
// 查询MAC地址映射表
bool MACTableSearch(DWORD ip, BYTE* MAC) {
    if (IPMACTable.empty()) {
        return false;
    }
    list<IP_MAC_t>::iterator i;
    for (i = IPMACTable.begin();i != IPMACTable.end();i++) {
        if (ip == i->IPAddr) {
            for (int j = 0;j < 6;j++) {
                MAC[j] = i->MACAddr[j];
            }
            return true;
        }
    }
    return false;
}
// 更新MAC地址映射表
void MACTableUpdate(DWORD ip, BYTE* MAC) {
    if (IPMACTable.empty()) {
        return;
    }
    list<IP_MAC_t>::iterator i;
    for (i = IPMACTable.begin();i != IPMACTable.end();i++) {
        if (ip == i->IPAddr) {
            for (int j = 0;j < 6;j++) {
                i->MACAddr[j] = MAC[j];
            }
            return;
        }
    }
    return;
}
// 处理ARP数据报
void DealARPPacket(struct pcap_pkthdr* header, const u_char* pkt_data) {
    ARPFrame_t* ARP;
    ARP = (ARPFrame_t*)pkt_data;
    BYTE mac[6];
    if (ARP->Operation == htons(0x0002)) {
        info.append("收到ARP响应数据报：");
        info.append(IPFormat(ARP->SendIP));
        info.append("--");
        info.append(MACFormat(ARP->SendHa));
        info.append("\n");
        if (MACTableSearch(ARP->SendIP, mac)) {
            // 判断MAC地址映射表中的MAC地址是否为最新
            if (memcmp(mac, ARP->SendHa, 6) == 0) {
                info.append("该映射关系已存在。\n\n");
            }
            else {
                MACTableUpdate(ARP->SendIP, ARP->SendHa);
                info.append("该映射关系已更新。\n\n");
            }
        }
        else {
            IP_MAC_t ipmac;
            ipmac.IPAddr = ARP->SendIP;
            for (int i = 0;i < 6;i++) {
                ipmac.MACAddr[i] = ARP->SendHa[i];
            }
            IPMACTable.push_back(ipmac);
            info.append("该映射关系已保存。\n\n");
            if (PacketQueue.empty()) {
                return;
            }
            list<Packet_t>::iterator i;// 遍历数据包缓存队列查看是否有可以转发的IP数据包
            for (i = PacketQueue.begin();i != PacketQueue.end();i++) {
                if (i->ip == ARP->SendIP) {// 如果有数据包的目标IP地址为ARP包IP地址
                    Data_t* IPFrame;
                    IPFrame = (Data_t*)i->data;
                    for (int j = 0;j < 6;j++) {
                        IPFrame->FrameHeader.DesMAC[j] = ARP->SendHa[j];
                    }
                    if (pcap_sendpacket(IfInfo[i->IfNo].adhandle, (u_char*)i->data, i->len) == -1) {
                        return;
                    }
                    else {
                        PacketQueue.erase(i);
                        info.append("转发缓存区中目的地址是该MAC地址的IP数据包,转发IP数据包：\n");
                        info.append(IPFormat(IPFrame->IPHeader.SrcIP));
                        info.append("->");
                        info.append(IPFormat(i->ip));
                        info.append(" ");
                        info.append(MACFormat(IPFrame->FrameHeader.SrcMAC));
                        info.append("->");
                        info.append(MACFormat(IPFrame->FrameHeader.DesMAC));
                        info.append("\n\n");
                    }
                }
            }
        }
    }
}
// 显示工作日志
void ShowRecord() {
    cout << "-------------------日志-------------------" << endl;
    cout << info << endl;
}
// 显示路由表
void ShowRouteTable() {
    cout << "-------------------路由表-------------------" << endl;
    list<RouteTable_t>::iterator i;
    for (i = RouteTable.begin();i != RouteTable.end();i++) {
        cout << IPFormat(i->Mask) << "---";
        cout << IPFormat(i->DstIP) << "---";
        cout << IPFormat(i->NextHop);
        if (i->NextHop == 0) {
            cout << "(直接投递)";
        }
        cout << endl;
    }
}
// 增加路由表项
void AddRoute() {
    RouteTable_t rt;
    string mask;
    string dstip;
    string nexthop;
    cout << "子网掩码：";
    cin>> mask;
    cout << "目的地址：";
    cin >> dstip;
    cout << "下一跳步：";
    cin >> nexthop;
    for (int i = 0;i < InterfaceCount;i++) {
        for (int j = 0;IfInfo[i].ip[j] != '\0';j++) {
            // 判断输入是否符合
            if (((IfInfo[i].netmask[j] & IfInfo[i].ip[j]) 
                == (IfInfo[i].netmask[j] & inet_addr(nexthop.c_str())))
                &&(IfInfo[i].netmask[j] == inet_addr(mask.c_str()))) {
                rt.IfNo = i;
                rt.Mask = inet_addr(mask.c_str());
                rt.DstIP = inet_addr(dstip.c_str());
                rt.NextHop = inet_addr(nexthop.c_str());
                RouteTable.push_front(rt);
                cout << "已增加该路由表项" << endl;
                return;
            }
        }
    }
    cout << "路由表项输入有误。" << endl;
}
// 删除路由表项
void DeleteRoute() {
    string mask;
    string dstip;
    string nexthop;
    cout << "子网掩码：";
    cin >> mask;
    cout << "目的地址：";
    cin >> dstip;
    cout << "下一跳步：";
    cin >> nexthop;
    if (inet_addr(nexthop.c_str()) == 0) {
        cout << "直接投递路由，不能删除" << endl;
        return;
    }
    if (RouteTable.empty()) {
        return;
    }
    // 遍历路由表项
    list<RouteTable_t>::iterator i;
    for (i = RouteTable.begin();i != RouteTable.end();i++) {
        if (i->DstIP == inet_addr(dstip.c_str())
            && i->Mask == inet_addr(mask.c_str())
            && i->NextHop == inet_addr(nexthop.c_str())) {
            RouteTable.erase(i);
            cout << "已删除该路由表项" << endl;
            return;
        }
    }
    cout << "不存在该路由表项" << endl;
}
// 将MAC地址转换成xx:xx:xx:xx:xx:xx
char* MACFormat(BYTE* mac) {
    char* buffer = new char[32];
    sprintf(buffer, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buffer;
}
// 将IP地址转换成xxx.xxx.xxx.xxx
char* IPFormat(DWORD ip) {
    u_char* p;
    p = (u_char*)&ip;
    char* buffer = new char[32];
    sprintf(buffer, "%03d.%03d.%03d.%03d", p[0], p[1], p[2], p[3]);
    return buffer;
}
// 检验IP数据报头部校验和
bool checkIPHeader(char* buff) {
    // 获得IP头内容
    IPHeader_t* ip_header = (IPHeader_t*)buff;
    // 备份原来的校验和
    u_short checksumBuf = ip_header->Checksum;
    u_short check_buff[sizeof(IPHeader_t)];
    // 设IP头中的校验和为0
    ip_header->Checksum = 0;
    memset(check_buff, 0, sizeof(IPHeader_t));
    memcpy(check_buff, ip_header, sizeof(IPHeader_t));
    // 计算IP头部校验和
    ip_header->Checksum = checksum(check_buff, sizeof(IPHeader_t));
    // 与备份的校验和进行比较
    if (ip_header->Checksum == checksumBuf)
    {
        return 1;
    }
    return 0;
}
// 计算校验和
u_short checksum(u_short* buffer, int size) {
    u_long cksum = 0;
    while (size > 1)
    {
        cksum += *buffer++;
        // 16位相加
        size -= sizeof(u_short);
    }
    if (size)
    {
        // 最后可能有单独8位
        cksum += *(u_char*)buffer;
    }
    // 将高16位进位加至低16位
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    // 取反
    return (u_short)(~cksum);
}
