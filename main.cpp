#include <iostream>
#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

using namespace std;

struct ip *iph;
struct tcphdr *tcph;

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct ether_header *ep;
    unsigned short ether_type;
    char *srcip, *dstip;

    ep=(struct ether_header *)packet;

    packet+=sizeof(struct ether_header);

    ether_type=ntohs(ep->ether_type);

    printf("\n-------------------------------\n");
    printf("Src Address : %02x:%02x:%02x:%02x:%02x:%02x\n",ep->ether_shost[0],ep->ether_shost[1],ep->ether_shost[2],ep->ether_shost[3],ep->ether_shost[4],ep->ether_shost[5]);
    printf("Dst Address : %02x:%02x:%02x:%02x:%02x:%02x\n",ep->ether_dhost[0],ep->ether_dhost[1],ep->ether_dhost[2],ep->ether_dhost[3],ep->ether_dhost[4],ep->ether_dhost[5]);
    printf("\n");

    if(ether_type==ETHERTYPE_IP)
    {
        iph = (struct ip *)packet;

        srcip=inet_ntoa(iph->ip_src);
        printf("Src IP : %s\n",srcip);
        dstip=inet_ntoa(iph->ip_dst);
        printf("Dst IP : %s\n",dstip);
        printf("\n");

        if(iph->ip_p == IPPROTO_TCP)
        {
            packet+=sizeof(struct ip);
            tcph=(struct tcphdr *)packet;

            printf("Src Port : %d\n",tcph->th_sport);
            printf("Dst Port : %d\n",tcph->th_dport);
            printf("\n");
        }
        else
        {
            printf("NONE TCP Packet\n");
        }

    }
    else
    {
        printf("NONE IP Packet\n");
    }
}

int main()
{
    char * device; //device name
    bpf_u_int32 netp, maskp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;
    struct bpf_program fp;
    pcap_t *pcd;


    device = pcap_lookupdev(errbuf);

    if(device == NULL)
    {
        printf("%s\n",errbuf);
        exit(1);
    }
    printf("Device : %s\n",device);

    ret=pcap_lookupnet(device,&netp,&maskp,errbuf);

    if(ret==-1)
    {
        printf("%s\n",errbuf);
        exit(1);

    }

    pcd=pcap_open_live(device, BUFSIZ, 0, -1, errbuf);
    if(pcd==NULL)
    {
        printf("%s\n",errbuf);
        exit(1);
    }

    if(pcap_compile(pcd, &fp, 0, 0,netp)==-1)
    {
        printf("compile error\n");
        exit(1);
    }

    if(pcap_setfilter(pcd, &fp)==-1)
    {
        printf("setfilter error\n");
        exit(0);
    }

    pcap_loop(pcd, 0, callback, NULL);

    return 0;
}
