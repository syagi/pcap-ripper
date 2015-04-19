#include<stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <pcap.h>

/* payload picker */
/*
 使い方
 1. フィルタ filter_exp を編集して取り出したいパケットを絞り込む
  (e.g. codegate 2012 network300では、被害者ホストから送信されたパケットに絞り込んだ
        = 攻撃者から送信されたパケットを無視した)
 2. パケット構造に合わせて get_payload のソースを変更
    基本的には、 tcp/udpのヘッダを付け替える程度のはず。
 3. a.out pcap_file > output
 4. できたファイルをKIAIで解析
*/


/* prototype of callback function */
void get_payload(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/* ether header structure */
typedef struct eth_hdr {
        u_char ether_dhost[ETHER_ADDR_LEN];
        u_char ether_shost[ETHER_ADDR_LEN];
        u_short ether_type;
} ETH;

/* upper layer header structures */
typedef struct ip IP4;
typedef struct ip6_hdr IP6;
typedef struct tcphdr TCP;
typedef struct udphdr UDP;

/* udp_lite hader structure */
#define UDP_LITE_LEN 8
typedef struct udp_lite_hdr {
        u_char whatisthis[UDP_LITE_LEN];
} UDPL;

int main (int argc, char **argv) {

   char ebuf[PCAP_ERRBUF_SIZE]; // error buffer
   pcap_t *pd;
   struct bpf_program fp;
   struct pcap_pkthdr pcap_hader;
   const u_char *packet;

   /*** pcap filter. EDIT HERE!!! ****/
   char filter_exp[] = "src host 192.168.136.136";

   if(argc!=2){
           printf (" usage: %s pcap_file \n", argv[0]);
           exit(1);
   }

   /* open pcap file */
   pd = pcap_open_offline(argv[1], ebuf);

   /* compile captuer filter */
   if (pcap_compile(pd, &fp, filter_exp, 0, 0) == -1) {
           fprintf(stderr, "failed to compile filtering rule: %s error: %s\n", filter_exp, pcap_geterr(pd));
           exit(1);
   }
   if (pcap_setfilter(pd, &fp) == -1) {
           fprintf(stderr, "failed to set filter: %s error: %s\n", filter_exp, pcap_geterr(pd));
           exit(1);
   }

   /* capture packet one by one */
   pcap_loop(pd, -1, get_payload, NULL);

   /* close pcap file */
   pcap_close(pd);
}

void get_payload(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

        /* headers */
        ETH *eth_hdr;
        IP4 *ip4_hdr;
        IP6 *ip6_hdr;
        TCP *tcp_hdr;
        unsigned char *payload;

        int ip4_tot_len;
        int ip6_payload_len;
        int tcp_hdr_len;
        int payload_length;
        int i;

        /* cast ETH header */
        eth_hdr = (ETH *) (packet);

        /* cast ipv4 header */
        ip4_hdr = (IP4 *) (packet + sizeof(ETH));

        /* get total packet length */
        ip4_tot_len = ntohs(ip4_hdr->ip_len);

        /*** remove below if your packets don't have ipv6 header ***/
        /* cast ipv6 header */
        ip6_hdr = (IP6 *) (packet + sizeof(ETH) + sizeof(IP4));

        /* get ipv6 payload length */
        ip6_payload_len = ntohs(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen);

        /*** remove above if your packets don't have ipv6 header ***/

        /* cast tcp header */
        tcp_hdr = (TCP *) (packet + sizeof(ETH) + sizeof(IP4) + sizeof(IP6));

        /* get tcp header length */
        tcp_hdr_len = tcp_hdr->th_off*4;

        /* get payload length */
        payload = (u_char *) (packet + sizeof(ETH) + sizeof(IP4) + sizeof(IP6) + sizeof(TCP));
        payload_length = ip6_payload_len - tcp_hdr_len;

        /* print payloads to stdout */
        for(i=0; i<payload_length; i++){
                fprintf (stdout,"%c", *(payload+i));
        }

}
