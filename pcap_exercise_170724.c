#include <stdio.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#define ETHER_ADDR_LEN	6 

struct _ethernet {
		  u_char ether_dhost[ETHER_ADDR_LEN];
		  u_char ether_shost[ETHER_ADDR_LEN];
		  u_short ether_type;
};

struct _ip {
		  u_char ip_vhl;
		  u_char ip_tos;
		  u_short ip_len;
		  u_short ip_id;
		  u_short ip_off;
		  u_char ip_ttl;
		  u_char ip_proto;
		  u_short ip_check;
		  struct in_addr ip_src, ip_dst;
};

struct _tcp {
		  u_short tcp_sport;
		  u_short tcp_dport;
		  u_int tcp_seqno;
		  u_int tcp_ackno;
		  u_char th_off;
};

void print_packet_header_info (const u_char *data);
int print_tcp_header_info (const u_char *data);
void print_data (const u_char *data);

int main (int argc, char *argv[]) {
		  char *dev, errbuf[PCAP_ERRBUF_SIZE];
		  pcap_t *handle;
		  struct bpf_program fp;
		  char filter_exp[] = "port 80";
		  struct pcap_pkthdr *header;
		  const u_char *packet;
		  int res;
		  int pac_div;
		  bpf_u_int32 net;
		 		  
		  dev = pcap_lookupdev(errbuf);
		  if (dev == NULL) {
					 fprintf (stderr, "Couldn't find default device : %s\n", errbuf);
					 return(2);
		  }
//		  printf("Device : %s\n", dev);

		  handle = pcap_open_live("dum0", BUFSIZ, 1, 1000, errbuf);
		  if (handle == NULL) {
					 fprintf(stderr, "Couldn't open device %s : $s\n", dev, errbuf);
					 return(2);
		  }

		  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
					 fprintf(stderr, "Couldn't parse filter %s : %s\n", filter_exp, pcap_geterr(handle));
					 return(2);
		  }

		  if (pcap_setfilter(handle, &fp) == -1) {
					 fprintf(stderr, "Couldn't install filter %s : %s\n", filter_exp, pcap_geterr(handle));
					 return(2);
		  }

		  while((res = pcap_next_ex(handle, &header, &packet)) >=0 ) {
					 if (res == 0) 
								continue;
					 if (res == -1) {
								fprintf(stderr, "Couldn't read the next packet : %s\n", pcap_geterr(handle));
								 return(2);
					 }
					 print_packet_header_info(packet);
			}
		pcap_freecode(&fp);
		pcap_close(handle);		
}

void print_packet_header_info (const u_char *data) {
		  struct _ethernet *ether = (struct _ethernet *) data;
		  struct _ip *ip_h = (struct _ip *) (data+14);
		  struct _tcp *tcp_h = (struct _tcp *) (data+14+(((ip_h->ip_vhl) & 0x0f)*4));
		  int i = 0, ip_type = (ip_h->ip_proto);
		  int ip_h_len = ((ip_h->ip_vhl) & 0x0f)*4;
		  int tcp_h_len = (((tcp_h->th_off) & 0xf0) >> 4)*4;
		  int total_ip_len = ntohs(ip_h->ip_len);
		  char buf[20];
//		  printf ("%x\n", ip_type);

		  printf ("\n-----------ETHERNET Header-----------\n");
		  printf ("Source Mac Address : ");
		  for (i=0; i<6; i++) {
					  printf ("%02x", ether->ether_shost[i]);
					  if (i != 5)
								  printf (" - ");
		  }
		  printf("\nDestintion Mac Address : ");

		  for (i=0; i<6; i++) {
					 printf("%02x", ether->ether_dhost[i]);
					 if (i != 5)
								printf(" - ");
		  }
		  printf("\n");
		  if (ntohs(ether->ether_type) == 0x0800) {
					 printf("\nNext Protocol is IPv4\n");
					 if (ip_type != 6) {
								switch (ip_type) {
										  case 1 :
										  	printf("\nProtocol : ICMP\n");
											break;
										  case 2 :
										  	printf("\nProtocol : IGMP\n");
											break;
										  case 17 :
										   printf("\nProtocol : UDP\n");
											break;
										  default :
										   printf("I don't know & I'll update for you\n");
								}
					 }
					 else {
							 printf ("\n-----------IP Header-----------\n");
							 printf ("Source IP : %s\n", inet_ntop(AF_INET, &(ip_h->ip_src), buf, sizeof(buf)));
							 printf ("Destination IP : %s\n", inet_ntop(AF_INET, &(ip_h->ip_dst), buf, sizeof(buf)));

							 printf ("\n4th layer Protocol is TCP\n");
					       printf ("\n-----------TCP Header-----------\n");
					       printf ("Source Port : %d\n", ntohs(tcp_h->tcp_sport));
					       printf ("Destination : %d\n", ntohs(tcp_h->tcp_dport));

							 printf("\ntotal ip len : %d\n", total_ip_len);
							 printf("ip header len : %d\n", ip_h_len);
							 printf("tcp header len : %d\n", tcp_h_len);

							 printf("\ndata len : %d\n", total_ip_len - (ip_h_len + tcp_h_len));

							 data = data + 14 + ip_h_len + tcp_h_len;
							 printf("\n--------------HTTP Stream----------\n");
							 printf("%s\n", data);
				 }
		  }
		  else if (ntohs(ether->ether_type) == 0x0806) {
					 printf("\nNext Protocol is ARP\n");
		  }
		  else {
					 printf("\nhum... I will update data\n");
		  }
}
