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
};

void print_ethernet_header_info (const u_char *data);
int print_ip_header_info (const u_char *data);
void print_tcp_header_info (const u_char *data);
void print_data (const u_char *data);

int main (int argc, char *argv[]) {
		  char *dev, errbuf[PCAP_ERRBUF_SIZE];
		  pcap_t *handle;
		  struct bpf_program fp;
		  char filter_exp[] = "port 80";
		  struct pcap_pkthdr *header;
		  const u_char *packet;
		  int res;
		  bpf_u_int32 net;
		 		  
		  dev = pcap_lookupdev(errbuf);
		  if (dev == NULL) {
					 fprintf (stderr, "Couldn't find default device : %s\n", errbuf);
					 return(2);
		  }
		  printf("Device : %s\n", dev);

		  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
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
					 print_ethernet_header_info(packet);
					 packet = packet + 14;
					 print_ip_header_info(packet);
					 packet = packet + print_ip_header_info(packet);
					 print_tcp_header_info(packet);
					 packet = packet + 20;
					 print_data(packet);
			}
		pcap_freecode(&fp);
		pcap_close(handle);		
}

void print_ethernet_header_info (const u_char *data) {
		  struct _ethernet *ether = (struct _ethernet *) data;

		  if (ntohs(ether->ether_type) == 0x0800) {
					 printf("Next Protocol is IPv4\n");
		  }
		  else if (ntohs(ether->ether_type) == 0x0806) {
					 printf("Next Protocol is ARP\n");
		  }
		  else
					 printf("hum... I will update data\n");

		  printf ("\n-----------ETHERNET Header-----------\n");
		  printf ("Source Mac Address : %02x - %02x - %02x - %02x - %02x - %02x\n", ether->ether_shost[0], ether->ether_shost[1], ether->ether_shost[2], ether->ether_shost[3], ether->ether_shost[4], ether->ether_shost[5]);
		  printf("Destination Mac Address : %02x - %02x - %02x - %02x - %02x - %02x\n", ether->ether_dhost[0], ether->ether_dhost[1], ether->ether_dhost[2], ether->ether_dhost[3], ether->ether_dhost[4], ether->ether_dhost[5]);
}

int print_ip_header_info (const u_char *data) {
		  struct _ip *ip_h = (struct _ip *) data;

		  switch (ip_h->ip_proto) {
					 case 1 :
					 	printf("\nProtocol : ICMP\n");
						break;
					 case 2 :
					 	printf("\nProtocol : IGMP\n");
						break ;
					 case 6 : 
						printf("\nProtocol : TCP\n");
						break ;
					 case 17 :
						printf("\nProtocol : UDP\n");
						break;
 					 default : 
						printf("\nProtocol : I don't know\n");
		  }

		  printf ("\n-----------IP Header-----------\n");
		  printf ("Source IP : %s\n", inet_ntoa(ip_h->ip_src));
		  printf ("Destination IP : %s\n", inet_ntoa(ip_h->ip_dst));

		  return ip_h->ip_vhl*4;
}

void print_tcp_header_info (const u_char *data) {
		  struct _tcp *tcp_h = (struct _tcp *) data;

		  printf ("\n-----------TCP Header-----------\n");
		  printf ("Source Port : %s\n", ntohs(tcp_h -> tcp_sport));
		  printf ("Destination : %s\n", ntohs(tcp_h -> tcp_dport));
}

void print_data (const u_char *data) {
		  printf("--------------HTTP Stream----------\n");
		  printf("%s\n", data);
}
