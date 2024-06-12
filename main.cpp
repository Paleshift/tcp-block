#include <cstdio>
#include <pcap.h>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

#include <fstream>
#include <iostream>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <net/if.h>
#include <unistd.h>


void usage() {
	printf("syntax: tcp-block <interface> <pattern>\n");
	printf("sample: tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

//+++++
bool get_s_mac(char* dev, char* mac){
	std::string mac_addr;
	std::ifstream mac_file("/sys/class/net/" + std::string(dev) + "/address");
	std::string str((std::istreambuf_iterator<char>(mac_file)), std::istreambuf_iterator<char>());

	if(str.length() > 0){
		strcpy(mac, str.c_str());
		return true;
	}

	return false;
}
//+++++

//+++++
typedef struct Pseudo_Header {
    uint32_t s_ip;
    uint32_t d_ip;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_len;
}pseudohdr;

uint16_t Checksum(uint16_t* buffer, int size){
	uint32_t checksum = 0;
	uint16_t odd = 0;

	while (size > 1){
		checksum += *buffer++;
		size -= sizeof(uint16_t);
	}

	if(size){
		checksum += *(uint16_t*)buffer;
	}

	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);

	return (uint16_t)(~checksum);
}
//+++++

int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char* pattern = argv[2];

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	/////
	char s_mac[Mac::SIZE];
	if(get_s_mac(dev, s_mac)){
		printf("My MAC address = %s\n", s_mac);
	}
	else{
		printf("Couldn't get my MAC address\n");
		return -1;
	}
	/////

	printf("Blocking \"%s\"..\n", pattern);

	while(true){
			struct pcap_pkthdr* header;
			const u_char* packet;

			int res = pcap_next_ex(handle, &header, &packet);

			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}

			EthHdr *ethernet_hdr = (EthHdr*) packet;
			if(ethernet_hdr->type() == EthHdr::Ip4){
				//First, check whether 'packet' is Ip4 or not.
				
				IpHdr *ip_hdr = (IpHdr*)(packet + sizeof(EthHdr));
				
				uint32_t ip_hdr_len = ip_hdr->ihl * 4;
            	uint32_t ip_pkt_len = ntohs(ip_hdr->total_length);

            	uint32_t ethernet_pkt_len = sizeof(EthHdr) + ip_pkt_len;

				if(ip_hdr->protocol == 6){
					//Second, check whether 'packet' is TCP or not.

					TcpHdr *tcp_hdr = (TcpHdr*)(packet + sizeof(EthHdr) + ip_hdr_len);

					uint32_t tcp_hdr_len = tcp_hdr->offset * 4;
                 	uint32_t tcp_payload_len = ip_pkt_len - (ip_hdr_len + tcp_hdr_len);

					if(tcp_payload_len == 0){
						continue;
					}

					char* tcp_payload = (char*)malloc(tcp_payload_len + 1);
               	 	memset(tcp_payload, 0, tcp_payload_len + 1);
                	strncpy(tcp_payload, (char*)((uint8_t*)tcp_hdr + tcp_hdr_len), tcp_payload_len);

					if(strstr(tcp_payload, pattern) && (strncmp(tcp_payload, "GET", 3) == 0)){
						//"strstr(tcp_payload, pattern)" -> Check whether "tcp_payload" has "pattern" or not
						//"(strncmp(tcp_payload, "GET ", 4) == 0)" -> Check whether Request Method is GET or not


						///// Forward Block Packet (To Server)
						uint32_t fbp_ethernet_pkt_len = sizeof(EthHdr) + ip_hdr_len + tcp_hdr_len;
						//Define length

						char* fbp_ethernet_pkt = (char*)malloc(fbp_ethernet_pkt_len + 1);
						//Define "fbp_ethernet_pkt"(= Forward Block Packet)
						memset(fbp_ethernet_pkt, 0, fbp_ethernet_pkt_len + 1);
						memcpy(fbp_ethernet_pkt, packet, fbp_ethernet_pkt_len);

						EthHdr* fbp_ethernet_hdr = (EthHdr*)fbp_ethernet_pkt;
						IpHdr* fbp_ip_hdr = (IpHdr*)(fbp_ethernet_pkt + sizeof(EthHdr));
						TcpHdr* fbp_tcp_hdr = (TcpHdr*)(fbp_ethernet_pkt + sizeof(EthHdr) + ip_hdr_len);
						//Define all headers

						fbp_ethernet_hdr->smac_ = Mac(s_mac);
						//Set Ethernet Header

    					fbp_ip_hdr->total_length = htons(ip_hdr_len + sizeof(TcpHdr));
						fbp_ip_hdr->checksum = 0;
						//Set IP Header

						fbp_tcp_hdr->offset = sizeof(TcpHdr) / 4;
						fbp_tcp_hdr->seq_number = htonl(ntohl(tcp_hdr->seq_number) + tcp_payload_len);
						fbp_tcp_hdr->tcp_flags = 0b00010100;
						fbp_tcp_hdr->checksum = 0;
						//Set TCP Header

						fbp_ip_hdr->checksum = Checksum((uint16_t*)fbp_ip_hdr, ip_hdr_len);


						pseudohdr* pseudo_hdr = (pseudohdr*)malloc(sizeof(pseudohdr) + 1);
						memset(pseudo_hdr, 0, sizeof(pseudohdr) + 1);

						pseudo_hdr->s_ip = ip_hdr->sip_;
    					pseudo_hdr->d_ip = ip_hdr->dip_;
    					pseudo_hdr->protocol = IPPROTO_TCP;
    					pseudo_hdr->tcp_len = htons(sizeof(TcpHdr));


						uint32_t fbp_tcp_checksum = Checksum((uint16_t*)fbp_tcp_hdr, sizeof(TcpHdr)) + Checksum((uint16_t*)pseudo_hdr, sizeof(pseudohdr));
						
						fbp_tcp_hdr->checksum = (fbp_tcp_checksum & 0xffff) + (fbp_tcp_checksum >> 16);
						// "(fbp_tcp_checksum & 0xffff)" makes "fbp_tcp_checksum" 16Bit.
						// "+ (fbp_tcp_checksum >> 16)" -> Wrapped around if "fbp_tcp_checksum" has carry
						
						if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(fbp_ethernet_pkt), fbp_ethernet_pkt_len)){
							fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
						}

						printf("\nSending Forward Block Packet Success!\n");
						
						free(pseudo_hdr);
                    	free(fbp_ethernet_pkt);
						///// Forward Block Packet (To Server)


						///// Backward Block Packet (To Client)
						uint16_t bbp_ip_hdr_len = sizeof(IpHdr);
						uint16_t bbp_tcp_hdr_len = sizeof(TcpHdr);

						const char* bbp_tcp_payload = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
						uint16_t bbp_tcp_payload_len = strlen(bbp_tcp_payload);

                    	uint16_t bbp_ip_pkt_len = bbp_ip_hdr_len + bbp_tcp_hdr_len + bbp_tcp_payload_len;
						//Define all lengths

						char *bbp_ip_pkt = (char*)malloc(bbp_ip_pkt_len + 1);
						memset(bbp_ip_pkt, 0, bbp_ip_pkt_len + 1);
						//Define "bbp_ip_pkt"(= Backward Block Packet)

						IpHdr* bbp_ip_hdr = (IpHdr*)bbp_ip_pkt;
						TcpHdr* bbp_tcp_hdr = (TcpHdr*)(bbp_ip_pkt + bbp_ip_hdr_len);
						//Define all headers

						memcpy(bbp_ip_pkt + bbp_ip_hdr_len + bbp_tcp_hdr_len, bbp_tcp_payload, bbp_tcp_payload_len);


						bbp_ip_hdr->ihl = bbp_ip_hdr_len/4;
    					bbp_ip_hdr->version = 4;

    					bbp_ip_hdr->total_length = htons(bbp_ip_pkt_len);
    					bbp_ip_hdr->ttl = 128;
						bbp_ip_hdr->protocol = 6;
    					bbp_ip_hdr->sip_ = ip_hdr->dip_;
    					bbp_ip_hdr->dip_ = ip_hdr->sip_;
						//Set IP Header

						bbp_tcp_hdr->s_port = tcp_hdr->d_port;
						bbp_tcp_hdr->d_port = tcp_hdr->s_port;
						bbp_tcp_hdr->seq_number = tcp_hdr->ack_number;
						bbp_tcp_hdr->ack_number = htonl(ntohl(tcp_hdr->seq_number) + tcp_payload_len);

						bbp_tcp_hdr->offset = bbp_tcp_hdr_len / 4;

						bbp_tcp_hdr->tcp_flags = 0b00010001;
						//Set ACK and FIN
						//Reset SYN
						bbp_tcp_hdr->window = htons(5840);
						//Set TCP Header

						bbp_ip_hdr->checksum = Checksum((uint16_t*)bbp_ip_hdr, bbp_ip_hdr_len);


						pseudo_hdr = (pseudohdr*)malloc(sizeof(pseudohdr) + 1);
						memset(pseudo_hdr, 0, sizeof(pseudohdr) + 1);

						pseudo_hdr->s_ip = ip_hdr->dip_;
    					pseudo_hdr->d_ip = ip_hdr->sip_;
    					pseudo_hdr->protocol = IPPROTO_TCP;
    					pseudo_hdr->tcp_len = htons(bbp_tcp_hdr_len + bbp_tcp_payload_len);


						uint32_t bbp_tcp_checksum = Checksum((uint16_t*)bbp_tcp_hdr, bbp_tcp_hdr_len + bbp_tcp_payload_len) + Checksum((uint16_t*)pseudo_hdr, sizeof(pseudohdr));
						
						bbp_tcp_hdr->checksum = (bbp_tcp_checksum & 0xffff) + (bbp_tcp_checksum >> 16);
						// "(bbp_tcp_checksum & 0xffff)" makes "bbp_tcp_checksum" 16Bit.
						// "+ (bbp_tcp_checksum >> 16)" -> Wrapped around if "bbp_tcp_checksum" has carry


						int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
						// AF_INET -> Ip4
						// SOCK_RAW -> Low-level socket control protocol
                    	char optval = 0x01;
                    	setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));
						//Set "raw_sock"'s option value by setsockopt()
						//Set level as "IPPROTO_IP" because of "IP_HDRINCL"
						//"IP_HDRINCL" -> Include IP Header when sending data

						struct sockaddr_in raw_addr;
						raw_addr.sin_family = AF_INET;
						raw_addr.sin_port = tcp_hdr->s_port;
						raw_addr.sin_addr.s_addr = (uint32_t)ip_hdr->sip_;
						//Use raw socket
						
						if (sendto(raw_sock, bbp_ip_pkt, bbp_ip_pkt_len, 0, (struct sockaddr *)&raw_addr, sizeof(raw_addr)) < 0){
							perror("Sending Backward Block Packet Failed..\n");
                        	return -1;
						}
						
						printf("Sending Backward Block Packet Success!\n");

                    	free(pseudo_hdr);
                    	free(bbp_ip_pkt);
                    	close(raw_sock);
						///// Backward Block Packet (To Client)

					}
					//End of 3rd "if"

				}
				//End of 2nd "if"

			}
			//End of 1st "if"

		}
		//End of "while"

}