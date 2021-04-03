

#include<stdio.h>
#include<WinSock2.h>
#include<mstcpip.h>
#include "packet_struct.h"

#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)

FILE *logSniffer;
int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0;
SOCKADDR_IN source, dest;
IPV4_HDR *ip_header;
TCP_HDR *tcp_header;
UDP_HDR *udp_header;
ICMP_HDR *icmp_header;

void StartSniffing(SOCKET); //This will sniff here and there

void ClassifyPacket(char*, int); //This will decide how to digest
void Printip_header(char*);
void PrintIcmpPacket(char*, int);
void PrintUdpPacket(char*, int);
void PrintTcpPacket(char*, int);
void PrintData(char*, int);


void StartSniffing(SOCKET sniffer) {
	char *buff = (char *)malloc(65536);
	int receivedByte;

	if (buff == NULL) {
		printf("Cannot dynamic allocate memory\n");
		return;
	}

	do {
		receivedByte = recvfrom(sniffer, buff, 65536, 0, 0, 0); //Receive as much as buffer can
		if (receivedByte > 0) {
			// Classify packet received and write to log
			ClassifyPacket(buff, receivedByte);
		}
		else {
			printf("Cannot receive data with error %d.\n", WSAGetLastError());
		}
	} while (receivedByte > 0);

	free(buff);
}

void ClassifyPacket(char* Buffer, int Size) {
	ip_header = (IPV4_HDR *)Buffer;
	total++;

	switch (ip_header->ip_protocol) { //Check the Protocol
	case 1: //ICMP Protocol
		icmp++;
		PrintIcmpPacket(Buffer, Size);
		break;

	case 2: //IGMP Protocol
		igmp++;
		break;

	case 6: //TCP Protocol
		tcp++;
		PrintTcpPacket(Buffer, Size);
		break;

	case 17: //UDP Protocol
		udp++;
		PrintUdpPacket(Buffer, Size);
		break;

	default: //Other Protocol
		others++;
		break;
	}
	printf("TCP:%d  UDP:%d  ICMP:%d  IGMP:%d  Others:%d  Total:%d\r", tcp, udp, icmp, igmp, others, total);
}

void Printip_header(char* Buffer) {
	unsigned short ip_header_len;

	ip_header = (IPV4_HDR *)Buffer;
	ip_header_len = ip_header->ip_header_len * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip_header->ip_srcaddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip_header->ip_destaddr;

	fprintf(logSniffer, "\nIP Header\n");
	fprintf(logSniffer, " |-IP Version : %d\n", (unsigned int)ip_header->ip_version);
	fprintf(logSniffer, " |-IP Header Length : %d DWORDS or %d Bytes\n", (unsigned int)ip_header->ip_header_len, ((unsigned int)(ip_header->ip_header_len)) * 4);
	fprintf(logSniffer, " |-Type Of Service : %d\n", (unsigned int)ip_header->ip_tos);
	fprintf(logSniffer, " |-IP Total Length : %d Bytes(Size of Packet)\n", ntohs(ip_header->ip_total_length));
	fprintf(logSniffer, " |-Identification : %d\n", ntohs(ip_header->ip_id));
	fprintf(logSniffer, " |-Reserved ZERO Field : %d\n", (unsigned int)ip_header->ip_reserved_zero);
	fprintf(logSniffer, " |-Dont Fragment Field : %d\n", (unsigned int)ip_header->ip_dont_fragment);
	fprintf(logSniffer, " |-More Fragment Field : %d\n", (unsigned int)ip_header->ip_more_fragment);
	fprintf(logSniffer, " |-TTL : %d\n", (unsigned int)ip_header->ip_ttl);
	fprintf(logSniffer, " |-Protocol : %d\n", (unsigned int)ip_header->ip_protocol);
	fprintf(logSniffer, " |-Checksum : %d\n", ntohs(ip_header->ip_checksum));
	fprintf(logSniffer, " |-Source IP : %s\n", inet_ntoa(source.sin_addr));
	fprintf(logSniffer, " |-Destination IP : %s\n", inet_ntoa(dest.sin_addr));
}

void PrintTcpPacket(char* Buffer, int Size) {
	unsigned short ip_header_len;

	ip_header = (IPV4_HDR *)Buffer;
	ip_header_len = ip_header->ip_header_len * 4;

	tcp_header = (TCP_HDR*)(Buffer + ip_header_len);

	fprintf(logSniffer, "\n\n***********************TCP Packet*************************\n");

	Printip_header(Buffer);

	fprintf(logSniffer, "\nTCP Header\n");
	fprintf(logSniffer, " |-Source Port : %u\n", ntohs(tcp_header->source_port));
	fprintf(logSniffer, " |-Destination Port : %u\n", ntohs(tcp_header->dest_port));
	fprintf(logSniffer, " |-Sequence Number : %u\n", ntohl(tcp_header->sequence));
	fprintf(logSniffer, " |-Acknowledge Number : %u\n", ntohl(tcp_header->acknowledge));
	fprintf(logSniffer, " |-Header Length : %d DWORDS or %d BYTES\n", (unsigned int)tcp_header->data_offset, (unsigned int)tcp_header->data_offset * 4);
	fprintf(logSniffer, " |-CWR Flag : %d\n", (unsigned int)tcp_header->cwr);
	fprintf(logSniffer, " |-ECN Flag : %d\n", (unsigned int)tcp_header->ecn);
	fprintf(logSniffer, " |-Urgent Flag : %d\n", (unsigned int)tcp_header->urg);
	fprintf(logSniffer, " |-Acknowledgement Flag : %d\n", (unsigned int)tcp_header->ack);
	fprintf(logSniffer, " |-Push Flag : %d\n", (unsigned int)tcp_header->psh);
	fprintf(logSniffer, " |-Reset Flag : %d\n", (unsigned int)tcp_header->rst);
	fprintf(logSniffer, " |-Synchronise Flag : %d\n", (unsigned int)tcp_header->syn);
	fprintf(logSniffer, " |-Finish Flag : %d\n", (unsigned int)tcp_header->fin);
	fprintf(logSniffer, " |-Window : %d\n", ntohs(tcp_header->window));
	fprintf(logSniffer, " |-Checksum : %d\n", ntohs(tcp_header->checksum));
	fprintf(logSniffer, " |-Urgent Pointer : %d\n", tcp_header->urgent_pointer);
	fprintf(logSniffer, "\n DATA Dump \n");

	fprintf(logSniffer, "IP Header\n");
	PrintData(Buffer, ip_header_len);

	fprintf(logSniffer, "TCP Header\n");
	PrintData(Buffer + ip_header_len, tcp_header->data_offset * 4);

	fprintf(logSniffer, "Data Payload\n");
	PrintData(Buffer + ip_header_len + tcp_header->data_offset * 4
		, (Size - tcp_header->data_offset * 4 - ip_header->ip_header_len * 4));

	fprintf(logSniffer, "\n###########################################################");
}

void PrintUdpPacket(char *Buffer, int Size) {
	unsigned short ip_header_len;

	ip_header = (IPV4_HDR *)Buffer;
	ip_header_len = ip_header->ip_header_len * 4;

	udp_header = (UDP_HDR *)(Buffer + ip_header_len);

	fprintf(logSniffer, "\n\n***********************UDP Packet*************************\n");

	Printip_header(Buffer);

	fprintf(logSniffer, "\nUDP Header\n");
	fprintf(logSniffer, " |-Source Port : %d\n", ntohs(udp_header->source_port));
	fprintf(logSniffer, " |-Destination Port : %d\n", ntohs(udp_header->dest_port));
	fprintf(logSniffer, " |-UDP Length : %d\n", ntohs(udp_header->udp_length));
	fprintf(logSniffer, " |-UDP Checksum : %d\n", ntohs(udp_header->udp_checksum));

	fprintf(logSniffer, "\nIP Header\n");

	PrintData(Buffer, ip_header_len);

	fprintf(logSniffer, "UDP Header\n");

	PrintData(Buffer + ip_header_len, sizeof(UDP_HDR));

	fprintf(logSniffer, "Data Payload\n");

	PrintData(Buffer + ip_header_len + sizeof(UDP_HDR), (Size - sizeof(UDP_HDR) - ip_header->ip_header_len * 4));

	fprintf(logSniffer, "\n###########################################################");
}

void PrintIcmpPacket(char* Buffer, int Size) {
	unsigned short ip_header_len;

	ip_header = (IPV4_HDR *)Buffer;
	ip_header_len = ip_header->ip_header_len * 4;

	icmp_header = (ICMP_HDR*)(Buffer + ip_header_len);

	fprintf(logSniffer, "\n\n***********************ICMP Packet*************************\n");
	Printip_header(Buffer);

	fprintf(logSniffer, "\n");

	fprintf(logSniffer, "ICMP Header\n");
	fprintf(logSniffer, " |-Type : %d", (unsigned int)(icmp_header->type));

	if ((unsigned int)(icmp_header->type) == 11) {
		fprintf(logSniffer, " (TTL Expired)\n");
	}
	else if ((unsigned int)(icmp_header->type) == 0) {
		fprintf(logSniffer, " (ICMP Echo Reply)\n");
	}

	fprintf(logSniffer, " |-Code : %d\n", (unsigned int)(icmp_header->code));
	fprintf(logSniffer, " |-Checksum : %d\n", ntohs(icmp_header->checksum));
	fprintf(logSniffer, " |-ID : %d\n", ntohs(icmp_header->id));
	fprintf(logSniffer, " |-Sequence : %d\n", ntohs(icmp_header->seq));
	fprintf(logSniffer, "\n");

	fprintf(logSniffer, "IP Header\n");
	PrintData(Buffer, ip_header_len);

	fprintf(logSniffer, "UDP Header\n");
	PrintData(Buffer + ip_header_len, sizeof(ICMP_HDR));

	fprintf(logSniffer, "Data Payload\n");
	PrintData(Buffer + ip_header_len + sizeof(ICMP_HDR), (Size - sizeof(ICMP_HDR) - ip_header->ip_header_len * 4));

	fprintf(logSniffer, "\n###########################################################");
}

// Print hex data
void PrintData(char* data, int Size) {
	char a, line[17], c;
	int j;

	//loop over each character and print
	for (int i = 0; i < Size; i++) {
		c = data[i];

		//Print the hex value for every character , with a space. Important to make unsigned
		fprintf(logSniffer, " %.2x", (unsigned char)c);

		//Add the character to data line. Important to make unsigned
		a = (c >= 32 && c <= 128) ? (unsigned char)c : '.';
		line[i % 16] = a;

		//if last character of a line , then print the line - 16 characters in 1 line
		if ((i != 0 && (i + 1) % 16 == 0) || i == Size - 1) {
			line[i % 16 + 1] = '\0';

			//print a big gap of 10 characters between hex and characters
			fprintf(logSniffer, "          ");

			//Print additional spaces for last lines which might be less than 16 characters in length
			for (j = strlen(line); j < 16; j++) {
				fprintf(logSniffer, "   ");
			}

			fprintf(logSniffer, "%s \n", line);
		}
	}

	fprintf(logSniffer, "\n");
}