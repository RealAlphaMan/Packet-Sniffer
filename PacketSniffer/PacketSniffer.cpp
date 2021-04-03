
#include "stdafx.h"
#include "sniff_function.h"


int main() {
	SOCKET sniffer;
	IN_ADDR addr;
	int choosenInterface;

	char hostname[100];
	struct hostent *local;
	WSADATA wsaData;

	logSniffer = fopen("Sniffer.txt", "w");
	if (logSniffer == NULL) {
		printf("Unable to create file.");
	}

	//Initiate Winsock
	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2, 2), &wsaData)) {
		printf("Cannot initiate winsock with error %d\n", WSAGetLastError());
		return 1;
	}

	//Create a RAW Socket
	sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (sniffer == INVALID_SOCKET) {
		printf("Cannot create raw socket with error %d.\n", WSAGetLastError());
		return 1;
	}

	//Retrive the local host name
	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
		printf("Cannot get host name with error %d\n", WSAGetLastError());
		return 1;
	}

	printf("\nHost name: %s \n", hostname);

	//Get available IP of host
	local = gethostbyname(hostname);
	if (local == NULL) {
		printf("Cannot get host by name with error %d.\n", WSAGetLastError());
		return 1;
	}

	printf("\nAvailable Network Interfaces:\n");

	for (int i = 0; local->h_addr_list[i] != 0; ++i) {
		memcpy(&addr, local->h_addr_list[i], sizeof(IN_ADDR));
		printf("Interface Number %d: Address: %s\n", i, inet_ntoa(addr));
	}

	printf("Enter the interface number you would like to sniff: ");
	scanf("%d", &choosenInterface);

	// Bind socket with address
	memset(&dest, 0, sizeof(dest));
	memcpy(&dest.sin_addr.s_addr, local->h_addr_list[choosenInterface], sizeof(dest.sin_addr.s_addr));
	dest.sin_family = AF_INET;
	dest.sin_port = 0;

	if (bind(sniffer, (struct sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR) {
		printf("Cannot bind to %s with error %d.\n", inet_ntoa(addr), WSAGetLastError());
		return 1;
	}
	printf("Bind successful");

	// Setting sniffer mode
	int j = 1;
	if (WSAIoctl(sniffer, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD)&choosenInterface, 0, 0) == SOCKET_ERROR) { // Enable sniffing with macro SIO_RCVALL
		printf("Cannot sniffing with error %d.\n", WSAGetLastError());
		return 1;
	}

	//Begin
	printf("\nStarted Sniffing\n");
	printf("Packet Capture Statistics...\n");
	StartSniffing(sniffer);

	// End
	closesocket(sniffer);
	WSACleanup();

	return 0;
}
