/* PacketKit - sniffer, packet generator, and GUI for Linux
 * Copyright (C) 2001 by Patrick Reynolds
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License
 * along with this library; if not, write to the Free
 * Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include "packet.h"

int fd;

void send(FILE *fp) {
	Packet *p;
	
	while ((p = parse(fp)) != NULL) {
		struct sockaddr_in sin;
		p->prepare();
		Buffer b = p->to_buffer();
		printf("buffer = { ");
		b.print();
		printf(" }\n");
		sin.sin_family = AF_INET;
		sin.sin_port = p->get_port();
		sin.sin_addr = p->get_dest();
		if (sendto(fd, b.data, b.length, 0, (struct sockaddr*)&sin,
				sizeof(sin)) == -1)
			perror("sendto");
	}
}

int make_raw_socket() {
	int fd;
	if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("raw socket");
		exit(1);
	}
	return fd;
}

int main(int argc, char **argv) {
	int i;
	fd = make_raw_socket();
	for (i=1; i<argc; i++) {
		FILE *fp = fopen(argv[i], "r");
		if (!fp)
			perror(argv[i]);
		else {
			send(fp);
			fclose(fp);
		}
	}
	close(fd);
	return 0;
}
