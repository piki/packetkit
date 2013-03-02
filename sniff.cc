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

#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <signal.h>
#if __GLIBC__ >= 2
#include <net/ethernet.h>
#include <netinet/tcp.h>
#else
#include <linux/if_ether.h>
#include <linux/tcp.h>
#endif
#include <net/if.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include "buffer.h"
#include "ippacket.h"

#define DEBUG

#define DEFAULT_DEVICE "eth0"

void die(int ignored);

int init_socket(const char *device);
void done_socket(int fd, const char *device);

static int quit = 0;
static int old_eth_flags;

void hostup(unsigned long hst, int size);
void htprint();
void htdone();

int main(int argc, char **argv) {
  int sock;
  const char *device = DEFAULT_DEVICE;
	unsigned char buf[70000];
  int size;

#if 0
  signal(SIGINT, die);
  signal(SIGTERM, die);
  signal(SIGABRT, die);
  signal(SIGHUP, die);
  signal(SIGALRM, die);
#endif

  sock = init_socket(device);

  while (!quit) {
    if ((size = recv(sock, buf, sizeof(buf), 0))) {
			if (buf[12] != 0x08 || buf[13] != 0x00) continue;  /* not IP */
			Buffer b(buf+14, size-14);
			printf("buffer = { "); b.print(); printf(" }\n");
			IPPacket ip(b);
			ip.print(stdout);
    }
	}

  done_socket(sock, device);

  return 0;
}

int init_socket(const char *device) {
  struct ifreq iface_request;
	struct sockaddr_pkt spkt;
  int fd;

  /* open a raw IP socket */
  //if ((fd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_IP))) < 0) {
  if ((fd = socket(AF_INET, SOCK_PACKET, 0x300)) < 0) {
    perror("init_socket: socket");
    exit(-1);
  }

	spkt.spkt_family = PF_INET;
	strcpy((char*)spkt.spkt_device, DEFAULT_DEVICE);
	spkt.spkt_protocol = 0;
	if (bind(fd, (struct sockaddr*)&spkt, 16) == -1) {
		perror("bind");
		exit(1);
	}

  /* get device flags for this socket / the device */
  strcpy(iface_request.ifr_name, device);
  if ((ioctl(fd, SIOCGIFFLAGS, &iface_request)) < 0) {
    perror("init_socket: ioctl(get)");
    close(fd);
    exit(-1);
  }

#if 0
  /* set promiscuous mode */
  old_eth_flags = iface_request.ifr_flags;
  iface_request.ifr_flags |= IFF_PROMISC;
  if ((ioctl(fd, SIOCSIFFLAGS, &iface_request)) < 0) {
    perror("init_socket: ioctl(set)");
    close(fd);
    exit(-1);
  }
#endif

  return fd;
}

void done_socket(int fd, const char *device) {
  struct ifreq iface_request;

  /* raw IP socket is already open */

  /* get device flags for this socket / the device */
  strcpy(iface_request.ifr_name, device);
  if ((ioctl(fd, SIOCGIFFLAGS, &iface_request)) < 0) {
    perror("done_socket: ioctl(get)");
    close(fd);
    exit(-1);
  }

  /* unset promiscuous mode, if necessary */
  iface_request.ifr_flags = old_eth_flags;
  if ((ioctl(fd, SIOCSIFFLAGS, &iface_request)) < 0) {
    perror("done_socket: ioctl(set)");
    close(fd);
    exit(-1);
  }

  close(fd);
}

void die(int ignored) {
  quit = 1;
#ifdef DEBUG
  printf("signal %d received, aborting.\n", ignored);
#endif
}
