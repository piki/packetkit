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

#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <glib.h>
#include "icmppacket.h"
#include "ippacket.h"
#include "packet.h"
#include "tcppacket.h"
#include "token.h"
#include "udppacket.h"

static int hex_digit(char c) {
	if (c >= '0' && c <= '9') return c-'0';
	if (c >= 'A' && c <= 'F') return c-'A'+10;
	if (c >= 'a' && c <= 'f') return c-'a'+10;
	g_warning("Bad hex digit '%c'", c);
	return -1;
}

Packet *parse(FILE *fp) {
	GString *s;
	Packet *ret = NULL;
	s = next_token(fp, ") \t\n\r", "(");
	if (!strcasecmp(s->str, "ICMP"))
		ret = new ICMPPacket();
	else if (!strcasecmp(s->str, "IP"))
		ret = new IPPacket();
	else if (!strcasecmp(s->str, "TCP"))
		ret = new TCPPacket();
	else if (!strcasecmp(s->str, "UDP"))
		ret = new UDPPacket();
	else if (!strcmp(s->str, ""))
		ret = NULL;
	else
		g_warning("Invalid packet code \"%s\".  Returning NULL.", s->str);
	g_string_free(s, TRUE);
	if (!ret) return NULL;

	s = next_token(fp, " \t\r\n", "=)");
	while (s && s->str && *s->str) {
		char *key, *value = NULL;
		key = s->str;
		g_string_free(s, FALSE);
		if (!strcasecmp(key, "payload")) {
			Packet *payload = parse(fp);
			ret->set_payload(payload);
		}
		else if (!strcasecmp(key, "data")) {
			s = next_token(fp, "( ", ")");
			Buffer b(s->len/2);
			for (size_t i=0; i<s->len; i+=2)
				b.data[i/2] = (hex_digit(s->str[i])<<4) + hex_digit(s->str[i+1]);
			ret->set_data(b);
			g_string_free(s, TRUE);
		}
		else {
			s = next_token(fp, "", " \t\r\n)");
			if (s) {
				value = s->str;
				g_string_free(s, FALSE);
			}
			ret->set_field(key, value);
		}
		g_free(key);
		if (value) g_free(value);

		s = next_token(fp, " \t\r\n", "=)");
	}
	if (s) g_string_free(s, TRUE);
	
	return ret;
}

static unsigned int cksum(const unsigned short *ptr, int nbytes) {
	long sum = 0;
	u_short oddbyte;
	u_short answer;

	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char *)&oddbyte) = *(u_char *)ptr;
		sum += oddbyte;
	}
	sum += (sum >> 16);
	answer = ~sum;
	return answer;
}

unsigned int calculate_checksum(const Buffer &b) {
	unsigned int sum = cksum((const unsigned short *)b.data, b.length);
	return ((sum & 0xFF) << 8) + ((sum & 0xFF00) >> 8);
}

void Packet::set_payload(Packet *payload) {
	g_warning("set_payload not implemented for this packet type.");
	delete payload;
}

void Packet::set_data(const Buffer &b) {
	g_warning("set_data not implemented for this packet type.");
}

int Packet::get_port(void) const {
	g_warning("get_port not implemented for this packet type.");
	return 0;
}

void Packet::prepare(void) { }

struct in_addr Packet::get_dest(void) const {
	struct in_addr ret;
	g_warning("get_dest not implemented for this packet type.");
	bzero(&ret, sizeof(ret));
	return ret;
}
