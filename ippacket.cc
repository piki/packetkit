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
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <glib.h>
#include "buffer.h"
#include "flags.h"
#include "icmppacket.h"
#include "ippacket.h"
#include "packet.h"
#include "tcppacket.h"
#include "token.h"
#include "udppacket.h"

static Flag flag_map[] = {
	{ 4, "RF" },
	{ 2, "DF" },
	{ 1, "MF" },
	{ 0, 0 }
};

IPPacket::IPPacket(void) {
	char buf[256];
	struct hostent *hent;
	gethostname(buf, sizeof(buf));
	hent = gethostbyname(buf);
	if (hent)
		memcpy(&src, hent->h_addr_list[0], sizeof(src));
	else {
		g_warning("IP: could not get host name to set default src");
		bzero(&src, sizeof(src));
	}
	bzero(&dst, sizeof(dst));
	version = 4;
	hlen = 5;
	len = 20;
	ttl = 64;
	tos = id = flags = frag_off = protocol = checksum = 0;
	payload = NULL;
}

IPPacket::IPPacket(const Buffer &b) {
	g_return_if_fail(b.length >= 20);
	//printf("IPPacket(");
	//b.print(20);
	//printf(")\n");
	version = (b.data[0] & 0xF0) >> 4;
	hlen = b.data[0] & 0x0F;
	tos = b.data[1];
	len = (b.data[2]<<8) + b.data[3];
	id = (b.data[4]<<8) + b.data[5];
	flags = (b.data[6] & 0xE0) >> 5;
	frag_off = ((b.data[6] & 0x1F) << 8) + b.data[7];
	ttl = b.data[8];
	protocol = b.data[9];
	checksum = (b.data[10] << 8) + b.data[11];
	memcpy(&src, &b.data[12], 4);
	memcpy(&dst, &b.data[16], 4);

	if (len > 4*hlen) {
		Buffer pb(b.data+4*hlen, len-4*hlen);
		switch (protocol) {
			case IP_IP:
				payload = new IPPacket(pb);
				break;
			case IP_ICMP:
				payload = new ICMPPacket(pb);
				break;
			case IP_TCP:
				payload = new TCPPacket(pb);
				break;
			case IP_UDP:
				payload = new UDPPacket(pb);
				break;
			default:
				g_warning("Unrecognized protocol %d.  Payload will be NULL.", protocol);
				payload = (Packet*)NULL;
		}
	}
}

IPPacket::~IPPacket(void) {
	if (payload) delete payload;
}

Buffer IPPacket::to_buffer(void) const {
	Buffer ret(20);
	ret.data[0] = (version << 4) + hlen;
	ret.data[1] = tos;
	ret.data[2] = (len >> 8) & 0xFF;
	ret.data[3] = len & 0xFF;
	ret.data[4] = (id >> 8) & 0xFF;
	ret.data[5] = id & 0xFF;
	ret.data[6] = (flags << 5) + ((frag_off >> 8) & 0x1F);
	ret.data[7] = frag_off & 0xFF;
	ret.data[8] = ttl;
	ret.data[9] = protocol;
	ret.data[10] = (checksum >> 8) & 0xFF;
	ret.data[11] = checksum & 0xFF;
	memcpy(&ret.data[12], &src, 4);
	memcpy(&ret.data[16], &dst, 4);

	if (payload) {
		Buffer pb = payload->to_buffer();
		ret.append(pb.data, pb.length);
	}
	
	return ret;
}

void IPPacket::print(FILE *fp) const {
	fprintf(fp, "IP(");
	if (version != 4) fprintf(fp, "version=%d ", version);
	if (hlen != 5) fprintf(fp, "header_length=%d ", hlen);
	if (tos) fprintf(fp, "tos=0x%x ", tos);
	fprintf(fp, "length=%d identification=0x%x ", len, id);
	if (flags) {
		fprintf(fp, "flags=");
		print_flags(fp, flags, flag_map);
		fprintf(fp, " ");
	}
	if (frag_off) fprintf(fp, "fragment_offset=%d ", frag_off);
	fprintf(fp, "ttl=%d ", ttl);
	struct protoent *pe = getprotobynumber(protocol);
	if (pe)
		fprintf(fp, "protocol=%s ", pe->p_name);
	else
		fprintf(fp, "protocol=%d ", protocol);
	/* print the checksum if it's wrong */
	fprintf(fp, "source=%s ", inet_ntoa(src));
	fprintf(fp, "destination=%s", inet_ntoa(dst));
	if (payload) {
		fprintf(fp, " payload=");
		payload->print(fp);
	}
	fprintf(fp, ")\n");
}

int IPPacket::get_length(void) const {
	return hlen*4 + (payload ? payload->get_length() : 0);
}

void IPPacket::set_field(const char *name, const char *value) {
	if (!strcasecmp(name, "version")) version = parse_number(value);
	else if (!strcasecmp(name, "hlen") || !strcasecmp(name, "header_length"))
		hlen = parse_number(value);
	else if (!strcasecmp(name, "tos")) tos = parse_number(value);
	else if (!strcasecmp(name, "len") || !strcasecmp(name, "length"))
		len = parse_number(value);
	else if (!strcasecmp(name, "id") || !strcasecmp(name, "identification"))
		id = parse_number(value);
	else if (!strcasecmp(name, "flags")) {
		if (isdigit((int)value[0]))
			flags = parse_number(value);
		else
			flags = parse_flags(value, flag_map);
	}
	else if (!strcasecmp(name, "fragment_offset"))
		frag_off = parse_number(value);
	else if (!strcasecmp(name, "ttl") || !strcasecmp(name, "time_to_live"))
		ttl = parse_number(value);
	else if (!strcasecmp(name, "protocol")) {
		if (isdigit((int)value[0]))
			protocol = parse_number(value);
		else {
			struct protoent *pe = getprotobyname(value);
			if (!pe)
				g_warning("Unknown protocol \"%s\"", value);
			else
				protocol = pe->p_proto;
		}
	}
	else if (!strcasecmp(name, "checksum")) checksum = parse_number(value);
	else if (!strcasecmp(name, "src") || !strcasecmp(name, "source"))
		inet_aton(value, &src);
	else if (!strcasecmp(name, "dst") || !strcasecmp(name, "destination"))
		inet_aton(value, &dst);
	else g_warning("IP: unknown field name \"%s\"", name);
}

void IPPacket::set_payload(Packet *payload) {
	if (this->payload) delete this->payload;
	this->payload = payload;
	len = hlen*4 + payload->get_length();
}

int IPPacket::get_port(void) const {
	switch (protocol) {
		case IP_TCP:
			return ((TCPPacket*)payload)->dport;
		case IP_UDP:
			return ((UDPPacket*)payload)->dport;
		default:
			return 0;
	}
}

void IPPacket::prepare(void) {
	len = hlen*4 + payload->get_length();
	checksum = 0;
	Buffer b = to_buffer();
	b.length = hlen*4;
	checksum = calculate_checksum(b);
	if (payload) payload->prepare();
	if (protocol == IP_TCP) {
		Buffer pseudo(12+payload->get_length());
		memcpy(&pseudo.data[0], &src, 4);
		memcpy(&pseudo.data[4], &dst, 4);
		pseudo.data[8] = 0;
		pseudo.data[9] = protocol;
		pseudo.data[10] = 0;
		pseudo.data[11] = 20;

		((TCPPacket*)payload)->checksum = 0;
		Buffer pb = payload->to_buffer();
		memcpy(&pseudo.data[12], &pb.data[0], pb.length);
		int cs = calculate_checksum(pseudo);
		printf("Setting TCP's checksum to %d\n", cs);
		((TCPPacket*)payload)->checksum = cs;
	}
}
