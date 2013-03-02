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
#include <glib.h>
#include "buffer.h"
#include "flags.h"
#include "packet.h"
#include "tcppacket.h"
#include "token.h"

static Flag flag_map[] = {
	{ 32, "URG" },
	{ 16, "ACK" },
	{ 8, "PSH" },
	{ 4, "RST" },
	{ 2, "SYN" },
	{ 1, "FIN" },
	{ 0, 0 }
};

TCPPacket::TCPPacket(void) {
	hlen = 5;
	sport = dport = seq = ack = flags = window = checksum = urg = 0;
}

TCPPacket::TCPPacket(const Buffer &b) {
	g_return_if_fail(b.length >= 20);
	//printf("TCPPacket(");
	//b.print(20);
	//printf(")\n");
	sport = (b.data[0]<<8) + b.data[1];
	dport = (b.data[2]<<8) + b.data[3];
	seq = (b.data[4]<<24) + (b.data[5]<<16) + (b.data[6]<<8) + b.data[7];
	ack = (b.data[8]<<24) + (b.data[9]<<16) + (b.data[10]<<8) + b.data[11];
	hlen = (b.data[12] & 0xF0) >> 4;
	flags = b.data[13] & 0x3F;
	window = (b.data[14]<<8) + b.data[15];
	checksum = (b.data[16]<<8) + b.data[17];
	urg = (b.data[18]<<8) + b.data[19];

	if (b.length > 4*hlen)
		data.set(b.data+4*hlen, b.length-4*hlen);
}

Buffer TCPPacket::to_buffer(void) const {
	Buffer ret(20);
	ret.data[0] = (sport >> 8) & 0xFF;
	ret.data[1] = sport & 0xFF;
	ret.data[2] = (dport >> 8) & 0xFF;
	ret.data[3] = dport & 0xFF;
	ret.data[4] = (seq >> 24) & 0xFF;
	ret.data[5] = (seq >> 16) & 0xFF;
	ret.data[6] = (seq >> 8) & 0xFF;
	ret.data[7] = seq & 0xFF;
	ret.data[8] = (ack >> 24) & 0xFF;
	ret.data[9] = (ack >> 16) & 0xFF;
	ret.data[10] = (ack >> 8) & 0xFF;
	ret.data[11] = ack & 0xFF;
	ret.data[12] = hlen<<4;
	ret.data[13] = flags;
	ret.data[14] = (window >> 8) & 0xFF;
	ret.data[15] = window & 0xFF;
	ret.data[16] = (checksum >> 8) & 0xFF;
	ret.data[17] = checksum & 0xFF;
	ret.data[18] = (urg >> 8) & 0xFF;
	ret.data[19] = urg & 0xFF;

	if (data.length > 0)
		ret.append(data.data, data.length);

	return ret;
}

void TCPPacket::print(FILE *fp) const {
	fprintf(fp, "TCP(sport=%d dport=%d", sport, dport);
	if (seq) fprintf(fp, " seq=%u", seq);
	if (ack) fprintf(fp, " ack=%u", ack);
	if (hlen != 5) fprintf(fp, " header_length=%d", hlen);
	if (flags) {
		fprintf(fp, " flags=");
		print_flags(fp, flags, flag_map);
	}
	if (window) fprintf(fp, " window=%d", window);
	/* print checksum if wrong */
	if (flags & TCP_FLAG_URG) fprintf(fp, " urg=%d", urg);
	if (data.length > 0) {
		fprintf(fp, " data=(");
		for (int i=0; i<data.length; i++)
			fprintf(fp, "%02x", data.data[i]);
		fprintf(fp, ")");
	}
	fprintf(fp, ")");
}

int TCPPacket::get_length(void) const {
	return hlen*4 + data.length;
}

void TCPPacket::set_field(const char *name, const char *value) {
	if (!strcasecmp(name, "sport") || !strcasecmp(name, "source_port"))
		sport = parse_number(value);
	else if (!strcasecmp(name, "dport") || !strcasecmp(name, "destination_port"))
		dport = parse_number(value);
	else if (!strcasecmp(name, "seq")) seq = parse_number(value);
	else if (!strcasecmp(name, "ack")) ack = parse_number(value);
	else if (!strcasecmp(name, "hlen") || !strcasecmp(name, "header_length"))
		hlen = parse_number(value);
	else if (!strcasecmp(name, "flags")) {
		if (isdigit((int)value[0]))
			flags = parse_number(value);
		else
			flags = parse_flags(value, flag_map);
	}
	else if (!strcasecmp(name, "window")) window = parse_number(value);
	else if (!strcasecmp(name, "checksum")) checksum = parse_number(value);
	else if (!strcasecmp(name, "urg")) {
		urg = parse_number(value);
		flags |= TCP_FLAG_URG;
	}
	else g_warning("TCP: unknown field name \"%s\"", name);
}

void TCPPacket::set_data(const Buffer &b) {
	data = b;
}

void TCPPacket::prepare(void) {
	checksum = 0;
	Buffer b = to_buffer();
	checksum = calculate_checksum(b);
}
