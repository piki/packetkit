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

#include <string.h>
#include <glib.h>
#include "buffer.h"
#include "packet.h"
#include "token.h"
#include "udppacket.h"

UDPPacket::UDPPacket(void) {
	length = 8;
	sport = dport = checksum = 0;
}

UDPPacket::UDPPacket(const Buffer &b) {
	g_return_if_fail(b.length >= 8);
	//printf("UDPPacket(");
	//b.print(8);
	//printf(")\n");
	sport = (b.data[0]<<8) + b.data[1];
	dport = (b.data[2]<<8) + b.data[3];
	length = (b.data[4]<<8) + b.data[5];
	checksum = (b.data[6]<<8) + b.data[7];

	if (b.length > 8)
		data.set(b.data+8, b.length-8);
}

Buffer UDPPacket::to_buffer(void) const {
	Buffer ret(8);
	ret.data[0] = (sport >> 8) & 0xFF;
	ret.data[1] = sport & 0xFF;
	ret.data[2] = (dport >> 8) & 0xFF;
	ret.data[3] = dport & 0xFF;
	ret.data[4] = (length >> 8) & 0xFF;
	ret.data[5] = length & 0xFF;
	ret.data[6] = (checksum >> 8) & 0xFF;
	ret.data[7] = checksum & 0xFF;

	if (data.length > 0)
		ret.append(data.data, data.length);

	return ret;
}

void UDPPacket::print(FILE *fp) const {
	fprintf(fp, "UDP(sport=%d dport=%d length=%d", sport, dport, length);
	/* print the checksum if it's wrong */
	if (data.length > 0) {
		fprintf(fp, " data=(");
		for (int i=0; i<data.length; i++)
			fprintf(fp, "%02x", data.data[i]);
		fprintf(fp, ")");
	}
	fprintf(fp, ")");
}

int UDPPacket::get_length(void) const {
	return 8 + data.length;
}

void UDPPacket::set_field(const char *name, const char *value) {
	if (!strcasecmp(name, "sport") || !strcasecmp(name, "source_port"))
		sport = parse_number(value);
	else if (!strcasecmp(name, "dport") || !strcasecmp(name, "destination_port"))
		dport = parse_number(value);
	else if (!strcasecmp(name, "length"))
		length = parse_number(value);
	else if (!strcasecmp(name, "checksum"))
		checksum = parse_number(value);
	else g_warning("UDP: unknown field name \"%s\"", name);
}

void UDPPacket::set_data(const Buffer &b) {
	data = b;
}

void UDPPacket::prepare(void) {
  length = 8 + data.length;
	checksum = 0;
//	Buffer b = to_buffer();
//	b.length = 8;
//	checksum = calculate_checksum(b);
}
