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
#include "icmppacket.h"
#include "packet.h"
#include "token.h"

static struct {
	int type, code;
	const char *name;
} icmp_map[] = {
	{ 0, 0, "echo_reply" },
	{ 3, 0, "network_unreachable" },
	{ 3, 1, "host_unreachable" },
	{ 3, 2, "protocol_unreachable" },
	{ 3, 3, "port_unreachable" },
	{ 3, 4, "fragmentation_needed" },
	{ 3, 5, "source_route_failed" },
	{ 3, 6, "destination_network_unknown" },
	{ 3, 7, "destination_host_unknown" },
	{ 3, 8, "source_host_isolated" },
	{ 3, 9, "destination_network_prohibited" },
	{ 3, 10, "destination_host_prohibited" },
	{ 3, 11, "network_unreachable_for_TOS" },
	{ 3, 12, "host_unreachable_for_TOS" },
	{ 3, 13, "communication_prohibited" },
	{ 3, 14, "host_precedence_violation" },
	{ 3, 15, "precedence_cutoff" },
	{ 4, 0, "source_quench" },
	{ 5, 0, "redirect_for_network" },
	{ 5, 1, "redirect_for_host" },
	{ 5, 2, "redirect_for_TOS_and_network" },
	{ 5, 3, "redirect_for_TOS_and_host" },
	{ 8, 0, "echo_request" },
	{ 9, 0, "router_advertisement" },
	{ 10, 0, "router_solicitation" },
	{ 11, 0, "ttl_exceeded" },
	{ 11, 1, "ttl_exceeded_during_reassembly" },
	{ 12, 0, "ip_header_bad" },
	{ 12, 1, "required_option_missing" },
	{ 13, 0, "timestamp_request" },
	{ 14, 0, "timestamp_reply" },
	{ 15, 0, "information_request" },
	{ 16, 0, "information_reply" },
	{ 17, 0, "address_mask_request" },
	{ 18, 0, "address_mask_reply" },
	{ 0, 0, 0 }
};

ICMPPacket::ICMPPacket(void) {
	type = code = checksum = 0;
}

ICMPPacket::ICMPPacket(const Buffer &b) {
	g_return_if_fail(b.length >= 8);
	//printf("ICMPPacket(");
	//b.print(8);
	//printf(")\n");
	type = b.data[0];
	code = b.data[1];
	checksum = (b.data[2]<<8) + b.data[3];

	if (b.length > 8)
		data.set(b.data+8, b.length-8);
}

Buffer ICMPPacket::to_buffer(void) const {
	Buffer ret(8);
	ret.data[0] = type;
	ret.data[1] = code;
	ret.data[2] = (checksum >> 8) & 0xFF;
	ret.data[3] = checksum & 0xFF;
	ret.data[4] = ret.data[5] = ret.data[6] = ret.data[7] = 0;

	if (data.length > 0)
		ret.append(data.data, data.length);

	return ret;
}

void ICMPPacket::print(FILE *fp) const {
	bool found = false;
	fprintf(fp, "ICMP(");
	for (int i=0; icmp_map[i].name; i++)
		if (icmp_map[i].type == type && icmp_map[i].code == code) {
			fprintf(fp, "message=%s", icmp_map[i].name);
			found = true;
			break;
		}
	if (!found) fprintf(fp, "type=%d code=%d", type, code);
	/* print checksum if wrong */
	if (data.length > 0) {
		fprintf(fp, " data=(");
		for (int i=0; i<data.length; i++)
			fprintf(fp, "%02x", data.data[i]);
		fprintf(fp, ")");
	}
	fprintf(fp, ")");
}

int ICMPPacket::get_length(void) const {
	return 8 + data.length;
}

void ICMPPacket::set_field(const char *name, const char *value) {
	if (!strcasecmp(name, "type")) type = parse_number(value);
	else if (!strcasecmp(name, "code")) type = parse_number(value);
	else if (!strcasecmp(name, "message")) {
		bool found = false;
		for (int i=0; icmp_map[i].name; i++)
			if (!strcasecmp(value, icmp_map[i].name)) {
				type = icmp_map[i].type;
				code = icmp_map[i].code;
				found = true;
				break;
			}
		if (!found) g_warning("ICMP: unknown message type \"%s\"", value);
	}
	else if (!strcasecmp(name, "checksum")) checksum = parse_number(value);
	else g_warning("ICMP: unknown field name \"%s\"", name);
}

void ICMPPacket::set_data(const Buffer &b) {
	data = b;
}

void ICMPPacket::prepare(void) {
	checksum = 0;
	Buffer b = to_buffer();
	checksum = calculate_checksum(b);
}
