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

#ifndef TCPPACKET_H
#define TCPPACKET_H

#include "buffer.h"
#include "packet.h"

class TCPPacket : public Packet {
public:
	TCPPacket(void);
	TCPPacket(const Buffer &b);
	virtual Buffer to_buffer(void) const;
	virtual void print(FILE *fp) const;
	virtual int get_length(void) const;
	virtual void set_field(const char *name, const char *value);
	virtual void set_data(const Buffer &b);
	virtual void prepare(void);

	unsigned short sport, dport;
	unsigned int seq, ack;
	int hlen, flags, window, checksum, urg;

	Buffer data;
};

enum { TCP_FLAG_FIN=1, TCP_FLAG_SYN=2, TCP_FLAG_RST=4, TCP_FLAG_PSH=8,
	TCP_FLAG_ACK=16, TCP_FLAG_URG=32 };

#endif
