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

#ifndef ICMPPACKET_H
#define ICMPPACKET_H

#include "buffer.h"
#include "packet.h"

class ICMPPacket : public Packet {
public:
	ICMPPacket(void);
	ICMPPacket(const Buffer &b);
	virtual Buffer to_buffer(void) const;
	virtual void print(FILE *fp) const;
	virtual int get_length(void) const;
	virtual void set_field(const char *name, const char *value);
	virtual void set_data(const Buffer &b);
	virtual void prepare(void);

	unsigned char type, code;
	unsigned short checksum;
	Buffer data;
};

#endif
