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

#ifndef PACKET_H
#define PACKET_H

#include <stdio.h>
#include "buffer.h"

class Packet {
public:
	virtual ~Packet(void) { }
	virtual Buffer to_buffer(void) const = 0;
	virtual void print(FILE *fp) const = 0;
	virtual int get_length(void) const = 0;
	virtual void set_field(const char *name, const char *value) = 0;
	virtual void set_data(const Buffer &b);
	virtual void set_payload(Packet *payload);
	virtual int get_port(void) const;
	virtual struct in_addr get_dest(void) const;
	virtual void prepare(void);
};

Packet *parse(FILE *fp);  /* factory! */
unsigned int calculate_checksum(const Buffer &b);

#endif
