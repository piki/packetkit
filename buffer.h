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

#ifndef BUFFER_H
#define BUFFER_H

#include <stdio.h>

class Buffer {
public:
	Buffer(void);
	Buffer(int len);
	Buffer(const unsigned char *s, int slen);
	Buffer(const Buffer &copy);
	Buffer &operator=(const Buffer &copy);
	~Buffer(void);
	void set(const unsigned char *s, int len);
	void append(const unsigned char *s, int len);
	void print(int n) const;
	void print(void) const { print(length); }

	unsigned char *data;
	int length;
	
private:
	void ensure_alloc(int len);
	int alloc;
};

#endif
