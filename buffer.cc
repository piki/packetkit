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

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include "buffer.h"

Buffer::Buffer(void) {
	data = (unsigned char*)NULL;
	length = alloc = 0;
}

Buffer::Buffer(int len) {
	length = alloc = len;
	data = g_new(unsigned char, length);
}

Buffer::Buffer(const unsigned char *s, int slen) {
	data = (unsigned char*)NULL;
	alloc = 0;
	set(s, slen);
}

Buffer::Buffer(const Buffer &copy) {
	length = alloc = copy.length;
	data = g_new(unsigned char, alloc);
	memcpy(data, copy.data, length);
}

Buffer &Buffer::operator=(const Buffer &copy) {
	if (data) g_free(data);
	length = alloc = copy.length;
	data = g_new(unsigned char, alloc);
	memcpy(data, copy.data, length);
	return *this;
}

Buffer::~Buffer() {
	if (data) g_free(data);
}

void Buffer::ensure_alloc(int slen) {
	if (slen > alloc) {
		data = (unsigned char*)g_realloc(data, slen);
		alloc = slen;
	}
}

void Buffer::set(const unsigned char *s, int slen) {
	g_return_if_fail(s);
	g_return_if_fail(slen > 0);
	ensure_alloc(slen);
	memcpy(data, s, slen);
	length = slen;
}

void Buffer::append(const unsigned char *s, int slen) {
	g_return_if_fail(s);
	g_return_if_fail(slen > 0);
	ensure_alloc(length + slen);
	memcpy(data+length, s, slen);
	length += slen;
}

void Buffer::print(int len) const {
	for (int i=0; i<len; i++) {
		if (i>0) putchar(' ');
		printf("0x%x", data[i]);
	}
}
