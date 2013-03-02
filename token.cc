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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <glib.h>

GString *next_token(FILE *fp, const char *skip, const char *end) {
	char c = '\0';
	GString *s = g_string_new(NULL);

	while (!feof(fp) && strchr(skip, (c=fgetc(fp)))) ;
	while (!feof(fp) && !strchr(end, c)) {
		g_string_append_c(s, c);
		c = fgetc(fp);
	}

	return s;
}

unsigned int parse_number(const char *string) {
	if (!strncasecmp(string, "0x", 2))
		return strtoul(string+2, NULL, 16);
	else if (string[0] == '0' && string[1] != '\0')
		return strtoul(string+1, NULL, 8);
	else if (string[0] == 'R') {
		const char *p = strchr(string, ',');
		unsigned int low = strtoul(string+1, NULL, 10);
		unsigned int high = strtoul(p+1, NULL, 10);
		static bool initialized = false;
		if (!initialized) {
			initialized = true;
			srand(time(NULL));
		}
		return (rand()%(high-low+1))+low;
	}
	else
		return strtoul(string, NULL, 10);
}
