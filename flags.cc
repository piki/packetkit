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
#include "flags.h"

void print_flags(FILE *fp, int flags, const Flag *map) {
	bool need_sep = false;
	for (int i=0; map[i].n; i++)
		if (flags & map[i].n) {
			fprintf(fp, "%s%s", need_sep?"|":"", map[i].name);
			need_sep = true;
		}
}

int parse_flags(const char *string, const Flag *map) {
	char *scratch = g_strdup(string);
	char *p = strtok(scratch, "|,");
	int flags = 0;
	while (p) {
		bool found = false;
		for (int i=0; map[i].n; i++)
			if (!strcasecmp(p, map[i].name)) {
				flags |= map[i].n;
				found = true;
				break;
			}
		if (!found) g_warning("Unknown flag \"%s\"", p);
		p = strtok(NULL, "|,");
	}
	g_free(scratch);
	return flags;
}
