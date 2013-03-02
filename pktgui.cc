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
#include <gtk/gtk.h>
#include <glade/glade.h>
#include "icmppacket.h"
#include "ippacket.h"
#include "tcppacket.h"
#include "udppacket.h"

#define CHECK(name) \
	gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON( \
	glade_xml_get_widget(xml, name)))

static struct {
	const char *name;
	int type, code;
} icmp_map[] = {
	{ "Echo reply (PING reply)", 0, 0 },
	{ "Network unreachable", 3, 0 },
	{ "Host unreachable", 3, 1 },
	{ "Protocol unreachable", 3, 2 },
	{ "Port unreachable", 3, 3 },
	{ "Fragmentation needed", 3, 4 },
	{ "Source route failed", 3, 5 },
	{ "Destination network unknown", 3, 6 },
	{ "Destination host unknown", 3, 7 },
	{ "Source host isolated", 3, 8 },
	{ "Destination network prohibited", 3, 9 },
	{ "Destination host prohibited", 3, 10 },
	{ "Network unreachable for TOS", 3, 11 },
	{ "Host unreachable for TOS", 3, 12 },
	{ "Communication prohibited", 3, 13 },
	{ "Host precedence violation", 3, 14 },
	{ "Precedence cutoff", 3, 15 },
	{ "Source quench", 4, 0 },
	{ "Redirect for network", 5, 0 },
	{ "Redirect for host", 5, 1 },
	{ "Redirect for TOS and network", 5, 2 },
	{ "Redirect for TOS and host", 5, 3 },
	{ "Echo request (PING)", 8, 0 },
	{ "Router advertisement", 9, 0 },
	{ "Router solicitation", 10, 0 },
	{ "TTL exceeded", 11, 0 },
	{ "TTL exceeded during reassembly", 11, 1 },
	{ "IP header bad", 12, 0 },
	{ "Required option missing", 12, 1 },
	{ "Timestamp request", 13, 0 },
	{ "Timestamp reply", 14, 0 },
	{ "Information request", 15, 0 },
	{ "Information reply", 16, 0 },
	{ "Address mask request", 17, 0 },
	{ "Address mask reply", 18, 0 },
	{ 0, 0, 0 }
};

static GladeXML *xml;

const char *TEXT(const char *name) {
	const char *ret = 
		gtk_entry_get_text(GTK_ENTRY(glade_xml_get_widget(xml, name)));
	if (!ret)
		g_warning("no entry widget \"%s\"", name);
	return ret;
}
extern "C" {
	void send_packet();
	void protocol_changed(GtkEditable *editable);
}

IPPacket *ip_from_form() {
	IPPacket *ip = new IPPacket();
	ip->set_field("version", TEXT("ip_version"));
	ip->set_field("tos", TEXT("ip_tos"));
	ip->set_field("id", TEXT("ip_id"));
	int flags = (CHECK("ip_rf") ? 4 : 0)
		+ (CHECK("ip_df") ? 2 : 0) + (CHECK("ip_mf") ? 1 : 0);
	char buf[10];
	sprintf(buf, "%d", flags);
	ip->set_field("flags", buf);
	ip->set_field("fragment_offset", TEXT("ip_frag_ofs"));
	ip->set_field("ttl", TEXT("ip_ttl"));
	char *protocol = g_strdup(TEXT("ip_protocol"));
	char *p = strchr(protocol, '(') + 1;
	char *q = strchr(p, ')');
	*q = '\0';
	ip->set_field("protocol", p);
	g_free(protocol);
	ip->set_field("src", TEXT("ip_source"));
	ip->set_field("dst", TEXT("ip_destination"));

	return ip;
}

TCPPacket *tcp_from_form() {
	TCPPacket *tcp = new TCPPacket();
	tcp->set_field("sport", TEXT("tcp_source"));
	tcp->set_field("dport", TEXT("tcp_dest"));
	tcp->set_field("seq", TEXT("tcp_seqno"));
	tcp->set_field("ack", TEXT("tcp_ackno"));
	int flags = (CHECK("tcp_fin") ? 1 : 0) + (CHECK("tcp_syn") ? 2 : 0) +
		(CHECK("tcp_rst") ? 4 : 0) + (CHECK("tcp_psh") ? 8 : 0) +
		(CHECK("tcp_ack") ? 16 : 0) + (CHECK("tcp_urg") ? 32 : 0);
	char buf[10];
	sprintf(buf, "%d", flags);
	tcp->set_field("flags", buf);
	tcp->set_field("window", TEXT("tcp_window"));
	const char *urg = TEXT("tcp_urgptr");
	if (atoi(urg))
		tcp->set_field("urg", urg);

	return tcp;
}

UDPPacket *udp_from_form() {
	UDPPacket *udp = new UDPPacket();
	udp->set_field("sport", TEXT("udp_source"));
	udp->set_field("dport", TEXT("udp_dest"));

	return udp;
}

ICMPPacket *icmp_from_form() {
	ICMPPacket *icmp = new ICMPPacket();
	const char *msg = TEXT("icmp_message");
	for (int i=0; icmp_map[i].name; i++)
		if (!strcmp(msg, icmp_map[i].name)) {
			icmp->type = icmp_map[i].type;
			icmp->code = icmp_map[i].code;
			return icmp;
		}
	
	g_warning("ICMP message \"%s\" not found", msg);
	return icmp;
}

void send_packet() {
	IPPacket *ip = ip_from_form();
	switch (gtk_notebook_get_current_page(GTK_NOTEBOOK(
			glade_xml_get_widget(xml, "notebook")))) {
		case 0:  /* tcp */
			ip->set_payload(tcp_from_form());
			break;
		case 1:  /* udp */
			ip->set_payload(udp_from_form());
			break;
		case 2:  /* icmp */
			ip->set_payload(icmp_from_form());
			break;
		default:
			g_warning("Unrecognized protocol page");
	}

	ip->print(stdout);
}

void protocol_changed(GtkEditable *editable) {
	const char *protocol = gtk_entry_get_text(GTK_ENTRY(editable));
	if (!strncmp(protocol, "TCP", 3))
		gtk_notebook_set_page(
			GTK_NOTEBOOK(glade_xml_get_widget(xml, "notebook")), 0);
	else if (!strncmp(protocol, "UDP", 3))
		gtk_notebook_set_page(
			GTK_NOTEBOOK(glade_xml_get_widget(xml, "notebook")), 1);
	else if (!strncmp(protocol, "ICMP", 3))
		gtk_notebook_set_page(
			GTK_NOTEBOOK(glade_xml_get_widget(xml, "notebook")), 2);
	else
		g_warning("Protocol has no property page: \"%s\"", protocol);
}

int main(int argc, char **argv) {
  gtk_init(&argc, &argv);
  glade_init();
  xml = glade_xml_new("pktgui.glade", NULL, NULL);
  glade_xml_signal_autoconnect(xml);
  gtk_main();
  return 0;
}
