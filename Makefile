CFLAGS = -g -O2 -Wall `pkg-config --cflags glib-2.0`
CXXFLAGS = $(CFLAGS)
LDLIBS = `pkg-config --libs glib-2.0`
CXX = g++

OBJS = buffer.o flags.o icmppacket.o ippacket.o packet.o tcppacket.o \
	token.o udppacket.o

all: sniff sender pktgui

sniff: sniff.o $(OBJS)
	$(CXX) -o $@ sniff.o $(OBJS) $(LDFLAGS) $(LDLIBS)

sender: sender.o $(OBJS)
	$(CXX) -o $@ sender.o $(OBJS) $(LDFLAGS) $(LDLIBS)

pktgui: pktgui.cc $(OBJS)
	$(CXX) -o $@ pktgui.cc $(OBJS) $(LDFLAGS) $(LDLIBS) \
		`pkg-config --cflags --libs libglade-2.0 gtk+-2.0`

clean:
	rm -f sniff.o sender.o pktgui.o $(OBJS) sniff sender pktgui

distclean: clean
	rm -f Makefile config.log config.status config.cache
