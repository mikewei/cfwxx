AM_CPPFLAGS = -I$(top_srcdir)/src
AM_CXXFLAGS = -std=gnu++11 -Wall
AM_LDFLAGS = -pthread

LDADD = -lgflags -lglog

noinst_PROGRAMS = \
	cfw_client \
	cfw_server

comm_SOURCES = \
	socket.cc \
	cfw_comm.cc

cfw_client_SOURCES = \
	$(comm_SOURCES) \
	cfw_client.cc

cfw_server_SOURCES = \
	$(comm_SOURCES) \
	cfw_server.cc

