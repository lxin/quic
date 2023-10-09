# SPDX-License-Identifier: GPL-2.0-or-later
#
# Makefile for QUIC support code.
#

LINUXINCLUDE += -I$(ROOTDIR)/include

obj-$(CONFIG_IP_QUIC) += quic.o

quic-y := protocol.o socket.o connection.o stream.o path.o packet.o frame.o input.o output.o crypto.o pnmap.o timer.o cong.o

ifdef CONFIG_NET_HANDSHAKE
	obj-$(CONFIG_IP_QUIC_TEST) += quic_test.o
	quic_test-y := test/test.o
endif
