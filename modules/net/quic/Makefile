# SPDX-License-Identifier: GPL-2.0-or-later
#
# Makefile for QUIC support code.
#

LINUXINCLUDE += -I$(ROOTDIR)/include

obj-$(CONFIG_IP_QUIC) += quic.o

quic-y := common.o family.o protocol.o socket.o stream.o connid.o path.o \
	  cong.o pnspace.o crypto.o timer.o frame.o packet.o outqueue.o \
	  inqueue.o offload.o

ifdef CONFIG_KUNIT
	obj-$(CONFIG_IP_QUIC_TEST) += quic_unit_test.o
	quic_unit_test-y := test/unit_test.o
endif

ifdef CONFIG_NET_HANDSHAKE
	obj-$(CONFIG_IP_QUIC_TEST) += quic_sample_test.o
	quic_sample_test-y := test/sample_test.o
endif
