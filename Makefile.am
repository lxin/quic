EXTRA_DIST		= net include autogen.sh
SUBDIRS			= handshake/ tests/

module:
	$(MAKE) -C $(KERNEL_SRC) M=$(CURDIR)/net/quic modules ROOTDIR=$(CURDIR) CONFIG_IP_QUIC=m CONFIG_IP_QUIC_TEST=m
module_install: module module_uninstall
	$(INSTALL) -m 644 include/uapi/linux/quic.h /usr/include/linux
	[ -d $(KERNEL_MOD) ] || mkdir $(KERNEL_MOD)
	$(INSTALL) -m 644 net/quic/quic.ko $(KERNEL_MOD)
	! [ -f net/quic/quic_quic_test.ko ] || $(INSTALL) -m 644 net/quic/quic_unit_test.ko $(KERNEL_MOD)
	! [ -f net/quic/quic_sample_test.ko ] || $(INSTALL) -m 644 net/quic/quic_sample_test.ko $(KERNEL_MOD)
	depmod -a
module_uninstall:
	! [ -d /sys/module/quic_unit_test ] || rmmod quic_unit_test
	! [ -d /sys/module/quic_sample_test ] || rmmod quic_sample_test
	! [ -d /sys/module/quic ] || rmmod quic
	rm -rf /usr/include/linux/quic.h
	rm -rf $(KERNEL_MOD)/quic.ko
	rm -rf $(KERNEL_MOD)/quic_sample_test.ko
	rm -rf $(KERNEL_MOD)/quic_unit_test.ko
	depmod -a
module_clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(CURDIR)/net/quic clean
distclean-local: module_clean
