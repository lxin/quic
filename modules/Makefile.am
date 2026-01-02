EXTRA_DIST	= include net
MODULES		= quic_unit_test quic_sample_test quic

all:
	$(MAKE) -C $(KERNEL_BUILD) W=1 M=$(CURDIR)/net/quic modules \
		ROOTDIR=$(CURDIR) CONFIG_IP_QUIC=m CONFIG_IP_QUIC_TEST=m

install: uninstall_modules install_headers install_modules depmod

uninstall: uninstall_modules uninstall_headers depmod

clean:
	$(MAKE) -C $(KERNEL_BUILD) M=$(CURDIR)/net/quic clean

selftests:
	@cd $(CURDIR)/tools/testing/selftests/net/ && ./quic_test.sh

install_headers:
	install -m 644 include/uapi/linux/quic.h /usr/include/linux

install_modules: all $(KERNEL_EXTRA)
	$(foreach module, $(MODULES), \
		! [ -f net/quic/$(module).ko ] || \
		install -m 644 net/quic/$(module).ko $(KERNEL_EXTRA);)

uninstall_modules:
	$(foreach module, $(MODULES), \
		! [ -d /sys/module/$(module) ] || rmmod $(module); \
		rm -f $(KERNEL_EXTRA)/$(module).ko;)

uninstall_headers:
	rm -f /usr/include/linux/quic.h

$(KERNEL_EXTRA):
	mkdir -p $@

depmod:
	depmod -a

MAINTAINERCLEANFILES	= Makefile.in
