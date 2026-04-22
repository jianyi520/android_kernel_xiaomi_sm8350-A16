include $(srctree)/techpack/sched/sched.conf
LINUXINCLUDE    += \
		-include $(srctree)/techpack/sched/schedconf.h

# The scheduler WALT implementation now lives in kernel/sched/walt/.
# Do not build the legacy techpack copy in that case, otherwise vmlinux
# gets duplicate global symbols from both implementations.
ifeq ($(wildcard $(srctree)/kernel/sched/walt/Makefile),)
obj-$(CONFIG_SCHED_WALT) += walt.o boost.o sched_avg.o qc_vas.o core_ctl.o trace.o
obj-$(CONFIG_CPU_BOOST) += cpu-boost.o
endif
