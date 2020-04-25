#
# Makefile for the linux vdfs4-filesystem routines.
#

####################################################################
# VDFS Version Definition(MAJ.MIN-DATE)
#-------------------------------------------------------------------
MAJ_VER=2
MIN_VER=52
DATE=190403	#YYMMDD
#-------------------------------------------------------------------
VERSION="$(strip $(MAJ_VER)).$(strip $(MIN_VER))-$(strip $(DATE))"
####################################################################

ifndef KBUILD_MODULES
# out-of-tree invocation
KSRC = /lib/modules/$(shell uname -r)/build

modules clean:
	$(MAKE) -C "${KSRC}" M="${PWD}" $@

tools:
	$(MAKE) -C ../vdfs4-tools/
endif

ifneq ($(KBUILD_EXTMOD),)
# building as external module
CONFIG_VDFS4_FS = m
CONFIG_VDFS4_DEBUG = y
ccflags-y += -DCONFIG_VDFS4_MODULE=1
ccflags-y += -DCONFIG_VDFS4_DEBUG=1
ccflags-y += -DCONFIG_VDFS4_META_SANITY_CHECK=1
ccflags-y += -DCONFIG_VDFS4_POSIX_ACL=1
ccflags-y += -DCONFIG_VDFS4_DECRYPT_SUPPORT=1
#ccflags-y += -CONFIG_VDFS4_HW_DECOMPRESS_SUPPORT=1
endif

ifdef VDFS4_NO_WARN
EXTRA_CFLAGS+=-Werror
endif

obj-$(CONFIG_VDFS4_FS) += vdfs4.o

vdfs4-y	:= btree.o bnode.o cattree.o file.o inode.o \
		   options.o super.o fsm.o ioctl.o \
		   extents.o snapshot.o orphan.o data.o \
		   cattree-helper.o xattr.o \
		   decompress.o authentication.o \
		   debug.o

vdfs4-$(CONFIG_VDFS4_TRACE) += vdfs_trace.o
vdfs4-$(CONFIG_VDFS4_LOCK_TRACE) += lock_trace.o

CFLAGS_super.o				+= -DVDFS4_VERSION=\"$(VERSION)\"
CFLAGS_decompress.o			+= -DVDFS4_VERSION=\"$(VERSION)\"
