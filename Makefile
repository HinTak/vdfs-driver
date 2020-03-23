#
# Makefile for the linux vdfs4-filesystem routines.
#

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
ccflags-y += -DCONFIG_VDFS4_DEBUG_GET_BNODE=1
ccflags-y += -DCONFIG_VDFS4_EXPERIMENTAL=1
ccflags-y += -DCONFIG_VDFS4_CRC_CHECK=1
ccflags-y += -DCONFIG_VDFS4_META_SANITY_CHECK=1
ccflags-y += -DCONFIG_VDFS4_POSIX_ACL=1
ccflags-y += -DCONFIG_VDFS4_DECRYPT_SUPPORT=1
#ccflags-y += -CONFIG_VDFS4_HW_DECOMPRESS_SUPPORT=1
GIT_REPO_PATH := "${KBUILD_EXTMOD}/../.git"
endif

ifdef VDFS4_NO_WARN
EXTRA_CFLAGS+=-Werror
endif

ccflags-$(CONFIG_VDFS4_NOOPTIMIZE) += -O0

obj-$(CONFIG_VDFS4_FS) += vdfs4.o

vdfs4-y	:= btree.o bnode.o cattree.o file.o inode.o \
		   options.o super.o fsm.o ioctl.o \
		   extents.o snapshot.o orphan.o data.o \
		   cattree-helper.o xattr.o \
		   decompress.o authentication.o

vdfs4-$(CONFIG_VDFS4_DEBUG)		+= debug.o

GIT_REPO_PATH ?= $(shell echo $(MAKEFILE_FULL_NAME) | sed "s/vdfs-driver\/Makefile/.git/g")
GIT_BRANCH = heads/vdfs4
GIT_REV_HASH = 0bc03d8c510e97f8b66248b7e1d93a20829d08ca
VERSION = "no_version"

ifneq ($(GIT_BRANCH),)
CFLAGS_super.o				+= -DVDFS4_GIT_BRANCH=\"$(GIT_BRANCH)\"
endif
ifneq ($(GIT_REV_HASH),)
CFLAGS_super.o				+= -DVDFS4_GIT_REV_HASH=\"$(GIT_REV_HASH)\"
endif
ifneq ($(VERSION),)
CFLAGS_super.o				+= -DVDFS4_VERSION=\"$(VERSION)\"
endif

