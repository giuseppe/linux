/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_MNTFS_H
#define _UAPI_LINUX_MNTFS_H

#include <linux/ioctl.h>

/* Return an O_PATH fd to the root of the mount represented by a mntfs fd. */
#define MNTFS_IOC_OPEN_MOUNT_ROOT	_IO(0x4d, 1)

#endif /* _UAPI_LINUX_MNTFS_H */
