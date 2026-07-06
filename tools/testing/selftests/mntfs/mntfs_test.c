// SPDX-License-Identifier: GPL-2.0

/*
 * Tests for the mntfs pseudo-filesystem.
 *
 * mntfs provides file-handle based access to mount objects via
 * open_by_handle_at(FD_MNTFS_ROOT, ...) and an ioctl to obtain an
 * O_PATH fd referring to the root of the underlying mount.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../kselftest_harness.h"

#include <linux/stat.h>

#ifndef FD_MNTFS_ROOT
#define FD_MNTFS_ROOT (-10004)
#endif

#ifndef STATX_MNT_ID_UNIQUE
#define STATX_MNT_ID_UNIQUE 0x00004000U
#endif

#ifndef FILEID_MNTFS
#define FILEID_MNTFS 0x4d
#endif

#ifndef MNTFS_IOC_OPEN_MOUNT_ROOT
#define MNTFS_IOC_OPEN_MOUNT_ROOT _IO(0x4d, 1)
#endif

#define MNTFS_FID_LEN_BYTES sizeof(uint64_t)
#define MNTFS_FID_LEN_U32   (sizeof(uint64_t) / sizeof(uint32_t))

static int get_unique_mnt_id(const char *path, uint64_t *mnt_id)
{
	struct statx sx;
	int ret;

	memset(&sx, 0, sizeof(sx));
	ret = statx(AT_FDCWD, path, 0, STATX_MNT_ID_UNIQUE, &sx);
	if (ret)
		return -errno;
	if (!(sx.stx_mask & STATX_MNT_ID_UNIQUE))
		return -EOPNOTSUPP;

	*mnt_id = sx.stx_mnt_id;
	return 0;
}

static int get_unique_mnt_id_fd(int fd, uint64_t *mnt_id)
{
	struct statx sx;
	int ret;

	memset(&sx, 0, sizeof(sx));
	ret = statx(fd, "", AT_EMPTY_PATH, STATX_MNT_ID_UNIQUE, &sx);
	if (ret)
		return -errno;
	if (!(sx.stx_mask & STATX_MNT_ID_UNIQUE))
		return -EOPNOTSUPP;

	*mnt_id = sx.stx_mnt_id;
	return 0;
}

static struct file_handle *alloc_mntfs_handle(uint64_t mnt_id_unique)
{
	struct file_handle *fh;

	fh = malloc(sizeof(*fh) + MNTFS_FID_LEN_BYTES);
	if (!fh)
		return NULL;

	fh->handle_bytes = MNTFS_FID_LEN_BYTES;
	fh->handle_type = FILEID_MNTFS;
	memcpy(fh->f_handle, &mnt_id_unique, sizeof(mnt_id_unique));
	return fh;
}

FIXTURE(mntfs)
{
	char tmpdir[PATH_MAX];
	int tmpdir_created;
	int mounted;
};

FIXTURE_SETUP(mntfs)
{
	int ret;

	snprintf(self->tmpdir, sizeof(self->tmpdir),
		 "/tmp/mntfs_test.XXXXXX");
	ASSERT_NE(mkdtemp(self->tmpdir), NULL);
	self->tmpdir_created = 1;

	/* Enter a new mount namespace so our mounts don't leak. */
	ret = unshare(CLONE_NEWNS);
	ASSERT_EQ(ret, 0) {
		TH_LOG("unshare(CLONE_NEWNS) failed: %s", strerror(errno));
	}

	/* Make the mount tree private so changes don't propagate. */
	ret = mount("", "/", NULL, MS_REC | MS_PRIVATE, NULL);
	ASSERT_EQ(ret, 0) {
		TH_LOG("mount(MS_REC|MS_PRIVATE) failed: %s", strerror(errno));
	}

	/* Mount a tmpfs at our test directory. */
	ret = mount("tmpfs", self->tmpdir, "tmpfs", 0, "size=1M");
	ASSERT_EQ(ret, 0) {
		TH_LOG("mount(tmpfs) failed: %s", strerror(errno));
	}
	self->mounted = 1;
}

FIXTURE_TEARDOWN(mntfs)
{
	if (self->mounted)
		umount2(self->tmpdir, MNT_DETACH);
	if (self->tmpdir_created)
		rmdir(self->tmpdir);
}

/*
 * Test that we can obtain the mnt_id_unique for a mount via statx and
 * use it to construct a mntfs file handle that open_by_handle_at
 * accepts.
 */
TEST_F(mntfs, open_by_handle)
{
	struct file_handle *fh;
	uint64_t mnt_id;
	int fd;

	ASSERT_EQ(get_unique_mnt_id(self->tmpdir, &mnt_id), 0) {
		TH_LOG("statx(STATX_MNT_ID_UNIQUE) failed");
	}
	ASSERT_NE(mnt_id, 0);

	fh = alloc_mntfs_handle(mnt_id);
	ASSERT_NE(fh, NULL);

	fd = open_by_handle_at(FD_MNTFS_ROOT, fh, O_RDONLY);
	if (fd < 0 && (errno == EINVAL || errno == EOPNOTSUPP)) {
		free(fh);
		SKIP(return, "mntfs file handles not supported by this kernel");
	}
	ASSERT_GE(fd, 0) {
		TH_LOG("open_by_handle_at(FD_MNTFS_ROOT) failed: %s",
		       strerror(errno));
	}

	ASSERT_EQ(close(fd), 0);
	free(fh);
}

/*
 * Test that the MNTFS_IOC_OPEN_MOUNT_ROOT ioctl returns an O_PATH fd
 * whose mnt_id_unique matches the original mount.
 */
TEST_F(mntfs, ioctl_open_mount_root)
{
	struct file_handle *fh;
	uint64_t mnt_id, root_mnt_id;
	int mntfs_fd, root_fd;

	ASSERT_EQ(get_unique_mnt_id(self->tmpdir, &mnt_id), 0);
	ASSERT_NE(mnt_id, 0);

	fh = alloc_mntfs_handle(mnt_id);
	ASSERT_NE(fh, NULL);

	mntfs_fd = open_by_handle_at(FD_MNTFS_ROOT, fh, O_RDONLY);
	if (mntfs_fd < 0 && (errno == EINVAL || errno == EOPNOTSUPP)) {
		free(fh);
		SKIP(return, "mntfs file handles not supported by this kernel");
	}
	ASSERT_GE(mntfs_fd, 0) {
		TH_LOG("open_by_handle_at(FD_MNTFS_ROOT) failed: %s",
		       strerror(errno));
	}

	root_fd = ioctl(mntfs_fd, MNTFS_IOC_OPEN_MOUNT_ROOT);
	ASSERT_GE(root_fd, 0) {
		TH_LOG("ioctl(MNTFS_IOC_OPEN_MOUNT_ROOT) failed: %s",
		       strerror(errno));
	}

	/* The returned fd should refer to the mount root. */
	ASSERT_EQ(get_unique_mnt_id_fd(root_fd, &root_mnt_id), 0);
	ASSERT_EQ(mnt_id, root_mnt_id) {
		TH_LOG("mnt_id mismatch: expected 0x%llx, got 0x%llx",
		       (unsigned long long)mnt_id,
		       (unsigned long long)root_mnt_id);
	}

	ASSERT_EQ(close(root_fd), 0);
	ASSERT_EQ(close(mntfs_fd), 0);
	free(fh);
}

/*
 * Test that the fd returned by MNTFS_IOC_OPEN_MOUNT_ROOT is an O_PATH
 * descriptor (i.e., read/write fail with EBADF).
 */
TEST_F(mntfs, ioctl_open_mount_root_is_o_path)
{
	struct file_handle *fh;
	uint64_t mnt_id;
	int mntfs_fd, root_fd;
	char buf[1];
	int flags;

	ASSERT_EQ(get_unique_mnt_id(self->tmpdir, &mnt_id), 0);

	fh = alloc_mntfs_handle(mnt_id);
	ASSERT_NE(fh, NULL);

	mntfs_fd = open_by_handle_at(FD_MNTFS_ROOT, fh, O_RDONLY);
	if (mntfs_fd < 0 && (errno == EINVAL || errno == EOPNOTSUPP)) {
		free(fh);
		SKIP(return, "mntfs file handles not supported by this kernel");
	}
	ASSERT_GE(mntfs_fd, 0);

	root_fd = ioctl(mntfs_fd, MNTFS_IOC_OPEN_MOUNT_ROOT);
	ASSERT_GE(root_fd, 0);

	/*
	 * An O_PATH fd does not permit read or write.  Verify that
	 * read returns EBADF.
	 */
	ASSERT_EQ(read(root_fd, buf, sizeof(buf)), -1);
	ASSERT_EQ(errno, EBADF);

	/* Check that O_PATH is set via fcntl. */
	flags = fcntl(root_fd, F_GETFL);
	ASSERT_GE(flags, 0);
	ASSERT_TRUE(flags & O_PATH);

	ASSERT_EQ(close(root_fd), 0);
	ASSERT_EQ(close(mntfs_fd), 0);
	free(fh);
}

/*
 * Test that after unmounting, open_by_handle_at returns ESTALE.
 */
TEST_F(mntfs, stale_after_unmount)
{
	struct file_handle *fh;
	uint64_t mnt_id;
	int fd;

	ASSERT_EQ(get_unique_mnt_id(self->tmpdir, &mnt_id), 0);
	ASSERT_NE(mnt_id, 0);

	fh = alloc_mntfs_handle(mnt_id);
	ASSERT_NE(fh, NULL);

	/* Verify the handle is valid before unmount. */
	fd = open_by_handle_at(FD_MNTFS_ROOT, fh, O_RDONLY);
	if (fd < 0 && (errno == EINVAL || errno == EOPNOTSUPP)) {
		free(fh);
		SKIP(return, "mntfs file handles not supported by this kernel");
	}
	ASSERT_GE(fd, 0);
	ASSERT_EQ(close(fd), 0);

	/* Unmount the tmpfs. */
	ASSERT_EQ(umount2(self->tmpdir, MNT_DETACH), 0);
	self->mounted = 0;

	/* The handle should now be stale. */
	fd = open_by_handle_at(FD_MNTFS_ROOT, fh, O_RDONLY);
	ASSERT_EQ(fd, -1);
	ASSERT_EQ(errno, ESTALE) {
		TH_LOG("expected ESTALE after unmount, got %s",
		       strerror(errno));
	}

	free(fh);
}

/*
 * Test that a bogus mnt_id_unique gives ESTALE.
 */
TEST_F(mntfs, invalid_mnt_id)
{
	struct file_handle *fh;
	int fd;

	/* Use a mnt_id_unique that should not exist. */
	fh = alloc_mntfs_handle(UINT64_MAX);
	ASSERT_NE(fh, NULL);

	fd = open_by_handle_at(FD_MNTFS_ROOT, fh, O_RDONLY);
	if (fd < 0 && (errno == EINVAL || errno == EOPNOTSUPP)) {
		free(fh);
		SKIP(return, "mntfs file handles not supported by this kernel");
	}
	ASSERT_EQ(fd, -1);
	ASSERT_EQ(errno, ESTALE) {
		TH_LOG("expected ESTALE for bogus mnt_id, got %s",
		       strerror(errno));
	}

	free(fh);
}

/*
 * Test that an incorrect handle type is rejected.
 */
TEST_F(mntfs, wrong_handle_type)
{
	struct file_handle *fh;
	uint64_t mnt_id;
	int fd;

	ASSERT_EQ(get_unique_mnt_id(self->tmpdir, &mnt_id), 0);

	fh = alloc_mntfs_handle(mnt_id);
	ASSERT_NE(fh, NULL);

	/* Corrupt the handle type. */
	fh->handle_type = 0xff;

	fd = open_by_handle_at(FD_MNTFS_ROOT, fh, O_RDONLY);
	/*
	 * The kernel should reject a handle whose type doesn't match
	 * FILEID_MNTFS.  The exact error may vary, but it should fail.
	 */
	ASSERT_LT(fd, 0) {
		TH_LOG("open_by_handle_at unexpectedly succeeded with wrong handle type");
		close(fd);
	}

	free(fh);
}

/*
 * Test that a handle with truncated (too short) payload is rejected.
 */
TEST_F(mntfs, short_handle)
{
	struct file_handle *fh;
	uint64_t mnt_id;
	int fd;

	ASSERT_EQ(get_unique_mnt_id(self->tmpdir, &mnt_id), 0);

	/* Allocate a handle but set handle_bytes too small. */
	fh = malloc(sizeof(*fh) + MNTFS_FID_LEN_BYTES);
	ASSERT_NE(fh, NULL);
	memset(fh, 0, sizeof(*fh) + MNTFS_FID_LEN_BYTES);
	fh->handle_bytes = sizeof(uint32_t); /* Only 4 bytes, need 8 */
	fh->handle_type = FILEID_MNTFS;
	memcpy(fh->f_handle, &mnt_id, sizeof(uint32_t));

	fd = open_by_handle_at(FD_MNTFS_ROOT, fh, O_RDONLY);
	ASSERT_LT(fd, 0) {
		TH_LOG("open_by_handle_at unexpectedly succeeded with short handle");
		close(fd);
	}

	free(fh);
}

/*
 * Test that an unsupported ioctl on a mntfs fd returns ENOTTY.
 */
TEST_F(mntfs, ioctl_unsupported)
{
	struct file_handle *fh;
	uint64_t mnt_id;
	int mntfs_fd, ret;

	ASSERT_EQ(get_unique_mnt_id(self->tmpdir, &mnt_id), 0);

	fh = alloc_mntfs_handle(mnt_id);
	ASSERT_NE(fh, NULL);

	mntfs_fd = open_by_handle_at(FD_MNTFS_ROOT, fh, O_RDONLY);
	if (mntfs_fd < 0 && (errno == EINVAL || errno == EOPNOTSUPP)) {
		free(fh);
		SKIP(return, "mntfs file handles not supported by this kernel");
	}
	ASSERT_GE(mntfs_fd, 0);

	/* Use a nonsense ioctl number. */
	ret = ioctl(mntfs_fd, _IO(0x4d, 0xff));
	ASSERT_EQ(ret, -1);
	ASSERT_EQ(errno, ENOTTY);

	ASSERT_EQ(close(mntfs_fd), 0);
	free(fh);
}

/*
 * Test that re-opening the same mount via handle yields a consistent
 * inode - i.e. two open_by_handle_at calls for the same mnt_id_unique
 * return fds that fstat to the same (dev, ino).
 */
TEST_F(mntfs, consistent_identity)
{
	struct file_handle *fh;
	uint64_t mnt_id;
	struct stat st1, st2;
	int fd1, fd2;

	ASSERT_EQ(get_unique_mnt_id(self->tmpdir, &mnt_id), 0);

	fh = alloc_mntfs_handle(mnt_id);
	ASSERT_NE(fh, NULL);

	fd1 = open_by_handle_at(FD_MNTFS_ROOT, fh, O_RDONLY);
	if (fd1 < 0 && (errno == EINVAL || errno == EOPNOTSUPP)) {
		free(fh);
		SKIP(return, "mntfs file handles not supported by this kernel");
	}
	ASSERT_GE(fd1, 0);

	fd2 = open_by_handle_at(FD_MNTFS_ROOT, fh, O_RDONLY);
	ASSERT_GE(fd2, 0);

	ASSERT_EQ(fstat(fd1, &st1), 0);
	ASSERT_EQ(fstat(fd2, &st2), 0);
	ASSERT_EQ(st1.st_dev, st2.st_dev);
	ASSERT_EQ(st1.st_ino, st2.st_ino);

	ASSERT_EQ(close(fd1), 0);
	ASSERT_EQ(close(fd2), 0);
	free(fh);
}

/*
 * Test that two different mounts produce different mntfs handles.
 */
TEST_F(mntfs, different_mounts)
{
	char tmpdir2[PATH_MAX];
	struct file_handle *fh1, *fh2;
	uint64_t mnt_id1, mnt_id2;
	int fd1, fd2;
	struct stat st1, st2;

	snprintf(tmpdir2, sizeof(tmpdir2), "%s/sub", self->tmpdir);
	ASSERT_EQ(mkdir(tmpdir2, 0755), 0);
	ASSERT_EQ(mount("tmpfs", tmpdir2, "tmpfs", 0, "size=1M"), 0);

	ASSERT_EQ(get_unique_mnt_id(self->tmpdir, &mnt_id1), 0);
	ASSERT_EQ(get_unique_mnt_id(tmpdir2, &mnt_id2), 0);
	ASSERT_NE(mnt_id1, mnt_id2);

	fh1 = alloc_mntfs_handle(mnt_id1);
	ASSERT_NE(fh1, NULL);

	fh2 = alloc_mntfs_handle(mnt_id2);
	ASSERT_NE(fh2, NULL);

	fd1 = open_by_handle_at(FD_MNTFS_ROOT, fh1, O_RDONLY);
	if (fd1 < 0 && (errno == EINVAL || errno == EOPNOTSUPP)) {
		free(fh1);
		free(fh2);
		umount2(tmpdir2, MNT_DETACH);
		rmdir(tmpdir2);
		SKIP(return, "mntfs file handles not supported by this kernel");
	}
	ASSERT_GE(fd1, 0);

	fd2 = open_by_handle_at(FD_MNTFS_ROOT, fh2, O_RDONLY);
	ASSERT_GE(fd2, 0);

	ASSERT_EQ(fstat(fd1, &st1), 0);
	ASSERT_EQ(fstat(fd2, &st2), 0);
	/* The two mntfs fds must refer to different inodes. */
	ASSERT_TRUE(st1.st_dev != st2.st_dev || st1.st_ino != st2.st_ino);

	ASSERT_EQ(close(fd1), 0);
	ASSERT_EQ(close(fd2), 0);
	free(fh1);
	free(fh2);

	umount2(tmpdir2, MNT_DETACH);
	rmdir(tmpdir2);
}

TEST_HARNESS_MAIN
