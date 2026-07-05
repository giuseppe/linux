// SPDX-License-Identifier: GPL-2.0
/*
 * mntfs - pseudo-filesystem for mount file handles
 *
 * Provides name_to_handle_at/open_by_handle_at support for mount objects,
 * enabling userspace to persist and reopen references to mounts - including
 * detached mounts that are not visible in any mount namespace.
 *
 * The design follows nsfs closely: a per-mount stashed dentry, a global
 * xarray lookup by mnt_id_unique, and a FD_MNTFS_ROOT sentinel for
 * open_by_handle_at.
 */

#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/ns_common.h>
#include <linux/pseudo_fs.h>
#include <linux/exportfs.h>
#include <linux/seq_file.h>
#include <linux/unaligned.h>

#include "mount.h"
#include "internal.h"

static struct vfsmount *mntfs_mnt;
static struct path mntfs_root_path;

void mntfs_get_root(struct path *path)
{
	*path = mntfs_root_path;
	path_get(path);
}

#define MNTFS_FID_LEN_U32 (sizeof(u64) / sizeof(u32))
#define FILEID_MNTFS 0x4d

static char *mntfs_dname(struct dentry *dentry, char *buffer, int buflen)
{
	struct inode *inode = d_inode(dentry);
	struct mount *mnt = inode->i_private;

	return dynamic_dname(buffer, buflen, "mnt:[%u]", mnt->mnt_id);
}

static const struct dentry_operations mntfs_dentry_operations = {
	.d_dname	= mntfs_dname,
	.d_prune	= stashed_dentry_prune,
};

static void mntfs_evict(struct inode *inode)
{
	struct mount *mnt = inode->i_private;

	clear_inode(inode);
	mntput(&mnt->mnt);
}

static int mntfs_show_path(struct seq_file *seq, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	struct mount *mnt = inode->i_private;

	seq_printf(seq, "mnt:[%u]", mnt->mnt_id);
	return 0;
}

static const struct super_operations mntfs_sops = {
	.statfs		= simple_statfs,
	.evict_inode	= mntfs_evict,
	.show_path	= mntfs_show_path,
	.drop_inode	= inode_just_drop,
};

static int mntfs_init_inode(struct inode *inode, void *data)
{
	struct mount *mnt = data;

	inode->i_private = data;
	inode->i_mode |= S_IRUGO;
	inode->i_ino = mnt->mnt_id_unique;
	return 0;
}

static void mntfs_put_data(void *data)
{
	struct mount *mnt = data;

	mntput(&mnt->mnt);
}

static const struct stashed_operations mntfs_stashed_ops = {
	.init_inode	= mntfs_init_inode,
	.put_data	= mntfs_put_data,
};

static int mntfs_encode_fh(struct inode *inode, u32 *fh, int *max_len,
			    struct inode *parent)
{
	struct mount *mnt = inode->i_private;

	if (parent)
		return FILEID_INVALID;

	if (*max_len < MNTFS_FID_LEN_U32) {
		*max_len = MNTFS_FID_LEN_U32;
		return FILEID_INVALID;
	}

	*max_len = MNTFS_FID_LEN_U32;
	put_unaligned(mnt->mnt_id_unique, (u64 *)fh);
	return FILEID_MNTFS;
}

static struct dentry *mntfs_fh_to_dentry(struct super_block *sb,
					  struct fid *fh, int fh_len,
					  int fh_type)
{
	struct path path __free(path_put) = {};
	struct mount *mnt;
	u64 mnt_id_unique;
	int ret;

	if (fh_type != FILEID_MNTFS)
		return NULL;

	if (fh_len < MNTFS_FID_LEN_U32)
		return NULL;

	mnt_id_unique = get_unaligned((u64 *)fh);

	rcu_read_lock();
	mnt = xa_load(&mnt_id_unique_xa, mnt_id_unique);
	if (mnt)
		mntget(&mnt->mnt);
	rcu_read_unlock();

	if (!mnt)
		return ERR_PTR(-ESTALE);

	/*
	 * If the mount is not in the caller's mount namespace,
	 * require CAP_SYS_ADMIN in the initial namespace.
	 * This mirrors the nsfs visibility check.
	 */
	if (mnt->mnt_ns != current->nsproxy->mnt_ns &&
	    !may_see_all_namespaces()) {
		mntput(&mnt->mnt);
		return ERR_PTR(-EPERM);
	}

	/* path_from_stashed() unconditionally consumes the reference. */
	ret = path_from_stashed(&mnt->mnt_stashed, mntfs_mnt, mnt, &path);
	if (ret)
		return ERR_PTR(ret);

	return no_free_ptr(path.dentry);
}

static int mntfs_export_permission(struct handle_to_path_ctx *ctx,
				    unsigned int oflags)
{
	return 0;
}

static struct file *mntfs_export_open(const struct path *path,
				      unsigned int oflags)
{
	return file_open_root(path, "", oflags, 0);
}

static const struct export_operations mntfs_export_operations = {
	.encode_fh	= mntfs_encode_fh,
	.fh_to_dentry	= mntfs_fh_to_dentry,
	.open		= mntfs_export_open,
	.permission	= mntfs_export_permission,
};

static int mntfs_init_fs_context(struct fs_context *fc)
{
	struct pseudo_fs_context *ctx = init_pseudo(fc, MNTFS_MAGIC);

	if (!ctx)
		return -ENOMEM;
	ctx->s_d_flags |= DCACHE_DONTCACHE;
	ctx->ops = &mntfs_sops;
	ctx->eops = &mntfs_export_operations;
	ctx->dops = &mntfs_dentry_operations;
	fc->s_fs_info = (void *)&mntfs_stashed_ops;
	return 0;
}

static struct file_system_type mntfs = {
	.name		= "mntfs",
	.init_fs_context = mntfs_init_fs_context,
	.kill_sb	= kill_anon_super,
};

void __init mntfs_init(void)
{
	mntfs_mnt = kern_mount(&mntfs);
	if (IS_ERR(mntfs_mnt))
		panic("can't set mntfs up\n");
	mntfs_mnt->mnt_sb->s_flags &= ~SB_NOUSER;
	mntfs_root_path.mnt = mntfs_mnt;
	mntfs_root_path.dentry = mntfs_mnt->mnt_root;
}
