#ifndef _LCFS_READER_H
#define _LCFS_READER_H

#include "lcfs.h"

#define EFSCORRUPTED       EUCLEAN         /* Filesystem is corrupted */

#ifdef FUZZING
# define ERR_CAST(x)((void *)x)
# define ERR_PTR(x)((void *)((long)x))
# define PTR_ERR(x)((long)x)
# define IS_ERR(x) ((unsigned long)(void *)(x) >= (unsigned long)-4096)
#endif

struct lcfs_context_s;

struct lcfs_context_s *lcfs_create_ctx(char *descriptor_path);

struct lcfs_context_s *lcfs_create_ctx_from_memory(char *blob, size_t size);

void lcfs_destroy_ctx(struct lcfs_context_s *ctx);

struct lcfs_dentry_s *lcfs_get_dentry(struct lcfs_context_s *ctx, size_t index);

void *lcfs_get_vdata(struct lcfs_context_s *ctx,
		     const struct lcfs_vdata_s vdata);

lcfs_off_t lcfs_get_dentry_index(struct lcfs_context_s *ctx,
				 struct lcfs_dentry_s *node);

struct lcfs_inode_s *lcfs_get_ino_index(struct lcfs_context_s *ctx,
					lcfs_off_t index);

struct lcfs_inode_s *lcfs_dentry_inode(struct lcfs_context_s *ctx,
				       struct lcfs_dentry_s *node);

struct lcfs_inode_data_s *lcfs_inode_data(struct lcfs_context_s *ctx,
					  struct lcfs_inode_s *ino);

char *lcfs_c_string(struct lcfs_context_s *ctx, lcfs_c_str_t off, size_t *len,
		    size_t max);

static inline u64 lcfs_dentry_ino(struct lcfs_dentry_s *d)
{
	return d->inode_index;
}

u64 lcfs_ino_num(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino);

lcfs_off_t lcfs_get_root_index(struct lcfs_context_s *ctx);

ssize_t lcfs_list_xattrs(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino, char *names, size_t size);

int lcfs_get_xattr(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino, const char *name, void *value, size_t size);

typedef bool (*lcfs_dir_iter_cb)(void *private, const char *name, int namelen, u64 ino, unsigned int dtype);

int lcfs_iterate_dir(struct lcfs_context_s *ctx, loff_t first, struct lcfs_inode_s *dir_ino, lcfs_dir_iter_cb cb, void *private);

int lcfs_lookup(struct lcfs_context_s *ctx, struct lcfs_inode_s *dir, const char *name, lcfs_off_t *index);

const char *lcfs_get_payload(struct lcfs_context_s *ctx, struct lcfs_inode_s *ino);

struct inode *lcfs_make_inode(struct lcfs_context_s *ctx, struct super_block *sb, struct lcfs_inode_s *ino, const struct inode *dir);

#endif
