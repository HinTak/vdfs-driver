/**
 * VDFS4 -- Vertically Deliberate improved performance File System
 *
 * Copyright 2012 by Samsung Electronics, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include <linux/xattr.h>
#include <linux/fs.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>

#include "vdfs4.h"
#include "xattrtree.h"
#include <linux/vdfs_trace.h>	/* FlashFS : vdfs-trace */

char *vdfs4_xattr_prefixes[] = {
	XATTR_USER_PREFIX,
	XATTR_SYSTEM_PREFIX,
	XATTR_TRUSTED_PREFIX,
	XATTR_SECURITY_PREFIX,
	NULL
};

static int check_xattr_prefix(const char *name)
{
	int ret = 0;
	char **prefix;

	prefix = vdfs4_xattr_prefixes;
	while (*prefix != NULL)	{
		ret = strncmp(name, *prefix, strlen(*prefix));
		if (ret == 0)
			break;
		prefix++;
	}

	return ret;
}

static int xattrtree_insert(struct vdfs4_btree *tree, u64 object_id,
		const char *name, size_t val_len, const void *value)
{
	void *insert_data = NULL;
	struct vdfs4_xattrtree_key *key;
	size_t key_len;
	size_t name_len = strlen(name);
	int ret = 0;

	/* Consider that value has preceding one byte of length */
	if (name_len >= VDFS4_XATTR_NAME_MAX_LEN ||
			val_len >= VDFS4_XATTR_VAL_MAX_LEN - 1) {
		VDFS4_ERR("xattr name or val too long");
		return -EINVAL;
	}
	insert_data = kzalloc(tree->max_record_len, GFP_NOFS);
	if (!insert_data)
		return -ENOMEM;

	key = insert_data;

	key_len = sizeof(*key) - sizeof(key->name) + name_len;

	memcpy(key->gen_key.magic, VDFS4_XATTR_REC_MAGIC,
		strlen(VDFS4_XATTR_REC_MAGIC));

	key->gen_key.key_len = cpu_to_le16(ALIGN(key_len, 8));
	key->gen_key.record_len =
		cpu_to_le16(key->gen_key.key_len + ALIGN(val_len + 1, 8));

	key->object_id = cpu_to_le64(object_id);
	memcpy(key->name, name, name_len);
	key->name_len = (__u8)name_len;

	/* Save preceding length byte */
	*(unsigned char *)get_value_pointer(key) = (unsigned char)val_len;
	/* Copy value excluding length byte  */
	memcpy((void *)((char *)get_value_pointer(key) + 1), value, val_len);

	ret = vdfs4_btree_insert(tree, insert_data, 0);
	kfree(insert_data);

	return ret;
}


/**
 * @brief		Xattr tree key compare function.
 * @param [in]	__key1	Pointer to the first key
 * @param [in]	__key2	Pointer to the second key
 * @return		Returns value	< 0	if key1 < key2,
					== 0	if key1 = key2,
					> 0	if key1 > key2 (like strcmp)
 */
int vdfs4_xattrtree_cmpfn(struct vdfs4_generic_key *__key1,
		struct vdfs4_generic_key *__key2)
{
	struct vdfs4_xattrtree_key *key1, *key2;
	int diff;
	size_t len;


	key1 = container_of(__key1, struct vdfs4_xattrtree_key, gen_key);
	key2 = container_of(__key2, struct vdfs4_xattrtree_key, gen_key);

	if (key1->object_id < key2->object_id)
		return -1;
	if (key1->object_id > key2->object_id)
		return 1;

	len = min(key1->name_len, key2->name_len);
	if (len) {
		diff = memcmp(key1->name, key2->name, len);
		if (diff)
			return diff;
	}

	return (int)key1->name_len - (int)key2->name_len;
}

static struct vdfs4_xattrtree_key *xattrtree_alloc_key(u64 object_id,
		const char *name)
{
	struct vdfs4_xattrtree_key *key;
	size_t name_len = strlen(name);

	if (name_len >= VDFS4_XATTR_NAME_MAX_LEN)
		return ERR_PTR(-EINVAL);

	key = kzalloc(sizeof(*key), GFP_NOFS);
	if (!key)
		return ERR_PTR(-ENOMEM);


	key->object_id = cpu_to_le64(object_id);
	key->name_len = (__u8)name_len;
	memcpy(key->name, name, name_len);

	return key;
}

static struct vdfs4_xattrtree_record *vdfs4_xattrtree_find(struct vdfs4_btree
	*btree, u64 object_id, const char *name,
	enum vdfs4_get_bnode_mode mode)
{
	struct vdfs4_xattrtree_key *key;
	struct vdfs4_xattrtree_record *record;

	key = xattrtree_alloc_key(object_id, name);
	if (IS_ERR(key))
		return (void *) key;

	record = (struct vdfs4_xattrtree_record *) vdfs4_btree_find(btree,
			&key->gen_key, mode);
	if (IS_ERR(record))
		goto exit;

	if (*name != '\0' &&
			btree->comp_fn(&key->gen_key, &record->key->gen_key)) {
		vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
		record = ERR_PTR(-ENODATA);
	}

exit:
	kfree(key);
	/* Correct return in case absent xattr is ENODATA */
	if (PTR_ERR(record) == -ENOENT)
		record = ERR_PTR(-ENODATA);
	return record;
}

static int xattrtree_remove_record(struct vdfs4_btree *tree, u64 object_id,
		const char *name)
{
	struct vdfs4_xattrtree_key *key;
	int ret;

	key = xattrtree_alloc_key(object_id, name);
	if (IS_ERR(key))
		return PTR_ERR(key);

	ret = vdfs4_btree_remove(tree, &key->gen_key);

	kfree(key);

	return ret;
}

static int xattrtree_get_next_record(struct vdfs4_xattrtree_record *record)
{
	return vdfs4_get_next_btree_record((struct vdfs4_btree_gen_record *)
			record);
}

static struct vdfs4_xattrtree_record *xattrtree_get_first_record(
		struct vdfs4_btree *tree, u64 object_id,
		enum vdfs4_get_bnode_mode mode)
{
	struct vdfs4_xattrtree_record *record;
	int ret = 0;

	record = vdfs4_xattrtree_find(tree, object_id, "", mode);

	if (IS_ERR(record))
		return record;

	ret = xattrtree_get_next_record(record);
	if (ret)
		goto err_exit;

	if (le64_to_cpu(record->key->object_id) != object_id) {
		ret = -ENOENT;
		goto err_exit;
	}

	return record;

err_exit:
	vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
	return ERR_PTR(ret);

}

#ifdef CONFIG_VDFS4_POSIX_ACL
struct posix_acl *vdfs4_get_acl(struct inode *inode, int type)
{
	struct vdfs4_sb_info *sbi = VDFS4_SB(inode->i_sb);
	struct vdfs4_xattrtree_record *record;
	struct posix_acl *acl;
	const char *name;
	size_t size;

	switch (type) {
	case ACL_TYPE_ACCESS:
		name = POSIX_ACL_XATTR_ACCESS;
		break;
	case ACL_TYPE_DEFAULT:
		name = POSIX_ACL_XATTR_DEFAULT;
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	/* FIXME : vdfs_trace_iops_get_acl */
	mutex_r_lock(sbi->xattr_tree->rw_tree_lock);
	record = vdfs4_xattrtree_find(sbi->xattr_tree, inode->i_ino,
				     name, VDFS4_BNODE_MODE_RO);
	if (record == ERR_PTR(-ENODATA)) {
		acl = NULL;
	} else if (IS_ERR(record)) {
		acl = ERR_CAST(record);
	} else {
		/*
		 * Consider that value has preceding one byte of length.
		 * See the xattrtree_insert function
		 */
		void *value = (unsigned char *)record->val + 1;
		size = *(unsigned char *)record->val;

		/* size = le32_to_cpu(record->key->gen_key.record_len) -
			le32_to_cpu(record->key->gen_key.key_len); */

		acl = posix_acl_from_xattr(&init_user_ns, value, size);
		vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
	}
	mutex_r_unlock(sbi->xattr_tree->rw_tree_lock);

	if (!IS_ERR(acl))
		set_cached_acl(inode, type, acl);

	return acl;
}

int vdfs4_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	struct vdfs4_sb_info *sbi = VDFS4_SB(inode->i_sb);
	const char *name;
	size_t size = 0;
	void *data = NULL;
	int ret;

	switch (type) {
	case ACL_TYPE_ACCESS:
		name = POSIX_ACL_XATTR_ACCESS;
		if (acl) {
			ret = posix_acl_equiv_mode(acl, &inode->i_mode);
			if (ret < 0)
				return ret;
		}
		break;
	case ACL_TYPE_DEFAULT:
		name = POSIX_ACL_XATTR_DEFAULT;
		if (!S_ISDIR(inode->i_mode))
			return acl ? -EACCES : 0;
		break;
	default:
		return -EINVAL;
	}

	if (acl) {
		size = posix_acl_xattr_size((int)acl->a_count);
		if (size > VDFS4_XATTR_VAL_MAX_LEN)
			return -ERANGE;
		data = kmalloc(size, GFP_NOFS);
		if (!data)
			return -ENOMEM;
		ret = posix_acl_to_xattr(&init_user_ns, acl, data, size);
		if (ret < 0)
			goto err_encode;
		size = (size_t)ret;
	}

	vdfs4_start_transaction(sbi);
	mutex_w_lock(sbi->xattr_tree->rw_tree_lock);
	ret = xattrtree_remove_record(sbi->xattr_tree, inode->i_ino, name);
	if (!ret || ret == -ENOENT) {
		ret = 0;
		if (acl)
			ret = xattrtree_insert(sbi->xattr_tree, inode->i_ino,
						name, size, data);
	}
	mutex_w_unlock(sbi->xattr_tree->rw_tree_lock);
	if (!ret) {
		inode->i_ctime = vdfs4_current_time(inode);
		mark_inode_dirty(inode);
	}
	vdfs4_stop_transaction(sbi);
err_encode:
	kfree(data);
	if (!ret)
		set_cached_acl(inode, type, acl);
	return ret;
}

static int vdfs4_get_acl_xattr(struct inode *inode, int type,
				void *buffer, size_t size)
{
	struct posix_acl *acl;
	int ret;

	if (!IS_POSIXACL(inode) || S_ISLNK(inode->i_mode))
		return -EOPNOTSUPP;
	acl = vdfs4_get_acl(inode, type);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	if (!acl)
		return -ENODATA;
	ret = posix_acl_to_xattr(&init_user_ns, acl, buffer, size);
	posix_acl_release(acl);
	return ret;
}

static int vdfs4_set_acl_xattr(struct inode *inode, int type,
				const void *value, size_t size)
{
	struct posix_acl *acl;
	int ret = 0;

	if (!IS_POSIXACL(inode) || S_ISLNK(inode->i_mode))
		return -EOPNOTSUPP;
	if (type == ACL_TYPE_DEFAULT && !S_ISDIR(inode->i_mode))
		return value ? -EACCES : 0;
	if (!inode_owner_or_capable(inode))
		return -EPERM;
	acl = posix_acl_from_xattr(&init_user_ns, value, size);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	if (acl)
		ret = posix_acl_valid(acl);
	if (!ret)
		ret = vdfs4_set_acl(inode, acl, type);
	posix_acl_release(acl);
	return ret;
}

int vdfs4_init_acl(struct inode *inode, struct inode *dir)
{
	struct posix_acl *default_acl = NULL, *acl = NULL;
	int error;

	error = posix_acl_create(dir, &inode->i_mode, &default_acl, &acl);
	if (error)
		return error;

	if (default_acl) {
		error = vdfs4_set_acl(inode, default_acl, ACL_TYPE_DEFAULT);
		posix_acl_release(default_acl);
	}
	if (acl) {
		if (!error)
			error = vdfs4_set_acl(inode, acl, ACL_TYPE_ACCESS);
		posix_acl_release(acl);
	}
	return error;
}

#else
static int vdfs4_get_acl_xattr(struct inode *inode, int type,
				void *buffer, size_t size)
{
	return -EOPNOTSUPP;
}

static int vdfs4_set_acl_xattr(struct inode *inode, int type,
				const void *value, size_t size)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_VDFS4_POSIX_ACL */

int vdfs4_xattrtree_remove_all(struct vdfs4_btree *tree, u64 object_id)
{
	struct vdfs4_xattrtree_record *record = NULL;
	struct vdfs4_xattrtree_key *rm_key =
		kzalloc(sizeof(*rm_key), GFP_NOFS);
	int ret = 0;

	if (!rm_key)
		return -ENOMEM;


	while (!ret) {
		vdfs4_start_transaction(tree->sbi);
		mutex_w_lock(tree->rw_tree_lock);

		record = xattrtree_get_first_record(tree, object_id,
				VDFS4_BNODE_MODE_RO);
		if (IS_ERR(record)) {
			if (PTR_ERR(record) == -ENOENT)
				ret = 0;
			else
				ret = PTR_ERR(record);

			mutex_w_unlock(tree->rw_tree_lock);
			vdfs4_stop_transaction(tree->sbi);
			break;
		}
		memcpy(rm_key, record->key, record->key->gen_key.key_len);
		vdfs4_release_record((struct vdfs4_btree_gen_record *) record);


		ret = vdfs4_btree_remove(tree, &rm_key->gen_key);
		mutex_w_unlock(tree->rw_tree_lock);
		vdfs4_stop_transaction(tree->sbi);
	}

	kfree(rm_key);
	return ret;
}

int vdfs4_setxattr(struct dentry *dentry, const char *name, const void *value,
		size_t size, int flags)
{
	int ret = 0;
	struct vdfs4_xattrtree_record *record;
	struct inode *inode = dentry->d_inode;
	struct vdfs4_sb_info *sbi = VDFS4_SB(inode->i_sb);

	VT_PREPARE_PARAM(vt_data);

	if (name == NULL)
		return -EINVAL;

	if (strlen(name) >= VDFS4_XATTR_NAME_MAX_LEN ||
			size >= VDFS4_XATTR_VAL_MAX_LEN)
		return -EINVAL;

	ret = check_xattr_prefix(name);
	if (ret)
		return -EOPNOTSUPP;

	if (!strcmp(name, POSIX_ACL_XATTR_DEFAULT))
		return vdfs4_set_acl_xattr(inode, ACL_TYPE_DEFAULT, value, size);
	if (!strcmp(name, POSIX_ACL_XATTR_ACCESS))
		return vdfs4_set_acl_xattr(inode, ACL_TYPE_ACCESS, value, size);

	VT_IOPS_START(vt_data, vdfs_trace_iops_setxattr, dentry);
	vdfs4_start_transaction(sbi);
	mutex_w_lock(sbi->xattr_tree->rw_tree_lock);

	record = vdfs4_xattrtree_find(sbi->xattr_tree, inode->i_ino, name,
			VDFS4_BNODE_MODE_RW);

	if (!IS_ERR(record)) {
		/* record found */
		vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
		if (flags & XATTR_CREATE) {
			ret = -EEXIST;
			goto exit;
		} else {
			ret = xattrtree_remove_record(sbi->xattr_tree,
				inode->i_ino, name);
			if (ret)
				goto exit;
		}
	} else if (PTR_ERR(record) == -ENODATA) {
		/* no such record */
		if (flags & XATTR_REPLACE) {
			ret = -ENODATA;
			goto exit;
		} else
			goto insert_xattr;
	} else {
		/* some other error */
		ret = PTR_ERR(record);
		goto exit;
	}

insert_xattr:
	ret = xattrtree_insert(sbi->xattr_tree, inode->i_ino, name, size,
			value);
exit:
	mutex_w_unlock(sbi->xattr_tree->rw_tree_lock);
	if (!ret) {
		inode->i_ctime = vdfs4_current_time(inode);
		mark_inode_dirty(inode);
	}
	vdfs4_stop_transaction(sbi);
	VT_FINISH(vt_data);
	return ret;
}

static inline u64 get_disk_inode_no(struct inode *inode)
{
	u64 result = inode->i_ino;
	return result;
}

ssize_t vdfs4_getxattr(struct dentry *dentry, const char *name, void *buffer,
		size_t buf_size)
{
	struct vdfs4_xattrtree_record *record;
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct vdfs4_sb_info *sbi = sb->s_fs_info;
	ssize_t size;
	struct vdfs4_btree *btree;

	VT_PREPARE_PARAM(vt_data);

	if (strcmp(name, "") == 0)
		return -EINVAL;

	if (check_xattr_prefix(name))
		return -EOPNOTSUPP;

	btree = sbi->xattr_tree;
	if (IS_ERR(btree))
		return PTR_ERR(btree);

	if (!strcmp(name, POSIX_ACL_XATTR_DEFAULT))
		return vdfs4_get_acl_xattr(inode, ACL_TYPE_DEFAULT,
						buffer, buf_size);
	if (!strcmp(name, POSIX_ACL_XATTR_ACCESS))
		return vdfs4_get_acl_xattr(inode, ACL_TYPE_ACCESS,
						buffer, buf_size);

	if (btree->btree_type != VDFS4_BTREE_INST_XATTR)
		mutex_r_lock(btree->rw_tree_lock);

	VT_IOPS_START(vt_data, vdfs_trace_iops_getxattr, dentry);
	record = vdfs4_xattrtree_find(btree, get_disk_inode_no(inode), name,
			VDFS4_BNODE_MODE_RO);

	if (IS_ERR(record)) {
		if (btree->btree_type != VDFS4_BTREE_INST_XATTR)
			mutex_r_unlock(btree->rw_tree_lock);
		VT_FINISH(vt_data);
		return PTR_ERR(record);
	}

	/* Get preceding length byte */
	size = *(unsigned char *)record->val;
	if (!buffer)
		goto exit;

	if (size > (ssize_t)buf_size) {
		size = -ERANGE;
		goto exit;
	}

	memcpy(buffer, record->val + 1, (size_t)size);
exit:
	vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
	if (btree->btree_type != VDFS4_BTREE_INST_XATTR)
		mutex_r_unlock(btree->rw_tree_lock);
	VT_FINISH(vt_data);
	return size;
}


int vdfs4_removexattr(struct dentry *dentry, const char *name)
{
	struct inode *inode = dentry->d_inode;
	struct vdfs4_sb_info *sbi = VDFS4_SB(inode->i_sb);
	int ret = 0;

	VT_PREPARE_PARAM(vt_data);
	if (strcmp(name, "") == 0)
		return -EINVAL;

	VT_IOPS_START(vt_data, vdfs_trace_iops_removexattr, dentry);
	vdfs4_start_transaction(sbi);
	mutex_w_lock(sbi->xattr_tree->rw_tree_lock);

	ret = xattrtree_remove_record(sbi->xattr_tree, inode->i_ino, name);

	mutex_w_unlock(sbi->xattr_tree->rw_tree_lock);
	vdfs4_stop_transaction(sbi);
	VT_FINISH(vt_data);
	return ret;
}

ssize_t vdfs4_listxattr(struct dentry *dentry, char *buffer, size_t buf_size)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct vdfs4_sb_info *sbi = sb->s_fs_info;
	struct vdfs4_xattrtree_record *record;
	struct vdfs4_btree *btree;
	ssize_t size = 0;
	int ret = 0;
	u64 disk_ino_no = get_disk_inode_no(inode);

	VT_PREPARE_PARAM(vt_data);

	btree = sbi->xattr_tree;
	if (IS_ERR(btree))
		return PTR_ERR(btree);

	if (btree->btree_type != VDFS4_BTREE_INST_XATTR)
		mutex_r_lock(btree->rw_tree_lock);
	VT_IOPS_START(vt_data, vdfs_trace_iops_listxattr, dentry);
	record = xattrtree_get_first_record(btree, disk_ino_no,
			VDFS4_BNODE_MODE_RO);

	if (IS_ERR(record)) {
		if (btree->btree_type != VDFS4_BTREE_INST_XATTR)
			mutex_r_unlock(btree->rw_tree_lock);
		VT_FINISH(vt_data);
		if (PTR_ERR(record) == -ENOENT)
			return 0; /* no exteneded attributes */
		else
			return PTR_ERR(record);
	}

	while (!ret && le64_to_cpu(record->key->object_id) == disk_ino_no) {
		size_t name_len = (size_t)record->key->name_len + 1lu;

		if (buffer) {
			if (buf_size < name_len) {
				ret = -ERANGE;
				break;
			}
			memcpy(buffer, record->key->name, name_len - 1lu);
			buffer[name_len - 1] = 0;
			buf_size -= name_len;
			buffer += name_len;
		}

		size += (ssize_t)name_len;

		ret = xattrtree_get_next_record(record);
	}

	if (ret == -ENOENT)
		/* It is normal if there is no more records in the btree */
		ret = 0;

	vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
	if (btree->btree_type != VDFS4_BTREE_INST_XATTR)
		mutex_r_unlock(btree->rw_tree_lock);
	VT_FINISH(vt_data);
	return ret ? ret : size;
}

int vdfs4_init_security_xattrs(struct inode *inode,
		const struct xattr *xattr_array, void *fs_data)
{
	struct vdfs4_sb_info *sbi = VDFS4_SB(inode->i_sb);
	const struct xattr *xattr;
	char *name = NULL;
	size_t name_len;
	int ret = 0;

	mutex_w_lock(sbi->xattr_tree->rw_tree_lock);
	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		name_len = strlen(xattr->name) + 1lu;
		name = krealloc(name, XATTR_SECURITY_PREFIX_LEN +
				name_len, GFP_NOFS);
		ret = -ENOMEM;
		if (!name)
			break;
		memcpy(name, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN);
		memcpy(name + XATTR_SECURITY_PREFIX_LEN, xattr->name,
				name_len);
#if 0
		/* always called for new inode */
		ret = xattrtree_remove_record(sbi->xattr_tree,
						inode->i_ino, name);
		if (ret && ret != -ENOENT)
			break;
#endif
		ret = 0;
		if (xattr->value)
			ret = xattrtree_insert(sbi->xattr_tree, inode->i_ino,
					name, xattr->value_len, xattr->value);
		if (ret)
			break;
	}
	mutex_w_unlock(sbi->xattr_tree->rw_tree_lock);
	kfree(name);

	return ret;
}
