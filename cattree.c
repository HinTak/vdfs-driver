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

#include <linux/slab.h>
#include <linux/ctype.h>

#include "vdfs4.h"
#include "cattree.h"
#include "debug.h"
#include "vdfs4.h"

/**
 * @brief		Key compare function for catalog tree
 *			for case-sensitive usecase.
 * @param [in]	__key1	Pointer to the first key
 * @param [in]	__key2	Pointer to the second key
 * @return		Returns value	< 0	if key1 < key2,
					== 0	if key1 = key2,
					> 0	if key1 > key2 (like strcmp)
 */
int vdfs4_cattree_cmpfn(struct vdfs4_generic_key *__key1,
		struct vdfs4_generic_key *__key2)
{
	struct vdfs4_cattree_key *key1, *key2;
	int ret, len;

	key1 = container_of(__key1, struct vdfs4_cattree_key, gen_key);
	key2 = container_of(__key2, struct vdfs4_cattree_key, gen_key);

	if (key1->parent_id < key2->parent_id)
		return -1;
	if (key1->parent_id > key2->parent_id)
		return 1;

	len = min(key1->name_len, key2->name_len);
	if (len) {
		ret = memcmp(key1->name, key2->name, (size_t)len);
		if (ret)
			return ret;
	}

	if (key1->name_len != key2->name_len)
		return (int)key1->name_len - (int)key2->name_len;

	if (key1->object_id < key2->object_id)
		return -1;
	if (key1->object_id > key2->object_id)
		return 1;

	return 0;
}

/**
 * @brief		Key compare function for catalog tree
 *			for case-insensitive usecase.
 * @param [in]	__key1	Pointer to the first key
 * @param [in]	__key2	Pointer to the second key
 * @return		Returns value	< 0	if key1 < key2,
					== 0	if key1 = key2,
					> 0	if key1 > key2 (like strcmp)
 */
int vdfs4_cattree_cmpfn_ci(struct vdfs4_generic_key *__key1,
		struct vdfs4_generic_key *__key2)
{
	struct vdfs4_cattree_key *key1, *key2;
	int ret, len;

	key1 = container_of(__key1, struct vdfs4_cattree_key, gen_key);
	key2 = container_of(__key2, struct vdfs4_cattree_key, gen_key);

	if (key1->parent_id < key2->parent_id)
		return -1;
	if (key1->parent_id > key2->parent_id)
		return 1;

	len = min(key1->name_len, key2->name_len);
	if (len) {
		ret = strncasecmp(key1->name, key2->name, (size_t)len);
		if (ret)
			return ret;
	}

	if (key1->name_len != key2->name_len)
		return (int)key1->name_len - (int)key2->name_len;

	if (key1->object_id < key2->object_id)
		return -1;
	if (key1->object_id > key2->object_id)
		return 1;

	return 0;
}

bool vdfs4_cattree_is_orphan(struct vdfs4_cattree_record *record)
{
	struct vdfs4_catalog_folder_record *val = record->val;

	switch (record->key->record_type) {
	case VDFS4_CATALOG_FOLDER_RECORD:
	case VDFS4_CATALOG_FILE_RECORD:
	case VDFS4_CATALOG_DLINK_RECORD:
		return (le32_to_cpu(val->flags) & (1<<ORPHAN_INODE)) != 0;
	default:
		return false;
	}
}

/* Help function for building new cattree interfaces and trancling them inot
 * old */
static int temp_fill_record(struct vdfs4_bnode *bnode, int pos,
		struct vdfs4_btree_record_info *rec_info)
{
	struct vdfs4_cattree_record *record = (void *) &rec_info->gen_record;

	rec_info->rec_pos.bnode = bnode;
	rec_info->rec_pos.pos = pos;
	record->key = vdfs4_get_btree_record(bnode, pos);

	BUG_ON(!record->key);
	if (IS_ERR(record->key)) {
		kfree(record);
		VDFS4_ERR("unable to get record");
		VDFS4_BUG();
	}


	record->val = get_value_pointer(record->key);
	if (IS_ERR(record->val))
		return PTR_ERR(record->val);
	return 0;
}

/*
 * Finds inode record when we knows everythin about its location.
 */
struct vdfs4_cattree_record *vdfs4_cattree_find_inode(struct vdfs4_btree *btree,
		__u64 object_id, __u64 parent_id, const char *name, size_t len,
		enum vdfs4_get_bnode_mode mode)
{
	struct vdfs4_cattree_key *key;
	struct vdfs4_cattree_record *record;

	key = kzalloc(sizeof(*key), GFP_NOFS);
	if (!key)
		return ERR_PTR(-ENOMEM);

	key->parent_id = cpu_to_le64(parent_id);
	key->object_id = cpu_to_le64(object_id);
	key->name_len = (u8)len;
	memcpy(key->name, name, (size_t)len);

	record = (struct vdfs4_cattree_record *) vdfs4_btree_find(btree,
			&key->gen_key, mode);
	if (IS_ERR(record))
		goto exit;

	if (btree->comp_fn(&record->key->gen_key, &key->gen_key)) {
		vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
		record = ERR_PTR(-ENOENT);
	}

exit:
	kfree(key);
	return record;
}

#define GREATEST_AVAIL_ID (-1ULL)
/*
 * Finds inode record with given parent_id and name.
 */
struct vdfs4_cattree_record *vdfs4_cattree_find(struct vdfs4_btree *btree,
		__u64 parent_id, const char *name, size_t len,
		enum vdfs4_get_bnode_mode mode)
{
	struct vdfs4_cattree_key *key;
	struct vdfs4_cattree_record *record;

	key = kzalloc(sizeof(*key), GFP_NOFS);
	if (!key)
		return ERR_PTR(-ENOMEM);

	/*
	 * Get the last record with key <parent_id, name, *>
	 */
	key->parent_id = cpu_to_le64(parent_id);
	key->object_id = cpu_to_le64(GREATEST_AVAIL_ID);
	key->name_len = (u8)len;
	memcpy(key->name, name, (size_t)len);

	record = (struct vdfs4_cattree_record *) vdfs4_btree_find(btree,
			&key->gen_key, mode);
	if (IS_ERR(record))
		goto exit;

	key->object_id = record->key->object_id;
	if (btree->comp_fn(&record->key->gen_key, &key->gen_key)) {
		vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
		record = ERR_PTR(-ENOENT);
		goto exit;
	}

	if (!vdfs4_cattree_is_orphan(record))
		goto exit;

	vdfs4_release_record((struct vdfs4_btree_gen_record *) record);

	/*
	 * get prev-to-first record for key <parent_id, name, *>
	 */
	key->object_id = 0;
	record = (struct vdfs4_cattree_record *)vdfs4_btree_find(btree,
			&key->gen_key, mode);
	if (IS_ERR(record))
		goto exit;

	do {
		int ret;

		ret = vdfs4_get_next_btree_record(
				(struct vdfs4_btree_gen_record *)record);
		if (ret) {
			vdfs4_release_record((struct vdfs4_btree_gen_record *)
					record);
			record = ERR_PTR(ret);
			break;
		}

		key->object_id = record->key->object_id;
		if (btree->comp_fn(&record->key->gen_key, &key->gen_key)) {
			vdfs4_release_record((struct vdfs4_btree_gen_record *)
					record);
			record = ERR_PTR(-ENOENT);
			break;
		}
	} while (vdfs4_cattree_is_orphan(record));

exit:
	kfree(key);
	return record;
}

/*
 * This finds hard-link body, its key is <object_id, "", object_id>
 */
struct vdfs4_cattree_record *vdfs4_cattree_find_hlink(struct vdfs4_btree *btree,
		__u64 object_id, enum vdfs4_get_bnode_mode mode)
{
	return vdfs4_cattree_find_inode(btree,
			object_id, object_id, NULL, 0, mode);
}

/**
 * @brief			Allocate key for catalog tree record.
 * @param [in]	name_len	Length of a name for an allocating object
 * @param [in]	record_type	Type of record which it should be
 * @return			Returns pointer to a newly allocated key
 *				or error code otherwise
 */
struct vdfs4_cattree_key *vdfs4_alloc_cattree_key(int name_len,
		u8 record_type)
{
	u32 record_len = 0;
	struct vdfs4_cattree_key *form_key;
	u32 key_len = sizeof(form_key->gen_key) + sizeof(form_key->parent_id) +
		sizeof(form_key->object_id) + sizeof(form_key->record_type) +
		sizeof(form_key->name_len) + (u32)name_len;

	key_len = ALIGN(key_len, 8);

	BUILD_BUG_ON(!IS_ALIGNED(sizeof(struct vdfs4_catalog_file_record), 8));
	BUILD_BUG_ON(!IS_ALIGNED(sizeof(struct vdfs4_catalog_folder_record), 8));
	BUILD_BUG_ON(!IS_ALIGNED(sizeof(struct vdfs4_catalog_hlink_record), 8));

	switch (record_type) {
	case VDFS4_CATALOG_FILE_RECORD:
		record_len = sizeof(struct vdfs4_catalog_file_record);
	break;
	case VDFS4_CATALOG_FOLDER_RECORD:
	case VDFS4_CATALOG_RECORD_DUMMY:
		record_len = sizeof(struct vdfs4_catalog_folder_record);
	break;
	case VDFS4_CATALOG_HLINK_RECORD:
		record_len = sizeof(struct vdfs4_catalog_hlink_record);
	break;
	case VDFS4_CATALOG_DLINK_RECORD:
		record_len = sizeof(struct vdfs4_catalog_dlink_record);
	break;
	case VDFS4_CATALOG_ILINK_RECORD:
		record_len = 0;
	break;
	default:
		VDFS4_BUG();
	}

	form_key = kzalloc(key_len + record_len, GFP_NOFS);
	if (!form_key)
		return ERR_PTR(-ENOMEM);

	form_key->gen_key.key_len = cpu_to_le16(key_len);
	form_key->gen_key.record_len = cpu_to_le16(key_len + record_len);
	form_key->record_type = record_type;

	return form_key;
}

/**
 * @brief			Fill already allocated key with data.
 * @param [out] fill_key	Key to fill
 * @param [in]	parent_id	Parent id of object
 * @param [in]	name		Object name
 * @return	void
 */
void vdfs4_fill_cattree_key(struct vdfs4_cattree_key *fill_key,
	u64 object_id, u64 parent_id, const char *name, unsigned int len)
{
	fill_key->name_len = (__u8)len;
	memcpy(fill_key->name, name, len);
	fill_key->parent_id = cpu_to_le64(parent_id);
	fill_key->object_id = cpu_to_le64(object_id);
}

struct vdfs4_cattree_record *vdfs4_cattree_place_record(
		struct vdfs4_btree *tree, u64 object_id, u64 parent_id,
		const char *name, size_t len, u8 record_type)
{
	struct vdfs4_cattree_record *record;
	struct vdfs4_cattree_key *key;
	int err = 0;
	/* insert ilink. if record is hlink body or hlink reference we do not
	 * need ilink */
	if ((object_id != parent_id) &&
			(record_type != VDFS4_CATALOG_HLINK_RECORD)) {
		err = vdfs4_cattree_insert_ilink(tree, object_id, parent_id,
				name, len);
		if (err)
			return ERR_PTR(err);
	}

	/* Still not perfect, this allocates buffer for key + value */
	key = vdfs4_alloc_cattree_key((int)len, record_type);
	if (IS_ERR(key)) {
		vdfs4_cattree_remove_ilink(tree, object_id, parent_id, name,
				len);
		return ERR_CAST(key);
	}
	vdfs4_fill_cattree_key(key, object_id, parent_id, name,
			(unsigned)len);
	record = (struct vdfs4_cattree_record *)
		vdfs4_btree_place_data(tree, &key->gen_key);
	if(IS_ERR(record))
		vdfs4_cattree_remove_ilink(tree, object_id, parent_id, name,
						len);

	kfree(key);
	return record;
}

int vdfs4_cattree_insert_ilink(struct vdfs4_btree *tree, __u64 object_id,
		__u64 parent_id, const char *name, size_t name_len)
{
	struct vdfs4_btree_gen_record *record;
	struct vdfs4_cattree_key *key;

	key = vdfs4_alloc_cattree_key((int)name_len,
			VDFS4_CATALOG_ILINK_RECORD);
	if (IS_ERR(key))
		return PTR_ERR(key);
	/* parent_id stored as object_id and vice versa */
	vdfs4_fill_cattree_key(key, parent_id, object_id, name,
			(unsigned)name_len);
	record = vdfs4_btree_place_data(tree, &key->gen_key);
	kfree(key);
	if (IS_ERR(record))
		return PTR_ERR(record);
	vdfs4_release_dirty_record(record);
	return 0;
}

int vdfs4_cattree_remove_ilink(struct vdfs4_btree *tree, __u64 object_id,
		__u64 parent_id, const char *name, size_t name_len)
{
	return vdfs4_cattree_remove(tree, parent_id, object_id, name, name_len,
			VDFS4_CATALOG_ILINK_RECORD);
}

/**
 * @brief                   Find first child object for the specified catalog.
 * @param [in] sbi          Pointer to superblock information
 * @param [in] catalog_id   Id of the parent catalog
 * @return             Returns cattree record containing first child object
 *                     in case of success, error code otherwise
 */
struct vdfs4_cattree_record *vdfs4_cattree_get_first_child(
	struct vdfs4_btree *btree, __u64 catalog_id)
{
	struct vdfs4_cattree_key *search_key;
	struct vdfs4_cattree_record *record;
	int ret;

	search_key = kzalloc(sizeof(*search_key), GFP_NOFS);
	if (!search_key)
		return ERR_PTR(-ENOMEM);

	search_key->parent_id = cpu_to_le64(catalog_id);
	search_key->name_len = 0;

	record = (struct vdfs4_cattree_record *) vdfs4_btree_find(btree,
			&search_key->gen_key, VDFS4_BNODE_MODE_RO);
	if (IS_ERR(record))
		goto exit;

	ret = vdfs4_get_next_btree_record((struct vdfs4_btree_gen_record *)
			record);
	if (ret) {
		vdfs4_release_record((struct vdfs4_btree_gen_record *) record);
		record = ERR_PTR(ret);
	}
exit:
	kfree(search_key);
	return record;
}

int vdfs4_cattree_get_next_record(struct vdfs4_cattree_record *record)
{
	int ret = 0;
	struct vdfs4_btree_record_info *rec_info =
		VDFS4_BTREE_REC_I((void *) record);

	struct vdfs4_bnode *bnode = rec_info->rec_pos.bnode;
	int pos = rec_info->rec_pos.pos;
	void *raw_record = NULL;

	raw_record = __vdfs4_get_next_btree_record(&bnode, &pos);

	/* Ret value have to be pointer, or error, not null */
	BUG_ON(!raw_record);
	if (IS_ERR(raw_record))
		return PTR_ERR(raw_record);

	ret = temp_fill_record(bnode, pos, rec_info);

	return ret;
}

int vdfs4_cattree_remove(struct vdfs4_btree *tree, __u64 object_id,
		__u64 parent_id, const char *name, size_t len, u8 record_type)
{
	int ret = 0;
	struct vdfs4_cattree_key *key;

	key = kzalloc(sizeof(*key), GFP_NOFS);
	if (!key)
		return -ENOMEM;
	/* remove ilink. hlink and hlink reference don't have the ilink */
	if ((object_id != parent_id) &&
			(record_type != VDFS4_CATALOG_HLINK_RECORD) &&
			(record_type != VDFS4_CATALOG_ILINK_RECORD)) {
		key->parent_id = cpu_to_le64(object_id);
		key->object_id = cpu_to_le64(parent_id);
		key->name_len = (__u8)len;
		memcpy(key->name, name, (size_t)len);
		ret = vdfs4_btree_remove(tree, &key->gen_key);
		if (ret) {
			kfree(key);
			return ret;
		}
	}

	key->parent_id = cpu_to_le64(parent_id);
	key->object_id = cpu_to_le64(object_id);
	key->name_len = (__u8)len;
	memcpy(key->name, name, (size_t)len);
	ret = vdfs4_btree_remove(tree, &key->gen_key);
	kfree(key);
	return ret;
}
