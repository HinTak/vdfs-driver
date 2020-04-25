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

#include <linux/pagemap.h>
#include <linux/vmalloc.h>
#include <linux/blkdev.h>

#include "vdfs4.h"

/*
 * This structure represents extent of free space.
 * sizeof is 32 bytes on 32-bit system.
 */
struct fsm_node {
	struct rb_node node; /* must be first or NULL pointer wouldnt be NULL */
	struct list_head list;
	__u32 length;
	__u64 start;
};

static struct kmem_cache *fsm_node_cachep;

static inline struct fsm_node *fsm_first(struct rb_root *root)
{
	return container_of(rb_first(root), struct fsm_node, node);
}

static inline struct fsm_node *fsm_last(struct rb_root *root)
{
	return container_of(rb_last(root), struct fsm_node, node);
}

static inline struct fsm_node *fsm_next(struct fsm_node *node)
{
	return container_of(rb_next(&node->node), struct fsm_node, node);
}

static inline struct fsm_node *fsm_prev(struct fsm_node *node)
{
	return container_of(rb_prev(&node->node), struct fsm_node, node);
}

static inline struct fsm_node *fsm_left(struct fsm_node *node)
{
	return container_of(node->node.rb_left, struct fsm_node, node);
}

static inline struct fsm_node *fsm_right(struct fsm_node *node)
{
	return container_of(node->node.rb_right, struct fsm_node, node);
}

static inline void rb_insert_after(struct rb_node *new,
		struct rb_node *node, struct rb_root *root)
{
	struct rb_node *parent = node;
	struct rb_node **p = &node->rb_right;

	if (*p) {
		parent = rb_next(node);
		if (!parent)
			/* XXX: mayhap return something meaningful? */
			return;
		p = &parent->rb_left;
	}

	rb_link_node(new, parent, p);
	rb_insert_color(new, root);
}

static inline bool
fsm_intersects(struct fsm_node *node, __u64 start, __u32 length)
{
	return (start >= node->start &&
		start < node->start + node->length) ||
	       (start + length > node->start &&
		start + length <= node->start + node->length);
}

static struct fsm_node *fsm_alloc_node(struct vdfs4_fsm_info *fsm)
{
	return kmem_cache_alloc(fsm_node_cachep, GFP_NOFS);
}

static void fsm_free_node(struct fsm_node *node)
{
	kmem_cache_free(fsm_node_cachep, node);
}

static void fsm_init_tree(struct vdfs4_fsm_info *fsm)
{
	int order;

	fsm->free_area_nodes = 0;
	fsm->free_area = RB_ROOT;
	for (order = 0; order <= VDFS4_FSM_MAX_ORDER; order++)
		INIT_LIST_HEAD(fsm->free_list + order);
}

static void fsm_init_next_tree(struct vdfs4_fsm_info *fsm)
{
	fsm->next_free_blocks = 0;
	fsm->next_free_nodes = 0;
	fsm->next_free_area = RB_ROOT;
	INIT_LIST_HEAD(&fsm->next_free_list);
}

static void fsm_free_node_list(struct list_head *list)
{
	struct fsm_node *node, *next;

	list_for_each_entry_safe(node, next, list, list)
		fsm_free_node(node);
}

static void fsm_free_tree(struct vdfs4_fsm_info *fsm)
{
	int order;

	for (order = 0; order <= VDFS4_FSM_MAX_ORDER; order++)
		fsm_free_node_list(fsm->free_list + order);
}

static void fsm_free_next_tree(struct vdfs4_fsm_info *fsm)
{
	fsm_free_node_list(&fsm->next_free_list);
}

/*
 * This returns maximum length of allocation from this position
 */
static inline __u32 fsm_max_length(struct fsm_node *node, __u64 start)
{
	return node->length + (u32)(node->start - start);
}

/*
 * Returns rounded down base 2 order of @length. @length must be non-zero.
 */
static int fsm_order(__u32 length)
{
	return min_t(int, __fls(length), VDFS4_FSM_MAX_ORDER);
}

static void fsm_hash(struct vdfs4_fsm_info *fsm, struct fsm_node *node)
{
	list_add_tail(&node->list, fsm->free_list + fsm_order(node->length));
}

static void fsm_unhash(struct vdfs4_fsm_info *fsm, struct fsm_node *node)
{
	list_del(&node->list);
}

static void fsm_drop(struct vdfs4_fsm_info *fsm, struct fsm_node *node)
{
	rb_erase(&node->node, &fsm->free_area);
	fsm->free_area_nodes--;
	fsm_free_node(node);
}

#ifdef CONFIG_VDFS4_DEBUG

static void fsm_dump_state(struct vdfs4_fsm_info *fsm)
{
	struct fsm_node *node;
	int order, nodes;
	__u64 blocks;

	pr_info("VDFS4(%s): free blocks: %lld reserved: %lld "
		"next free: %lld untracked: %lld+%lld nodes: %u+%u",
		fsm->sbi->sb->s_id,
		fsm->sbi->free_blocks_count,
		fsm->sbi->reserved_blocks_count,
		fsm->next_free_blocks,
		fsm->untracked_blocks,
		fsm->untracked_next_free,
		fsm->free_area_nodes,
		fsm->next_free_nodes);

	for (order = 0; order <= VDFS4_FSM_MAX_ORDER; order++) {
		blocks = 0;
		nodes = 0;

		list_for_each_entry(node, fsm->free_list + order, list) {
			blocks += node->length;
			nodes++;
		}

		if (nodes)
			pr_cont(" %d:%lld/%d", order, blocks, nodes);
	}

	pr_cont("\n");
}

static int fsm_check_node(struct fsm_node *node, struct fsm_node *prev)
{
	if (!node->length) {
		VDFS4_ERR("node->length = 0");
		return -1;
	}
	if (list_empty(&node->list)) {
		VDFS4_ERR("node->list is empty");
		return -1;
	}
	if (prev && prev->start + prev->length >= node->start) {
		VDFS4_ERR("prev->start + prev->length >= node->start."
				"prev->start = %lu, prev->length = %u,"
				"node->start = %lu", (unsigned long int)
				prev->start, (unsigned int)prev->length,
				(unsigned long int)node->start);
		return -1;
	}
	if (prev && fsm_intersects(prev, node->start, node->length)) {
		VDFS4_ERR("fsm_intersects(prev, node->start,"
				" node->length). prev->start - %lu,"
				"prev->length = %u, node->start = %lu,"
				"node->length = %u.", (unsigned long int)
				prev->start,
				(unsigned int)prev->length,
				(unsigned long int)node->start,
				(unsigned int)node->length);
		return -1;
	}
	return 0;
}
/*
 * This verifies consistency of in-memory trees and counters
 */
static void fsm_verify_state(struct vdfs4_fsm_info *fsm)
{
	struct fsm_node *prev, *node;
	long long blocks, free_blocks;
	int order;
	unsigned int nodes;

	free_blocks = fsm->next_free_blocks - fsm->untracked_next_free;

	blocks = 0;
	nodes = 0;
	for (prev = NULL, node = fsm_first(&fsm->next_free_area); node;
			prev = node, node = fsm_next(node)) {
		if (fsm_check_node(node, prev))
			goto dump_state;
		blocks += node->length;
		nodes++;
	}
	if (blocks != free_blocks) {
		VDFS4_ERR("blocks != free_blocks. blocks = %llu,"
				" free_blocks = %llu", blocks, free_blocks);
		goto dump_state;
	}
	if (nodes != fsm->next_free_nodes) {
		VDFS4_ERR("nodes ! = fsm->next_free_nodes; nodes = %u,"
				"fsm->next_free_nodes = %u", nodes,
				fsm->next_free_nodes);
		goto dump_state;
	}

	free_blocks = (long long)(fsm->sbi->free_blocks_count +
		fsm->sbi->reserved_blocks_count) -
		fsm->untracked_blocks;

	blocks = 0;
	nodes = 0;
	for (prev = NULL, node = fsm_first(&fsm->free_area); node;
			prev = node, node = fsm_next(node)) {
		if (fsm_check_node(node, prev))
			goto dump_state;
		blocks += node->length;
		nodes++;
	}

	blocks = 0;
	nodes = 0;
	for (order = 0; order <= VDFS4_FSM_MAX_ORDER; order++) {
		list_for_each_entry(node, fsm->free_list + order, list) {
			if (RB_EMPTY_NODE(&node->node)) {
				VDFS4_ERR("RB_EMPTY_NODE(&node->node)");
				goto dump_state;
			}
			if (fsm_order(node->length) != order) {
				VDFS4_ERR("fsm_order(node->length) != order."
						"fsm_order(node->length) = %d,"
						" order = %d",
						fsm_order(node->length), order);
				goto dump_state;
			}
			blocks += node->length;
			nodes++;
		}
	}
	if (blocks != free_blocks) {
		VDFS4_ERR("blocks != free_blocks. blocks = %llu,"
				" free_blocks = %llu", blocks, free_blocks);
		goto dump_state;
	}
	if (nodes != fsm->free_area_nodes) {
		VDFS4_ERR("nodes ! = fsm->free_area_nodes; nodes = %u,"
				"fsm->free_area_nodes = %u", nodes,
				fsm->free_area_nodes);
		goto dump_state;
	}
	return;
dump_state:
	fsm_dump_state(fsm);
	VDFS4_BUG(fsm->sbi);
}


#else
static inline void fsm_verify_state(struct vdfs4_fsm_info *fsm) { }
#endif

static struct fsm_node *fsm_front_merge(struct fsm_node *node, __u32 length)
{
	struct fsm_node *prev = fsm_prev(node);

	node->start -= length;
	node->length += length;

	if (prev && prev->start + prev->length == node->start) {
		node->start -= prev->length;
		node->length += prev->length;
		return prev;
	}

	return NULL;
}

static struct fsm_node *fsm_back_merge(struct fsm_node *node, __u32 length)
{
	struct fsm_node *next = fsm_next(node);

	node->length += length;

	if (next && node->start + node->length == next->start) {
		node->length += next->length;
		return next;
	}

	return NULL;
}

/*
 * This adds free space into next_free_area tree
 */
static void fsm_add_free_space(struct vdfs4_fsm_info *fsm,
		__u64 start, __u64 length)
{
	struct rb_node **p = &fsm->next_free_area.rb_node;
	struct fsm_node *cur = NULL, *node = NULL, *drop;

	while (*p) {
		cur = container_of(*p, struct fsm_node, node);

		if (fsm_intersects(cur, start, (u32)length)) {
			vdfs4_fatal_error(fsm->sbi, "freeing already free "
					"space: %lld +%lld, %lld +%d",
					start, length, cur->start, cur->length);
			vdfs4_record_err_dump_disk(fsm->sbi,
					VDFS4_DEBUG_ERR_BITMAP_FREE,
					0, 0, "freeing already free", NULL, 0);
			return;
		}

		if (start + length == cur->start) {
			drop = fsm_front_merge(cur, (u32)length);
		} else if (cur->start + cur->length == start) {
			drop = fsm_back_merge(cur, (u32)length);
		} else {
			if (start < cur->start)
				p = &cur->node.rb_left;
			else
				p = &cur->node.rb_right;
			continue;
		}

		fsm->next_free_blocks += (long long)length;
		if (drop) {
			list_del(&drop->list);
			rb_erase(&drop->node, &fsm->next_free_area);
			fsm->next_free_nodes--;
			fsm_free_node(drop);
		}
		return;
	}

	fsm->next_free_blocks += (long long)length;

	node = fsm_alloc_node(fsm);
	if (!node) {
		fsm->untracked_next_free += (long long)length;
		return;
	}

	node->start = start;
	node->length = (u32)length;
	rb_link_node(&node->node, &cur->node, p);
	rb_insert_color(&node->node, &fsm->next_free_area);
	list_add_tail(&node->list, &fsm->next_free_list);
	fsm->next_free_nodes++;
}

/*
 * This is used for building tree from bitmap. It builds tree left to right,
 * this way next node is always right child of the @last node.
 */
static struct fsm_node *
fsm_append_free_space(struct vdfs4_fsm_info *fsm, struct fsm_node *last,
			__u64 start, __u64 length)
{
	struct fsm_node *node = NULL;

	fsm->sbi->free_blocks_count += length;

	if (last && last->start + last->length == start) {
		last->length += (u32)length;
		return last;
	}

	if (fsm->free_area_nodes < VDFS4_FSM_MAX_FREE_NODES)
		node = fsm_alloc_node(fsm);

	if (!node) {
		fsm->untracked_blocks += (long long)length;
		return last;
	}

	node->start = start;
	node->length = (u32)length;
	if (last) {
		fsm_hash(fsm, last);
		rb_link_node(&node->node, &last->node, &last->node.rb_right);
	} else
		rb_link_node(&node->node, NULL, &fsm->free_area.rb_node);
	rb_insert_color(&node->node, &fsm->free_area);
	fsm->free_area_nodes++;

	return node;
}

static int fsm_discard_free_space(struct vdfs4_fsm_info *fsm,
				  struct fsm_node *cur)
{
	int rtn;
	unsigned int i;
	__u64 total_size = fsm->sbi->volume_blocks_count * fsm->sbi->block_size;

	for (i = 0; i < cur->length; i++) {
		__u64 index = cur->start + i;
		__u64 erase_block_num = index
			>> fsm->sbi->log_erase_block_size_in_blocks;

		if (!--fsm->sbi->erase_blocks_counters[erase_block_num]) {
			u64 erase_blk_size_in_sector = 1llu <<
				(fsm->sbi->log_erase_block_size
				 - SECTOR_SIZE_SHIFT);
			u64 last_block = ((erase_block_num <<
					   fsm->sbi->log_erase_block_size)
					  + fsm->sbi->erase_block_size);

			if (last_block > total_size)
				continue;

			rtn = blkdev_issue_discard(fsm->sbi->sb->s_bdev,
				   erase_block_num * erase_blk_size_in_sector,
				   erase_blk_size_in_sector, GFP_NOFS, 0);

			VDFS4_INFO("discard %s : %d %llu %llu\n",
				   fsm->sbi->sb->s_id, rtn,
				   erase_block_num, erase_blk_size_in_sector);

			if (rtn && rtn != -EOPNOTSUPP) {
				VDFS4_ERR("discard %s : %d %llu %llu",
					  fsm->sbi->sb->s_id, rtn,
					  erase_block_num,
					  erase_blk_size_in_sector);
				VDFS4_BUG(fsm->sbi);
			}
		}
	}
	return rtn;
}

/*
 * This moves free space extents from next_free_area to free_area.
 */
static void fsm_commit_free_space(struct vdfs4_fsm_info *fsm)
{
	struct fsm_node *node, *next, *drop;

	fsm_verify_state(fsm);

	list_for_each_entry_safe(node, next, &fsm->next_free_list, list) {
		struct rb_node **p = &fsm->free_area.rb_node;
		struct fsm_node *cur = NULL;

		fsm->sbi->free_blocks_count += node->length;

		fsm_discard_free_space(fsm, node);

		while (*p) {
			cur = container_of(*p, struct fsm_node, node);
			if (fsm_intersects(cur, node->start, node->length)) {
				vdfs4_fatal_error(fsm->sbi,
						"freeing already free "
						"space: %lld +%d, %lld +%d",
						node->start, node->length,
						cur->start, cur->length);
				vdfs4_record_err_dump_disk(fsm->sbi, VDFS4_DEBUG_ERR_BITMAP_FREE,
						0, 0, "freeing already free", NULL, 0);

				fsm->sbi->free_blocks_count -= node->length;
				fsm->untracked_blocks += node->length;
				fsm_free_node(node);
				goto next;
			}

			if (node->start + node->length == cur->start) {
				fsm_unhash(fsm, cur);
				drop = fsm_front_merge(cur, node->length);
				if (drop) {
					fsm_unhash(fsm, drop);
					fsm_drop(fsm, drop);
				}
				fsm_hash(fsm, cur);
				fsm_free_node(node);
				goto next;
			}

			if (cur->start + cur->length == node->start) {
				fsm_unhash(fsm, cur);
				drop = fsm_back_merge(cur, node->length);
				if (drop) {
					fsm_unhash(fsm, drop);
					fsm_drop(fsm, drop);
				}
				fsm_hash(fsm, cur);
				fsm_free_node(node);
				goto next;
			}

			if (node->start < cur->start)
				p = &cur->node.rb_left;
			else
				p = &cur->node.rb_right;
		}

		if (fsm->free_area_nodes < VDFS4_FSM_MAX_FREE_NODES) {
			rb_link_node(&node->node, &cur->node, p);
			rb_insert_color(&node->node, &fsm->free_area);
			fsm->free_area_nodes++;
			fsm_hash(fsm, node);
		} else {
			fsm->untracked_blocks += node->length;
			fsm_free_node(node);
		}

next:;
	}

	/*
	 * After metadata commit all newly freed blocks might be reused.
	 */
	if (fsm->untracked_next_free) {
		fsm->sbi->free_blocks_count += (unsigned long long)
				fsm->untracked_next_free;
		fsm->untracked_blocks += fsm->untracked_next_free;
		fsm->untracked_next_free = 0;
	}

	fsm_init_next_tree(fsm);
	fsm_verify_state(fsm);
}

void vdfs4_commit_free_space(struct vdfs4_sb_info *sbi)
{
	struct vdfs4_fsm_info *fsm = sbi->fsm_info;

	mutex_lock(&fsm->lock);
	fsm_commit_free_space(fsm);
	mutex_unlock(&fsm->lock);
}

static void fsm_rebuild_tree(struct vdfs4_fsm_info *fsm);

static struct fsm_node *
fsm_find_node(struct vdfs4_fsm_info *fsm, __u64 start)
{
	struct fsm_node *node;

	node = container_of(fsm->free_area.rb_node, struct fsm_node, node);
	while (node) {
		if (start >= node->start &&
		    start <  node->start + node->length)
			break;

		if (start < node->start)
			node = fsm_left(node);
		else
			node = fsm_right(node);
	}

	return node;
}

static struct fsm_node *
fsm_choose_node(struct vdfs4_fsm_info *fsm, __u32 length)
{
	int order = fsm_order(length);

	while (list_empty(fsm->free_list + order) && order
			< VDFS4_FSM_MAX_ORDER)
		order++;

	while (list_empty(fsm->free_list + order) && order > 0)
		order--;

	if (list_empty(fsm->free_list + order))
		return NULL;

	return list_first_entry(fsm->free_list + order, struct fsm_node, list);
}

/*
 * This allocates extent from given node starting from given position.
 */
static void fsm_allocate_from_node(struct vdfs4_fsm_info *fsm,
		struct fsm_node *node, __u64 start, __u32 length)
{
	__u32 max_length = fsm_max_length(node, start);

	/* allocation must be inside */
	VDFS4_BUG_ON(start < node->start ||
	       start >= node->start + node->length ||
	       length > max_length, fsm->sbi);

	fsm_unhash(fsm, node);

	if (length == max_length) {
		node->length -= length;
	} else if (start == node->start) {
		node->start += length;
		node->length -= length;
	} else {
		struct fsm_node *tail = NULL;

		if (fsm->free_area_nodes < VDFS4_FSM_MAX_FREE_NODES)
			tail = fsm_alloc_node(fsm);

		if (!tail) {
			fsm->untracked_blocks += max_length - length;
		} else {
			tail->start = start + length;
			tail->length = max_length - length;
			rb_insert_after(&tail->node,
					&node->node, &fsm->free_area);
			fsm->free_area_nodes++;
			fsm_hash(fsm, tail);
		}

		node->length -= max_length;
	}

	if (node->length)
		fsm_hash(fsm, node);
	else
		fsm_drop(fsm, node);
}

static struct fsm_node *
fsm_get_longest_node(struct vdfs4_fsm_info *fsm)
{
	struct fsm_node *prev, *node;
	struct fsm_node *return_node;

	for (prev = NULL, node = fsm_first(&fsm->free_area),
			return_node = node; node;
			prev = node, node = fsm_next(node)) {
		if (node->length > return_node->length)
			return_node = node;
	}
	return return_node;
}

static __u64 fsm_allocate_space(struct vdfs4_fsm_info *fsm,
		__u32 start, __u32 min_length, __u32 *length)
{
	bool try_rebuild = true;
	struct fsm_node *node;
	__u32 max_length;

again:
	if (start) {
		node = fsm_find_node(fsm, start);
		if (node) {
			max_length = fsm_max_length(node, start);
			if (max_length >= min_length)
				goto allocate;
		}
	}

	node = fsm_choose_node(fsm, *length);
	if (!node)
		goto nospace;

	max_length = node->length;
	if (max_length < min_length)
		goto nospace;

	start = (u32)node->start;
allocate:
	*length = min(*length, max_length);
	fsm_allocate_from_node(fsm, node, start, *length);
	return start;

nospace:
	if (fsm->untracked_blocks && try_rebuild) {
		fsm_rebuild_tree(fsm);
		try_rebuild = false;
		goto again;
	}
	fsm_verify_state(fsm);
	return 0;
}

/**
 * @brief			Get free space block chunk from tree
 *					and update free space manager bitmap.
 * @param [in]	inode_info		The inode information structure.
 * @param [in]	block_offset		Desired physical number of first block
 *					of block chunk.
 * @param [in]	length_in_blocks	Blocks count.
 * @param [in]	da			delya allocation flag. if it is 1, don't
 *					change the free space value
 *
 * @return				Returns physical number of first block
 *					of block chunk (may differs from
 *					block_offset parameter if desired block
 *					already used by file system), 0 if
 *					function fails (no free space).
 */
__u64 vdfs4_fsm_get_free_block(struct vdfs4_sb_info *sbi,
		__u64 block_offset, __u32 *length_in_blocks,
		unsigned int min_blk_count, int fsm_flags)
{
	struct vdfs4_fsm_info *fsm = sbi->fsm_info;
	__u64 start_page = 0, end_page = 0, index;

	if ((block_offset + *length_in_blocks) >= sbi->volume_blocks_count)
		block_offset = 0;

	mutex_lock(&fsm->lock);
	/* check free space only if it's not delay allocation case.
	 * for delay allocation case, this check is made in write_begin
	 * function. */
	if ((*length_in_blocks > sbi->free_blocks_count) &&
		!(fsm_flags & VDFS4_FSM_ALLOC_DELAYED)) {
		block_offset = 0;
		goto exit;
	}

	if (fsm_flags & VDFS4_FSM_ALLOC_ALIGNED) {
		/* align metadata to superpage size */
		__u32 blocks_per_superpage = 1U << (sbi->log_super_page_size -
				sbi->log_block_size);
		__u32 optimal_length = *length_in_blocks + blocks_per_superpage;
		__u32 minimal_length = min_blk_count + blocks_per_superpage;
		__u32 length = optimal_length;

		VDFS4_BUG_ON(*length_in_blocks & (blocks_per_superpage - 1), sbi);

		/* try to allocate length desired by caller first */
		block_offset = fsm_allocate_space(fsm, (u32)block_offset,
						  length, &length);
		if (!block_offset) {
			struct fsm_node *longest_node;

			/* Space is so fragmented that our attempt
			failed. Find longest possible free chunk and
			try to get as much as possible from it */
			longest_node = fsm_get_longest_node(fsm);
			if (!longest_node)
				goto exit;

			length = round_down(longest_node->length, blocks_per_superpage);
			if (length > optimal_length)
				length = optimal_length;

			/* found chunk size must be at least of minimal
			length acceptable for caller (min_blk_count).
			Usually it will be much longer than minimum */
			if (length < minimal_length + blocks_per_superpage)
				goto exit;

			block_offset = longest_node->start;
			fsm_allocate_from_node(fsm, longest_node, block_offset, length);
			/* neccessary to align physical block num */
			*length_in_blocks = length - blocks_per_superpage;
		}

		VDFS4_BUG_ON((length < minimal_length) ||
				(length > optimal_length), sbi);
		fsm->untracked_blocks += blocks_per_superpage;
		block_offset = ALIGN(block_offset, blocks_per_superpage);
	} else {
		block_offset = fsm_allocate_space(fsm, (u32)block_offset,
				1U, length_in_blocks);
	}

	if (block_offset) {
		int ret = 0;
		start_page = block_offset;
		end_page = block_offset + *length_in_blocks;

		/* calculate start block */
		do_div(start_page, VDFS4_BIT_BLKSIZE(sbi->block_size,
				FSM_BMP_MAGIC_LEN));
		/* calculate end block */
		do_div(end_page, VDFS4_BIT_BLKSIZE(sbi->block_size,
				FSM_BMP_MAGIC_LEN));
		/* index of start page */
		start_page = (unsigned int)start_page >>
				(PAGE_SHIFT - sbi->block_size_shift);

		end_page = (unsigned int)end_page >>
				(PAGE_SHIFT - sbi->block_size_shift);

		if (fsm_flags & VDFS4_FSM_ALLOC_DELAYED)
			fsm->sbi->reserved_blocks_count -= *length_in_blocks;
		else
			fsm->sbi->free_blocks_count -= *length_in_blocks;

		VDFS4_BUG_ON(block_offset + *length_in_blocks >
					(fsm->sbi->volume_blocks_count), sbi);

		ret = vdfs4_set_bits(fsm->data, (int)(fsm->page_count *
			PAGE_SIZE), (unsigned int)block_offset,
			*length_in_blocks, FSM_BMP_MAGIC_LEN, sbi->block_size);
		if (ret != 0) {
			destroy_layout(sbi);
			VDFS4_BUG_ON(1, sbi);
		}
		for (index = 0; index < *length_in_blocks; index++) {
			int erase_block_num = (int)((block_offset + index) >>
				sbi->log_erase_block_size_in_blocks);
			sbi->erase_blocks_counters[erase_block_num]++;
			VDFS4_BUG_ON(sbi->erase_blocks_counters[erase_block_num] >
				sbi->erase_block_size_in_blocks, sbi);
		}
	}
exit:
	mutex_unlock(&fsm->lock);
	if (block_offset)
		for (index = start_page; index <= end_page; index++)
			vdfs4_add_chunk_bitmap(sbi, fsm->pages[index],
					fsm_flags);

	return block_offset;
}

/**
 * @brief				Free block chunk (put free space chunk
 *					to tree and update free space manager
 *					bitmap.
 * @param [in]	fsm			FSM information structure.
 * @param [in]	block_offset		Physical number of first block of
 *					block chunk.
 * @param [in]	length_in_blocks	Blocks count.
 * @return	void
 */
static int fsm_free_block_chunk(struct vdfs4_fsm_info *fsm,
	__u64 block_offset, __u32 length_in_blocks, int fsm_flags)
{
	int err = 0;
	unsigned int i;
	__u64 start_page = block_offset;
	__u64 end_page	= block_offset + length_in_blocks, page_index;
	__u64 total_size = fsm->sbi->volume_blocks_count * fsm->sbi->block_size;
	/* calculate start block */
	do_div(start_page, VDFS4_BIT_BLKSIZE(fsm->sbi->block_size,
			FSM_BMP_MAGIC_LEN));
	/* calculate end block */
	do_div(end_page, VDFS4_BIT_BLKSIZE(fsm->sbi->block_size,
			FSM_BMP_MAGIC_LEN));
	/* index of start page */
	start_page = (unsigned int)start_page >>
			(PAGE_SHIFT - fsm->sbi->block_size_shift);
	/* index of end page */
	end_page = (unsigned int)end_page >>
			(PAGE_SHIFT - fsm->sbi->block_size_shift);


	mutex_lock(&fsm->lock);

	/* check boundary */
	if (block_offset + length_in_blocks > (fsm->sbi->volume_blocks_count)) {
		if (!is_sbi_flag_set(fsm->sbi, IS_MOUNT_FINISHED)) {
			mutex_unlock(&fsm->lock);
			return err;
		}
		VDFS4_ERR("[boundary check] offset:%lld, length:%u, count:%llu\n",
				block_offset, length_in_blocks,
				fsm->sbi->volume_blocks_count);
		VDFS4_BUG(fsm->sbi);
	}
	/* clear bits */
	err = (int)vdfs4_clear_bits(fsm->data, (int)
			(fsm->page_count * PAGE_SIZE),
			(unsigned int)block_offset,
			length_in_blocks, FSM_BMP_MAGIC_LEN,
			fsm->sbi->block_size);
	if (err) {
		if (!is_sbi_flag_set(fsm->sbi, IS_MOUNT_FINISHED)) {
			mutex_unlock(&fsm->lock);
			return err;
		}

		destroy_layout(fsm->sbi);
		VDFS4_BUG(fsm->sbi);
	}

	/* return failed delayed-allocation back to reserve */
	if (fsm_flags & VDFS4_FSM_FREE_RESERVE)
		fsm->sbi->reserved_blocks_count += length_in_blocks;
	else if (fsm_flags & VDFS4_FSM_FREE_UNUSED)
		fsm->sbi->free_blocks_count += length_in_blocks;

	/* release unused allocations in current transaction */
	if (fsm_flags & VDFS4_FSM_FREE_UNUSED)
		fsm->untracked_blocks += length_in_blocks;
	else
		fsm_add_free_space(fsm, block_offset, length_in_blocks);

	mutex_unlock(&fsm->lock);
	for (page_index = start_page; page_index <= end_page; page_index++)
		vdfs4_add_chunk_bitmap(fsm->sbi, fsm->pages[page_index], 1);

	return 0;
}

/**
 * @brief				The fsm_free_block_chunk wrapper. This
 *					function is called during truncate or
 *					unlink inode processes.
 * @param [in]	sbi			Superblock information structure.
 * @param [in]	block_offset		Physical number of first block of
 *					inserted chunk
 * @param [in]	length_in_blocks	Inserted blocks count.
 * @param [in]	fsm_flags		VDFS4_FSM_FREE_*
 * @return	error code
 */
int vdfs4_fsm_put_free_block(struct vdfs4_inode_info *inode_info,
		__u64 offset, __u32 length_in_blocks, int fsm_flags)
{
	int ret;
	struct vdfs4_sb_info *sbi = VDFS4_SB(inode_info->vfs_inode.i_sb);

	ret = fsm_free_block_chunk(sbi->fsm_info, offset,
				   length_in_blocks, fsm_flags);

	return ret;
}

/**
 * @brief			Puts back to tree preallocated blocks.
 * @param [in]	inode_info	The inode information structure.
 * @return			Returns 0 on success, -1 on failure.
 */
void vdfs4_fsm_discard_preallocation(struct vdfs4_inode_info *inode_info)
{
	struct vdfs4_sb_info *sbi = inode_info->vfs_inode.i_sb->s_fs_info;
	struct vdfs4_fork_info *fork = &inode_info->fork;

	mutex_lock(&sbi->fsm_info->lock);
	if (fork->prealloc_start_block && fork->prealloc_block_count) {
		fsm_add_free_space(sbi->fsm_info, fork->prealloc_start_block,
				fork->prealloc_block_count);
		fork->prealloc_block_count = 0;
		fork->prealloc_start_block = 0;
	}
	mutex_unlock(&sbi->fsm_info->lock);
}

/**
 * @brief			Build free space management tree from
 *				on-disk bitmap.
 * @param [in,out]	fsm	Free space manager information structure.
 * @return			Returns error code.
 */
static void fsm_build_tree(struct vdfs4_fsm_info *fsm)
{
	struct vdfs4_sb_info *sbi = fsm->sbi;
	__u64 bits_count = sbi->volume_blocks_count;
	__u64 block_start = 0, free_start = 0, data_start = 0, bit;
	void *block = (char *)fsm->data + FSM_BMP_MAGIC_LEN;
	unsigned int block_size = 8 * (sbi->block_size -
			(FSM_BMP_MAGIC_LEN + CRC32_SIZE));
	struct fsm_node *last = NULL;

	memset(sbi->erase_blocks_counters, 0,
			sizeof(u32) * sbi->nr_erase_blocks_counters);

	while (block_start < bits_count) {

		/* cut size of last bitmap block */
		block_size = min_t(__u64, block_size, bits_count - block_start);

		free_start = block_start + find_next_zero_bit(block,
				block_size,
				(data_start - block_start));

		/* count erase blocks */
		for (bit = data_start; bit < free_start;) {
			__u64 leb = bit >> sbi->log_erase_block_size_in_blocks;
			__u64 len = min(free_start, (leb + 1) <<
				sbi->log_erase_block_size_in_blocks) - bit;

			sbi->erase_blocks_counters[leb] += (u32)len;
			VDFS4_BUG_ON(sbi->erase_blocks_counters[leb] >
					sbi->erase_block_size_in_blocks, sbi);
			bit += len;
		}

		data_start = block_start + find_next_bit(block, block_size,
					(free_start - block_start));

		/* switch to next bitmap block */
		if (data_start == block_start + block_size) {
			block_start += block_size;
			block = (char *)block + sbi->block_size;
		}

		if (free_start < data_start)
			last = fsm_append_free_space(fsm, last,
					free_start, data_start - free_start);
	}

	if (last)
		fsm_hash(fsm, last);
}

/*
 * This removes not-yet-freed extents from rebuilded tree
 */
static void fsm_cut_next_free(struct vdfs4_fsm_info *fsm)
{
	struct fsm_node *node, *next;

	list_for_each_entry(next, &fsm->next_free_list, list) {
		node = fsm_find_node(fsm, next->start);
		if (!node) {
			/* it might absent only if something off a tree */
			VDFS4_BUG_ON(fsm->untracked_blocks < next->length, fsm->sbi);
			fsm->untracked_blocks -= next->length;
			continue;
		}

		/* otherwise whole extent must be in the tree */
		VDFS4_BUG_ON(fsm_max_length(node, next->start) <
				next->length, fsm->sbi);
		fsm_allocate_from_node(fsm, node, next->start, next->length);
	}
}

/*
 * This rebuilds tree from bitmap
 */
static void fsm_rebuild_tree(struct vdfs4_fsm_info *fsm)
{
	/*
	 * Without completely tracked next-free it's impossible to rebuild
	 * tree safely. Please come again after metadata commit.
	 *
	 * Update: currently we cannot decline request here. Space might be
	 * already reserved by delayed allocation. To release space and
	 * commit transaction we must commit transaction. Oops.
	 */
	if (fsm->untracked_next_free) {
		if (!fsm->sbi->reserved_blocks_count)
			return;
		/* Forget about some of unlinked data. what data? */
		fsm->next_free_blocks -= fsm->untracked_next_free;
		fsm->untracked_next_free = 0;
	}

	fsm_free_tree(fsm);
	fsm_init_tree(fsm);
	fsm->untracked_blocks = 0;
	fsm->sbi->free_blocks_count = 0;
	fsm_build_tree(fsm);
	fsm->sbi->free_blocks_count -=
			(unsigned long long)fsm->next_free_blocks;
	fsm->sbi->free_blocks_count -= fsm->sbi->reserved_blocks_count;
	fsm_cut_next_free(fsm);
	fsm_verify_state(fsm);
}

int vdfs4_fsm_cache_init(void)
{
	fsm_node_cachep = kmem_cache_create("vdfs4_fsm_node",
			sizeof(struct fsm_node), 0, 0, NULL);
	if (!fsm_node_cachep)
		return -ENOMEM;
	return 0;
}

void vdfs4_fsm_cache_destroy(void)
{
	kmem_cache_destroy(fsm_node_cachep);
}

/**
 * @brief			Build free space management.
 * @param [in,out]	sb	The VFS superblock
 * @return			Returns 0 on success, -errno on failure.
 */
int vdfs4_fsm_build_management(struct super_block *sb)
{
	struct vdfs4_fsm_info *fsm;
	struct vdfs4_sb_info *sbi = sb->s_fs_info;
	struct vdfs4_layout_sb *l_sb = sbi->raw_superblock;
	int err = 0;
	unsigned int page_index = 0;
	__u64 page_count;
	u64 total_size = sbi->volume_blocks_count * sbi->block_size;

	if (sbi->log_erase_block_size == 0) {
		VDFS4_ERR("wrong erase block size");
		return -EINVAL;
	}

	sbi->nr_erase_blocks_counters =
		(u32)(total_size >> sbi->log_erase_block_size) + 1;
	sbi->erase_blocks_counters = kzalloc(sizeof(u32) *
			sbi->nr_erase_blocks_counters, GFP_NOFS);
	if (!sbi->erase_blocks_counters)
		return -ENOMEM;

	fsm = kzalloc(sizeof(struct vdfs4_fsm_info), GFP_NOFS);
	if (!fsm)
		return -ENOMEM;

	page_count = DIV_ROUND_UP_ULL(sbi->volume_blocks_count,
		(unsigned int)((PAGE_SIZE - FSM_BMP_MAGIC_LEN -
				CRC32_SIZE) * 8));


	fsm->page_count = (__u32)page_count;
	sbi->fsm_info = fsm;
	fsm->sbi = sbi;

	fsm->free_space_start = (u32)le64_to_cpu(l_sb->exsb.volume_body.begin);
	mutex_init(&fsm->lock);

	fsm->pages = kzalloc(sizeof(*fsm->pages) * fsm->page_count, GFP_NOFS);

	if (!fsm->pages) {
		err = -ENOMEM;
		goto fail;
	}
	for (page_index = 0; page_index < fsm->page_count ; page_index++)
		fsm->pages[page_index] = ERR_PTR(-EIO);

	fsm->bitmap_inode = vdfs4_special_iget(sb, VDFS4_SPACE_BITMAP_INO);

	if (IS_ERR(fsm->bitmap_inode)) {
		err = PTR_ERR(fsm->bitmap_inode);
		goto fail;
	}

	err = vdfs4_read_or_create_pages(fsm->bitmap_inode, 0,
			fsm->page_count, fsm->pages, VDFS4_META_READ, 0, 0);
	if (err)
		goto fail_no_release;

	fsm->data = vdfs4_vmap(fsm->pages, fsm->page_count,
					VM_MAP, PAGE_KERNEL);

	if (!fsm->data) {
		VDFS4_ERR("can't map pages\n");
		err = -ENOMEM;
		goto fail;
	}

	fsm_init_tree(fsm);
	fsm_init_next_tree(fsm);
	fsm_build_tree(fsm);
	fsm_verify_state(fsm);

	return 0;

fail:
	if (fsm->pages) {
		for (page_index = 0; page_index < fsm->page_count; page_index++)
			if (!IS_ERR(fsm->pages[page_index]))
				page_cache_release(fsm->pages[page_index]);
fail_no_release:
		kfree(fsm->pages);
	}
	if (fsm->bitmap_inode)
		iput(fsm->bitmap_inode);
	kfree(fsm);
	kfree(sbi->erase_blocks_counters);
	sbi->fsm_info = NULL;
	return err;
}

/**
 * @brief			Destroy free space management.
 * @param [in,out]	sb	The VFS superblock.
 * @return		void
 */
void vdfs4_fsm_destroy_management(struct super_block *sb)
{
	struct vdfs4_sb_info *sbi = sb->s_fs_info;
	struct vdfs4_fsm_info *fsm = sbi->fsm_info;
	unsigned int page_index = 0;

	VDFS4_BUG_ON(!fsm->data || !fsm->pages, sbi);

	fsm_verify_state(fsm);
	fsm_free_tree(fsm);
	fsm_free_next_tree(fsm);

	vunmap((void *)fsm->data);
	for (page_index = 0; page_index < fsm->page_count; page_index++)
		page_cache_release(fsm->pages[page_index]);

	iput(fsm->bitmap_inode);

	kfree(sbi->fsm_info->pages);
	kfree(sbi->fsm_info);
	kfree(sbi->erase_blocks_counters);
	sbi->fsm_info = NULL;
	sbi->free_blocks_count = 0;
}
