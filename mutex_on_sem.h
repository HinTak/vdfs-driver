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

#ifndef MUTEX_ON_SEM_H_
#define MUTEX_ON_SEM_H_

#define RW_MUTEX
#ifdef RW_MUTEX
#include <linux/rwsem.h>

#define rw_mutex_t struct rw_semaphore

/**
 * @brief		Locks mutex for reading.
 * @param [in]	mutex	Mutex that will be locked.
 * @return	void
 */
#define mutex_r_lock(mutex) down_read(&mutex)

#define mutex_r_lock_nested(mutex, class) down_read_nested(&mutex, class)

/**
 * @brief		Locks mutex for writing.
 * @param [in]	mutex	Mutex that will be locked.
 * @return	void
 */
#define mutex_w_lock(mutex) down_write(&mutex)

#define mutex_w_lock_nested(mutex, class) down_write_nested(&mutex, class)

/**
 * @brief		Unlocks mutex for reading.
 * @param [in]	mutex	Mutex that will be unlocked.
 * @return	void
 */
#define mutex_r_unlock(mutex) up_read(&mutex)

/**
 * @brief		Unlocks mutex for writing.
 * @param [in]	mutex	Mutex that will be unlocked.
 * @return	void
 */
#define mutex_w_unlock(mutex) up_write(&mutex)

/**
 * @brief		Inits mutex.
 * @param [in]	mutex	Mutex that will be inited.
 * @return	void
 */
#define init_mutex(mutex) init_rwsem(&mutex)

#else

#include <linux/mutex.h>
#define rw_mutex_t struct mutex

/**
 * @brief		Locks mutex for reading.
 * @param [in]	mutex	Mutex that will be locked.
 * @return	void
 */
#define mutex_r_lock(mutex) mutex_lock(&mutex)

/**
 * @brief		Locks mutex for writing.
 * @param [in]	mutex	Mutex that will be locked.
 * @return	void
 */
#define mutex_w_lock(mutex) mutex_lock(&mutex)

/**
 * @brief		Unlocks mutex for reading.
 * @param [in]	mutex	Mutex that will be unlocked.
 * @return	void
 */
#define mutex_r_unlock(mutex) mutex_unlock(&mutex)

/**
 * @brief		Unlocks mutex for writing.
 * @param [in]	mutex	Mutex that will be unlocked.
 * @return	void
 */
#define mutex_w_unlock(mutex) mutex_unlock(&mutex)

/**
 * @brief		Inits mutex.
 * @param [in]	mutex	Mutex that will be inited.
 * @return	void
 */
#define init_mutex(mutex) mutex_init(&mutex)
#endif

#endif /* MUTEX_ON_SEM_H_ */
