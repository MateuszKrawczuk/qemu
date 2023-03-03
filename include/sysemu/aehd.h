/*
 * QEMU AEHD support
 *
 * Copyright IBM, Corp. 2008
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_AEHD_H
#define QEMU_AEHD_H

#ifdef NEED_CPU_H
# ifdef CONFIG_AEHD
#  define CONFIG_AEHD_IS_POSSIBLE
# endif
#else
# define CONFIG_AEHD_IS_POSSIBLE
#endif

#define aehd_enabled()           (0)
