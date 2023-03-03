/*
 * QEMU AEHD support
 *
 * Copyright IBM, Corp. 2008
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * Copyright (c) 2017 Intel Corporation
 *  Written by:
 *  Haitao Shan <hshan@google.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_AEHD_I386_H
#define QEMU_AEHD_I386_H

#include "sysemu/aehd.h"

void aehd_arch_reset_vcpu(X86CPU *cs);
void aehd_arch_do_init_vcpu(X86CPU *cs);

#endif /*QEMU_AEHD_I386_H */
