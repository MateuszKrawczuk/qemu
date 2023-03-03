/*
 * QEMU AEHD x86 specific function stubs
 *
 * Copyright Linaro Limited 2012
 *
 * Author: Peter Maydell <peter.maydell@linaro.org>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "aehd_i386.h"

#ifndef __OPTIMIZE__
uint32_t aehd_arch_get_supported_cpuid(AEHDState *env, uint32_t function,
                                       uint32_t index, int reg)
{
    abort();
}
#endif
