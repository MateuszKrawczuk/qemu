/*
 * Accelerator CPUS Interface
 *
 * Copyright 2020 SUSE LLC
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef AEHD_CPUS_H
#define AEHD_CPUS_H

#include "sysemu/cpus.h"

int aehd_init_vcpu(CPUState *cpu);
int aehd_cpu_exec(CPUState *cpu);
void aehd_destroy_vcpu(CPUState *cpu);
void aehd_cpu_synchronize_post_reset(CPUState *cpu);
void aehd_cpu_synchronize_post_init(CPUState *cpu);
void aehd_cpu_synchronize_pre_loadvm(CPUState *cpu);

#endif /* AEHD_CPUS_H */
