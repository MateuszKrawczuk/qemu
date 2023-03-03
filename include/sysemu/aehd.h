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

#include "qemu/queue.h"
#include "qemu/accel.h"
#include "hw/core/cpu.h"
#include "exec/memattrs.h"
#include "hw/irq.h"

#ifdef NEED_CPU_H
# ifdef CONFIG_AEHD
#  define CONFIG_AEHD_IS_POSSIBLE
# endif
#else
# define CONFIG_AEHD_IS_POSSIBLE
#endif

#define aehd_enabled()           (0)

struct aehd_run;
struct aehd_lapic_state;
struct aehd_irq_routing_entry;

struct AEHDState;

#define TYPE_AEHD_ACCEL ACCEL_CLASS_NAME("aehd")
typedef struct AEHDState AEHDState;
DECLARE_INSTANCE_CHECKER(AEHDState, AEHD_STATE,
                         TYPE_AEHD_ACCEL)

extern AEHDState *aehd_state;

#ifdef NEED_CPU_H
#include "cpu.h"

/* internal API */

int aehd_ioctl(AEHDState *s, int type, void *input, size_t input_size,
               void *output, size_t output_size);
int aehd_vm_ioctl(AEHDState *s, int type, void *input, size_t input_size,
                  void *output, size_t output_size);
int aehd_vcpu_ioctl(CPUState *cpu, int type, void *input, size_t input_size,
                    void *output, size_t output_size);

/* Arch specific hooks */

/* Notify arch about newly added MSI routes */
int aehd_arch_add_msi_route_post(struct aehd_irq_routing_entry *route,
                                 int vector, PCIDevice *dev);
/* Notify arch about released MSI routes */
int aehd_arch_release_virq_post(int virq);

int aehd_set_irq(AEHDState *s, int irq, int level);
int aehd_irqchip_send_msi(AEHDState *s, MSIMessage msg);

void aehd_put_apic_state(DeviceState *d, struct aehd_lapic_state *kapic);
void aehd_get_apic_state(DeviceState *d, struct aehd_lapic_state *kapic);

#endif /* NEED_CPU_H */

void aehd_irqchip_commit_routes(AEHDState *s);
void aehd_irqchip_release_virq(AEHDState *s, int virq);

#endif
