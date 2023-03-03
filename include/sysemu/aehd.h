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

#ifdef CONFIG_AEHD_IS_POSSIBLE

extern bool aehd_allowed;
#define aehd_enabled()           (aehd_allowed)

#else /* !CONFIG_AEHD_IS_POSSIBLE */

#define aehd_enabled()           (0)

#endif /* !CONFIG_AEHD_IS_POSSIBLE */

struct aehd_run;
struct aehd_lapic_state;
struct aehd_irq_routing_entry;

struct AEHDState;

#define TYPE_AEHD_ACCEL ACCEL_CLASS_NAME("aehd")
typedef struct AEHDState AEHDState;
DECLARE_INSTANCE_CHECKER(AEHDState, AEHD_STATE,
                         TYPE_AEHD_ACCEL)

extern AEHDState *aehd_state;

/* external API */
bool aehd_has_free_slot(MachineState *ms);

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

void aehd_arch_pre_run(CPUState *cpu, struct aehd_run *run);
MemTxAttrs aehd_arch_post_run(CPUState *cpu, struct aehd_run *run);

int aehd_arch_handle_exit(CPUState *cpu, struct aehd_run *run);

int aehd_arch_handle_ioapic_eoi(CPUState *cpu, struct aehd_run *run);

int aehd_arch_process_async_events(CPUState *cpu);

int aehd_arch_get_registers(CPUState *cpu);

/* state subset only touched by the VCPU itself during runtime */
#define AEHD_PUT_RUNTIME_STATE   1
/* state subset modified during VCPU reset */
#define AEHD_PUT_RESET_STATE     2
/* full state set, modified during initialization or on vmload */
#define AEHD_PUT_FULL_STATE      3

int aehd_arch_put_registers(CPUState *cpu, int level);

int aehd_arch_init(MachineState *ms, AEHDState *s);

int aehd_arch_init_vcpu(CPUState *cpu);

bool aehd_vcpu_id_is_valid(int vcpu_id);

/* Returns VCPU ID to be used on AEHD_CREATE_VCPU ioctl() */
unsigned long aehd_arch_vcpu_id(CPUState *cpu);

void aehd_arch_init_irq_routing(AEHDState *s);

int aehd_arch_fixup_msi_route(struct aehd_irq_routing_entry *route,
                              uint64_t address, uint32_t data, PCIDevice *dev);

/* Notify arch about newly added MSI routes */
int aehd_arch_add_msi_route_post(struct aehd_irq_routing_entry *route,
                                 int vector, PCIDevice *dev);
/* Notify arch about released MSI routes */
int aehd_arch_release_virq_post(int virq);

int aehd_set_irq(AEHDState *s, int irq, int level);
int aehd_irqchip_send_msi(AEHDState *s, MSIMessage msg);

void aehd_irqchip_add_irq_route(AEHDState *s, int gsi, int irqchip, int pin);

void aehd_put_apic_state(DeviceState *d, struct aehd_lapic_state *kapic);
void aehd_get_apic_state(DeviceState *d, struct aehd_lapic_state *kapic);

bool aehd_arch_stop_on_emulation_error(CPUState *cpu);

int aehd_check_extension(AEHDState *s, unsigned int extension);

int aehd_vm_check_extension(AEHDState *s, unsigned int extension);

uint32_t aehd_arch_get_supported_cpuid(AEHDState *env, uint32_t function,
                                       uint32_t index, int reg);

#endif /* NEED_CPU_H */

void aehd_raise_event(CPUState *cpu);
void aehd_cpu_synchronize_state(CPUState *cpu);

/**
 * aehd_irqchip_add_msi_route - Add MSI route for specific vector
 * @s:      AEHD state
 * @vector: which vector to add. This can be either MSI/MSIX
 *          vector. The function will automatically detect whether
 *          MSI/MSIX is enabled, and fetch corresponding MSI
 *          message.
 * @dev:    Owner PCI device to add the route. If @dev is specified
 *          as @NULL, an empty MSI message will be inited.
 * @return: virq (>=0) when success, errno (<0) when failed.
 */
int aehd_irqchip_add_msi_route(AEHDState *s, int vector, PCIDevice *dev);
int aehd_irqchip_update_msi_route(AEHDState *s, int virq, MSIMessage msg,
                                  PCIDevice *dev);
void aehd_irqchip_commit_routes(AEHDState *s);
void aehd_irqchip_release_virq(AEHDState *s, int virq);

void aehd_irqchip_set_qemuirq_gsi(AEHDState *s, qemu_irq irq, int gsi);
void aehd_pc_setup_irq_routing(bool pci_enabled);
void aehd_init_irq_routing(AEHDState *s);

/**
 * aehd_arch_irqchip_create:
 * @AEHDState: The AEHDState pointer
 * @MachineState: The MachineState pointer
 *
 * Allow architectures to create an in-kernel irq chip themselves.
 *
 * Returns: < 0: error
 *            0: irq chip was not created
 *          > 0: irq chip was created
 */
int aehd_arch_irqchip_create(MachineState *ms, AEHDState *s);

#endif
