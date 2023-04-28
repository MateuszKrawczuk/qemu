/*
 * GVM in-kernel IOPIC support
 *
 * Copyright (c) 2011 Siemens AG
 *
 * Authors:
 *  Jan Kiszka          <jan.kiszka@siemens.com>
 *
 * This work is licensed under the terms of the GNU GPL version 2.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "monitor/monitor.h"
#include "hw/qdev-properties.h"
#include "hw/intc/ioapic_internal.h"
#include "hw/intc/gvm_irqcount.h"
#include "hw/i386/pc.h"
#include "hw/i386/apic_internal.h"
#include "sysemu/gvm.h"
#include "sysemu/gvm-interface.h"

/* PC Utility function */
void gvm_pc_setup_irq_routing(bool pci_enabled)
{
    GVMState *s = gvm_state;
    int i;

    for (i = 0; i < 8; ++i) {
        if (i == 2) {
            continue;
        }
        gvm_irqchip_add_irq_route(s, i, GVM_IRQCHIP_PIC_MASTER, i);
    }
    for (i = 8; i < 16; ++i) {
        gvm_irqchip_add_irq_route(s, i, GVM_IRQCHIP_PIC_SLAVE, i - 8);
    }
    if (pci_enabled) {
        for (i = 0; i < 24; ++i) {
            if (i == 0) {
                gvm_irqchip_add_irq_route(s, i, GVM_IRQCHIP_IOAPIC, 2);
            } else if (i != 2) {
                gvm_irqchip_add_irq_route(s, i, GVM_IRQCHIP_IOAPIC, i);
            }
        }
    }
    gvm_irqchip_commit_routes(s);
}

typedef struct GVMIOAPICState GVMIOAPICState;

struct GVMIOAPICState {
    IOAPICCommonState ioapic;
    uint32_t gvm_gsi_base;
};

static void gvm_ioapic_get(IOAPICCommonState *s)
{
    struct gvm_irqchip chip;
    struct gvm_ioapic_state *kioapic;
    int ret, i;

    chip.chip_id = GVM_IRQCHIP_IOAPIC;
    ret = gvm_vm_ioctl(gvm_state, GVM_GET_IRQCHIP,
            &chip, sizeof(chip), &chip, sizeof(chip));
    if (ret < 0) {
        fprintf(stderr, "GVM_GET_IRQCHIP failed: %s\n", strerror(ret));
        abort();
    }

    kioapic = &chip.chip.ioapic;

    s->id = kioapic->id;
    s->ioregsel = kioapic->ioregsel;
    s->irr = kioapic->irr;
    for (i = 0; i < IOAPIC_NUM_PINS; i++) {
        s->ioredtbl[i] = kioapic->redirtbl[i].bits;
    }
}

static void gvm_ioapic_put(IOAPICCommonState *s)
{
    struct gvm_irqchip chip;
    struct gvm_ioapic_state *kioapic;
    int ret, i;

    chip.chip_id = GVM_IRQCHIP_IOAPIC;
    kioapic = &chip.chip.ioapic;

    kioapic->id = s->id;
    kioapic->ioregsel = s->ioregsel;
    kioapic->base_address = s->busdev.mmio[0].addr;
    kioapic->irr = s->irr;
    for (i = 0; i < IOAPIC_NUM_PINS; i++) {
        kioapic->redirtbl[i].bits = s->ioredtbl[i];
    }

    ret = gvm_vm_ioctl(gvm_state, GVM_SET_IRQCHIP,
            &chip, sizeof(chip), NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "GVM_GET_IRQCHIP failed: %s\n", strerror(ret));
        abort();
    }
}

static void gvm_ioapic_reset(DeviceState *dev)
{
    IOAPICCommonState *s = IOAPIC_COMMON(dev);

    ioapic_reset_common(dev);
    gvm_ioapic_put(s);
}

static void gvm_ioapic_set_irq(void *opaque, int irq, int level)
{
    GVMIOAPICState *s = opaque;
    IOAPICCommonState *common = IOAPIC_COMMON(s);
    int delivered;

    ioapic_stat_update_irq(common, irq, level);
    delivered = gvm_set_irq(gvm_state, s->gvm_gsi_base + irq, level);
    gvm_report_irq_delivered(delivered);
}

static void gvm_ioapic_realize(DeviceState *dev, Error **errp)
{
    IOAPICCommonState *s = IOAPIC_COMMON(dev);

    memory_region_init_io(&s->io_memory, OBJECT(dev), NULL, NULL, "gvm-ioapic", 0x1000);

    /*
     * GVM ioapic only supports 0x11 now. This will only be used when
     * we want to dump ioapic version.
     */
    s->version = 0x11;

    qdev_init_gpio_in(dev, gvm_ioapic_set_irq, IOAPIC_NUM_PINS);
}

static Property gvm_ioapic_properties[] = {
    DEFINE_PROP_UINT32("gsi_base", GVMIOAPICState, gvm_gsi_base, 0),
    DEFINE_PROP_END_OF_LIST()
};

static void gvm_ioapic_class_init(ObjectClass *klass, void *data)
{
    IOAPICCommonClass *k = IOAPIC_COMMON_CLASS(klass);
    DeviceClass *dc = DEVICE_CLASS(klass);

    k->realize   = gvm_ioapic_realize;
    k->pre_save  = gvm_ioapic_get;
    k->post_load = gvm_ioapic_put;
    dc->reset    = gvm_ioapic_reset;
    device_class_set_props(dc, gvm_ioapic_properties);
}

static const TypeInfo gvm_ioapic_info = {
    .name  = TYPE_GVM_IOAPIC,
    .parent = TYPE_IOAPIC_COMMON,
    .instance_size = sizeof(GVMIOAPICState),
    .class_init = gvm_ioapic_class_init,
};

static void gvm_ioapic_register_types(void)
{
    type_register_static(&gvm_ioapic_info);
}

type_init(gvm_ioapic_register_types)
