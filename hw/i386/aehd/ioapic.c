/*
 * AEHD in-kernel IOPIC support
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
#include "hw/i386/pc.h"
#include "hw/qdev-properties.h"
#include "hw/intc/ioapic_internal.h"
#include "sysemu/aehd.h"
#include "sysemu/aehd-interface.h"

/* PC Utility function */
void aehd_pc_setup_irq_routing(bool pci_enabled)
{
    AEHDState *s = aehd_state;
    int i;

    for (i = 0; i < 8; ++i) {
        if (i == 2) {
            continue;
        }
        aehd_irqchip_add_irq_route(s, i, AEHD_IRQCHIP_PIC_MASTER, i);
    }
    for (i = 8; i < 16; ++i) {
        aehd_irqchip_add_irq_route(s, i, AEHD_IRQCHIP_PIC_SLAVE, i - 8);
    }
    if (pci_enabled) {
        for (i = 0; i < 24; ++i) {
            if (i == 0) {
                aehd_irqchip_add_irq_route(s, i, AEHD_IRQCHIP_IOAPIC, 2);
            } else if (i != 2) {
                aehd_irqchip_add_irq_route(s, i, AEHD_IRQCHIP_IOAPIC, i);
            }
        }
    }
    aehd_irqchip_commit_routes(s);
}

typedef struct AEHDIOAPICState AEHDIOAPICState;

struct AEHDIOAPICState {
    IOAPICCommonState ioapic;
    uint32_t aehd_gsi_base;
};

static void aehd_ioapic_get(IOAPICCommonState *s)
{
    struct aehd_irqchip chip;
    struct aehd_ioapic_state *aioapic;
    int ret, i;

    chip.chip_id = AEHD_IRQCHIP_IOAPIC;
    ret = aehd_vm_ioctl(aehd_state, AEHD_GET_IRQCHIP, &chip, sizeof(chip),
                        &chip, sizeof(chip));
    if (ret < 0) {
        fprintf(stderr, "AEHD_GET_IRQCHIP failed: %s\n", strerror(ret));
        abort();
    }

    aioapic = &chip.chip.ioapic;

    s->id = aioapic->id;
    s->ioregsel = aioapic->ioregsel;
    s->irr = aioapic->irr;
    for (i = 0; i < IOAPIC_NUM_PINS; i++) {
        s->ioredtbl[i] = aioapic->redirtbl[i].bits;
    }
}

static void aehd_ioapic_put(IOAPICCommonState *s)
{
    struct aehd_irqchip chip;
    struct aehd_ioapic_state *aioapic;
    int ret, i;

    chip.chip_id = AEHD_IRQCHIP_IOAPIC;
    aioapic = &chip.chip.ioapic;

    aioapic->id = s->id;
    aioapic->ioregsel = s->ioregsel;
    aioapic->base_address = s->busdev.mmio[0].addr;
    aioapic->irr = s->irr;
    for (i = 0; i < IOAPIC_NUM_PINS; i++) {
        aioapic->redirtbl[i].bits = s->ioredtbl[i];
    }

    ret = aehd_vm_ioctl(aehd_state, AEHD_SET_IRQCHIP,
                        &chip, sizeof(chip), NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "AEHD_GET_IRQCHIP failed: %s\n", strerror(ret));
        abort();
    }
}

static void aehd_ioapic_reset(DeviceState *dev)
{
    IOAPICCommonState *s = IOAPIC_COMMON(dev);

    ioapic_reset_common(dev);
    aehd_ioapic_put(s);
}

static void aehd_ioapic_set_irq(void *opaque, int irq, int level)
{
    AEHDIOAPICState *s = opaque;

    aehd_set_irq(aehd_state, s->aehd_gsi_base + irq, level);
}

static void aehd_ioapic_realize(DeviceState *dev, Error **errp)
{
    IOAPICCommonState *s = IOAPIC_COMMON(dev);

    memory_region_init_io(&s->io_memory, OBJECT(dev), NULL, NULL,
                          "aehd-ioapic", 0x1000);

    /*
     * AEHD ioapic only supports 0x11 now. This will only be used when
     * we want to dump ioapic version.
     */
    s->version = 0x11;

    qdev_init_gpio_in(dev, aehd_ioapic_set_irq, IOAPIC_NUM_PINS);
}

static Property aehd_ioapic_properties[] = {
    DEFINE_PROP_UINT32("gsi_base", AEHDIOAPICState, aehd_gsi_base, 0),
    DEFINE_PROP_END_OF_LIST()
};

static void aehd_ioapic_class_init(ObjectClass *klass, void *data)
{
    IOAPICCommonClass *k = IOAPIC_COMMON_CLASS(klass);
    DeviceClass *dc = DEVICE_CLASS(klass);

    k->realize   = aehd_ioapic_realize;
    k->pre_save  = aehd_ioapic_get;
    k->post_load = aehd_ioapic_put;
    dc->reset    = aehd_ioapic_reset;
    device_class_set_props(dc, aehd_ioapic_properties);
}

static const TypeInfo aehd_ioapic_info = {
    .name  = TYPE_AEHD_IOAPIC,
    .parent = TYPE_IOAPIC_COMMON,
    .instance_size = sizeof(AEHDIOAPICState),
    .class_init = aehd_ioapic_class_init,
};

static void aehd_ioapic_register_types(void)
{
    type_register_static(&aehd_ioapic_info);
}

type_init(aehd_ioapic_register_types)
