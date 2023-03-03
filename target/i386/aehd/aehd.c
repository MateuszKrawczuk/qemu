/*
 * QEMU AEHD support
 *
 * Copyright (C) 2006-2008 Qumranet Technologies
 * Copyright IBM, Corp. 2008
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qapi/error.h"

#include "cpu.h"
#include "aehd_int.h"
#include "sysemu/aehd-interface.h"
#include "sysemu/sysemu.h"
#include "sysemu/hw_accel.h"
#include "sysemu/reset.h"
#include "sysemu/runstate.h"

#include "exec/gdbstub.h"
#include "qemu/host-utils.h"
#include "qemu/main-loop.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "qemu/memalign.h"
#include "hw/i386/x86.h"
#include "hw/i386/apic.h"
#include "hw/i386/apic_internal.h"
#include "hw/i386/apic-msidef.h"
#include "hw/i386/e820_memory_layout.h"

#include "exec/ioport.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "migration/blocker.h"
#include "exec/memattrs.h"

#ifdef DEBUG_AEHD
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

typedef struct MSIRouteEntry MSIRouteEntry;

struct MSIRouteEntry {
    PCIDevice *dev;             /* Device pointer */
    int vector;                 /* MSI/MSIX vector index */
    int virq;                   /* Virtual IRQ index */
    QLIST_ENTRY(MSIRouteEntry) list;
};

/* List of used GSI routes */
static QLIST_HEAD(, MSIRouteEntry) msi_route_list = \
    QLIST_HEAD_INITIALIZER(msi_route_list);

int aehd_arch_add_msi_route_post(struct aehd_irq_routing_entry *route,
                                 int vector, PCIDevice *dev)
{
    MSIRouteEntry *entry;

    entry = g_new0(MSIRouteEntry, 1);
    entry->dev = dev;
    entry->vector = vector;
    entry->virq = route->gsi;
    QLIST_INSERT_HEAD(&msi_route_list, entry, list);
    return 0;
}

int aehd_arch_release_virq_post(int virq)
{
    MSIRouteEntry *entry, *next;
    QLIST_FOREACH_SAFE(entry, &msi_route_list, list, next) {
        if (entry->virq == virq) {
            QLIST_REMOVE(entry, list);
            break;
        }
    }
    return 0;
}
