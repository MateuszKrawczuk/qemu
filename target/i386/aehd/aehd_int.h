/*
 * Internal definitions for a target's AEHD support
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_AEHD_INT_H
#define QEMU_AEHD_INT_H

#include "qemu/accel.h"
#include "sysemu/aehd.h"

typedef struct AEHDSlot {
    hwaddr start_addr;
    ram_addr_t memory_size;
    void *ram;
    int slot;
    int flags;
} AEHDSlot;

typedef struct AEHDMemoryListener {
    MemoryListener listener;
    AEHDSlot *slots;
    int as_id;
} AEHDMemoryListener;

#define AEHD_MSI_HASHTAB_SIZE    256

struct AEHDState {
    AccelState parent_obj;

    int nr_slots;
    HANDLE fd;
    HANDLE vmfd;
    GHashTable *gsimap;
    struct aehd_irq_routing *irq_routes;
    int nr_allocated_irq_routes;
    unsigned long *used_gsi_bitmap;
    unsigned int gsi_count;
    QTAILQ_HEAD(, AEHDMSIRoute) msi_hashtab[AEHD_MSI_HASHTAB_SIZE];
    AEHDMemoryListener memory_listener;
    QLIST_HEAD(, AEHDParkedVcpu) aehd_parked_vcpus;
};

void aehd_memory_listener_register(AEHDState *s, AEHDMemoryListener *kml,
                                   AddressSpace *as, int as_id);

#endif
