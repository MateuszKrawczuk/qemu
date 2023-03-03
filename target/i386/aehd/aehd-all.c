/*
 * QEMU AEHD support
 *
 * Copyright IBM, Corp. 2008
 *           Red Hat, Inc. 2008
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *  Glauber Costa     <gcosta@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"

#include "qemu/atomic.h"
#include "qemu/option.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "hw/hw.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "exec/gdbstub.h"
#include "sysemu/runstate.h"
#include "sysemu/cpus.h"
#include "qemu/bswap.h"
#include "exec/memory.h"
#include "exec/ram_addr.h"
#include "exec/address-spaces.h"
#include "qemu/event_notifier.h"
#include "qemu/main-loop.h"
#include "trace.h"
#include "hw/irq.h"
#include "qapi/visitor.h"
#include "qapi/qapi-types-common.h"
#include "qapi/qapi-visit-common.h"
#include "sysemu/hw_accel.h"
#include "sysemu/aehd-interface.h"
#include "aehd_int.h"

#include "hw/boards.h"

#ifdef DEBUG_AEHD
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

AEHDState *aehd_state;

int aehd_set_irq(AEHDState *s, int irq, int level)
{
    struct aehd_irq_level event;
    int ret;

    event.level = level;
    event.irq = irq;
    ret = aehd_vm_ioctl(s, AEHD_IRQ_LINE_STATUS, &event, sizeof(event),
                        &event, sizeof(event));

    if (ret < 0) {
        perror("aehd_set_irq");
        abort();
    }

    return event.status;
}

typedef struct AEHDMSIRoute {
    struct aehd_irq_routing_entry kroute;
    QTAILQ_ENTRY(AEHDMSIRoute) entry;
} AEHDMSIRoute;

static void set_gsi(AEHDState *s, unsigned int gsi)
{
    set_bit(gsi, s->used_gsi_bitmap);
}

static void clear_gsi(AEHDState *s, unsigned int gsi)
{
    clear_bit(gsi, s->used_gsi_bitmap);
}

void aehd_irqchip_commit_routes(AEHDState *s)
{
    int ret;
    size_t irq_routing_size;

    s->irq_routes->flags = 0;
    irq_routing_size = sizeof(struct aehd_irq_routing) +
                       s->irq_routes->nr *
                       sizeof(struct aehd_irq_routing_entry);
    ret = aehd_vm_ioctl(s, AEHD_SET_GSI_ROUTING, s->irq_routes,
                        irq_routing_size, NULL, 0);
    assert(ret == 0);
}

static void aehd_add_routing_entry(AEHDState *s,
                                   struct aehd_irq_routing_entry *entry)
{
    struct aehd_irq_routing_entry *new;
    int n, size;

    if (s->irq_routes->nr == s->nr_allocated_irq_routes) {
        n = s->nr_allocated_irq_routes * 2;
        if (n < 64) {
            n = 64;
        }
        size = sizeof(struct aehd_irq_routing);
        size += n * sizeof(*new);
        s->irq_routes = g_realloc(s->irq_routes, size);
        s->nr_allocated_irq_routes = n;
    }
    n = s->irq_routes->nr++;
    new = &s->irq_routes->entries[n];

    *new = *entry;

    set_gsi(s, entry->gsi);
}

void aehd_irqchip_add_irq_route(AEHDState *s, int irq, int irqchip, int pin)
{
    struct aehd_irq_routing_entry e = {};

    assert(pin < s->gsi_count);

    e.gsi = irq;
    e.type = AEHD_IRQ_ROUTING_IRQCHIP;
    e.flags = 0;
    e.u.irqchip.irqchip = irqchip;
    e.u.irqchip.pin = pin;
    aehd_add_routing_entry(s, &e);
}

void aehd_irqchip_release_virq(AEHDState *s, int virq)
{
    struct aehd_irq_routing_entry *e;
    int i;

    for (i = 0; i < s->irq_routes->nr; i++) {
        e = &s->irq_routes->entries[i];
        if (e->gsi == virq) {
            s->irq_routes->nr--;
            *e = s->irq_routes->entries[s->irq_routes->nr];
        }
    }
    clear_gsi(s, virq);
    aehd_arch_release_virq_post(virq);
}

static unsigned int aehd_hash_msi(uint32_t data)
{
    /*
     * According to Intel SDM, the lowest byte is an interrupt vector
     */
    return data & 0xff;
}

static void aehd_flush_dynamic_msi_routes(AEHDState *s)
{
    AEHDMSIRoute *route, *next;
    unsigned int hash;

    for (hash = 0; hash < AEHD_MSI_HASHTAB_SIZE; hash++) {
        QTAILQ_FOREACH_SAFE(route, &s->msi_hashtab[hash], entry, next) {
            aehd_irqchip_release_virq(s, route->kroute.gsi);
            QTAILQ_REMOVE(&s->msi_hashtab[hash], route, entry);
            g_free(route);
        }
    }
}

static int aehd_irqchip_get_virq(AEHDState *s)
{
    int next_virq;

    /*
     * PIC and IOAPIC share the first 16 GSI numbers, thus the available
     * GSI numbers are more than the number of IRQ route. Allocating a GSI
     * number can succeed even though a new route entry cannot be added.
     * When this happens, flush dynamic MSI entries to free IRQ route entries.
     */
    if (s->irq_routes->nr == s->gsi_count) {
        aehd_flush_dynamic_msi_routes(s);
    }

    /* Return the lowest unused GSI in the bitmap */
    next_virq = find_first_zero_bit(s->used_gsi_bitmap, s->gsi_count);
    if (next_virq >= s->gsi_count) {
        return -ENOSPC;
    } else {
        return next_virq;
    }
}

static AEHDMSIRoute *aehd_lookup_msi_route(AEHDState *s, MSIMessage msg)
{
    unsigned int hash = aehd_hash_msi(msg.data);
    AEHDMSIRoute *route;

    QTAILQ_FOREACH(route, &s->msi_hashtab[hash], entry) {
        if (route->kroute.u.msi.address_lo == (uint32_t)msg.address &&
            route->kroute.u.msi.address_hi == (msg.address >> 32) &&
            route->kroute.u.msi.data == le32_to_cpu(msg.data)) {
            return route;
        }
    }
    return NULL;
}

int aehd_irqchip_send_msi(AEHDState *s, MSIMessage msg)
{
    AEHDMSIRoute *route;

    route = aehd_lookup_msi_route(s, msg);
    if (!route) {
        int virq;

        virq = aehd_irqchip_get_virq(s);
        if (virq < 0) {
            return virq;
        }

        route = g_malloc0(sizeof(AEHDMSIRoute));
        route->kroute.gsi = virq;
        route->kroute.type = AEHD_IRQ_ROUTING_MSI;
        route->kroute.flags = 0;
        route->kroute.u.msi.address_lo = (uint32_t)msg.address;
        route->kroute.u.msi.address_hi = msg.address >> 32;
        route->kroute.u.msi.data = le32_to_cpu(msg.data);

        aehd_add_routing_entry(s, &route->kroute);
        aehd_irqchip_commit_routes(s);

        QTAILQ_INSERT_TAIL(&s->msi_hashtab[aehd_hash_msi(msg.data)], route,
                           entry);
    }

    assert(route->kroute.type == AEHD_IRQ_ROUTING_MSI);

    return aehd_set_irq(s, route->kroute.gsi, 1);
}

int aehd_ioctl(AEHDState *s, int type, void *input, size_t input_size,
               void *output, size_t output_size)
{
    int ret;
    DWORD byteRet;

    ret = DeviceIoControl(s->fd, type, input, input_size,
                          output, output_size, &byteRet, NULL);
    if (!ret) {
        DPRINTF("aehd device IO control %x failed: %lx\n",
                type, GetLastError());
        switch (GetLastError()) {
        case ERROR_MORE_DATA:
            ret = -E2BIG;
            break;
        case ERROR_RETRY:
            ret = -EAGAIN;
            break;
        default:
            ret = -EFAULT;
        }
    } else {
        ret = 0;
    }
    return ret;
}

int aehd_vm_ioctl(AEHDState *s, int type, void *input, size_t input_size,
                  void *output, size_t output_size)
{
    int ret;
    DWORD byteRet;

    ret = DeviceIoControl(s->vmfd, type, input, input_size,
                          output, output_size, &byteRet, NULL);
    if (!ret) {
        DPRINTF("aehd VM IO control %x failed: %lx\n",
                type, GetLastError());
        switch (GetLastError()) {
        case ERROR_MORE_DATA:
            ret = -E2BIG;
            break;
        case ERROR_RETRY:
            ret = -EAGAIN;
            break;
        default:
            ret = -EFAULT;
        }
    } else {
        ret = 0;
    }
    return ret;
}

int aehd_vcpu_ioctl(CPUState *cpu, int type, void *input, size_t input_size,
                    void *output, size_t output_size)
{
    int ret;
    DWORD byteRet;

    ret = DeviceIoControl(cpu->aehd_fd, type, input, input_size,
                          output, output_size, &byteRet, NULL);
    if (!ret) {
        DPRINTF("aehd VCPU IO control %x failed: %lx\n",
                type, GetLastError());
        switch (GetLastError()) {
        case ERROR_MORE_DATA:
            ret = -E2BIG;
            break;
        case ERROR_RETRY:
            ret = -EAGAIN;
            break;
        default:
            ret = -EFAULT;
        }
    } else {
        ret = 0;
    }
    return ret;
}
