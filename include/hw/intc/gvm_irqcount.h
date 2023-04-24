/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef GVM_IRQCOUNT_H
#define GVM_IRQCOUNT_H

void gvm_report_irq_delivered(int delivered);
void gvm_reset_irq_delivered(void);
int gvm_get_irq_delivered(void);

#endif
