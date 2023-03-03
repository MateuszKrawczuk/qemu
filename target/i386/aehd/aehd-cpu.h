/*
 * i386 AEHD CPU type and functions
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef AEHD_CPU_H
#define AEHD_CPU_H

#ifdef CONFIG_AEHD
/*
 * Change the value of a AEHD-specific default
 *
 * If value is NULL, no default will be set and the original
 * value from the CPU model table will be kept.
 *
 * It is valid to call this function only for properties that
 * are already present in the aehd_default_props table.
 */
void x86_cpu_change_aehd_default(const char *prop, const char *value);

#else /* !CONFIG_AEHD */

#define x86_cpu_change_aehd_default(a, b)

#endif /* CONFIG_AEHD */

#endif /* AEHD_CPU_H */
