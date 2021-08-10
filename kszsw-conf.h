/* Microchip KSZ9897/9477 sysfs mib helpers
 *
 * Copyright (C) 2021  Michael R Miller <mike@mtekllc.com>
 *
 * This file may be distributed and/or modified under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.
 *
 * This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
 * WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See COPYING for GPL licensing information.
 */

#ifndef _KSZSW_CONF_H_
#define _KSZSW_CONF_H_

#include <confuse.h>
#include "config.h"
#include "mini-snmpd.h"

#ifdef CONFIG_ENABLE_KSZSW
void kszsw_xlate_cfg(cfg_t *cfg);
#else
static inline void kszsw_xlate_cfg(cfg_t *cfg)
{
	if (cfg_size(cfg, "kszsw") > 0)
		logit(LOG_WARNING, 0, "no kszsw support. ignoring config section");
}
#endif

#endif
