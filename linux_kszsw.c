/* Linux ksz 9897/9477 helpers
 *
 * Copyright (C) 2021 Michael R Miller <mike@mtekllc.com>
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
#ifdef __linux__

#define _GNU_SOURCE

#include <confuse.h>
#include <fnmatch.h>
#include <net/if.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/ethtool.h>
#include <linux/netlink.h>
#include <linux/sockios.h>
#include <linux/types.h>
#include <fcntl.h>

#include "kszsw-conf.h"
#include "mini-snmpd.h"

#ifdef CONFIG_ENABLE_KSZSW

typedef unsigned long long u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int32_t s32;

/* counter offsets and number of counters per interface */
static struct kszsw_ifs_s {
        char *mib_path; /**< path to mib data*/
        char *speed_path; /**< path to speed / link */
        char *macaddr_path; /**< path to port mac address */
        char *macaddr_str; /**< str of mac addr */
        char *description; /**< ports description */
        uint8_t macaddr_bytes[6]; /**< digested / converted */
} kszsw_ifs[MAX_NR_INTERFACES];

static void kszsw_digest_mac_str(int intf, char *macaddr)
{
        unsigned int mb[6];
        int i;

        printf("%s %s\n", __func__, macaddr);

        int c = sscanf(macaddr, "%02x:%02x:%02x:%02x:%02x:%02x",
                &mb[0],
                &mb[1],
                &mb[2],
                &mb[3],
                &mb[4],
                &mb[5]
                );

        printf("c = %d mb5 %x\n", c, mb[5]);

        for (i = 0; i < 6; i++) {
                kszsw_ifs[intf].macaddr_bytes[i] = (uint8_t) (mb[i] & 0xff);
        }

        printf("digested %02X:%02X:%02X:%02X:%02X:%02X\n",
                kszsw_ifs[intf].macaddr_bytes[0],
                kszsw_ifs[intf].macaddr_bytes[1],
                kszsw_ifs[intf].macaddr_bytes[2],
                kszsw_ifs[intf].macaddr_bytes[3],
                kszsw_ifs[intf].macaddr_bytes[4],
                kszsw_ifs[intf].macaddr_bytes[5]);
}

static void kszsw_xlate_intf(cfg_t *cfg, int intf, const char *iname)
{
        char *tmpstr;

        if (!(tmpstr = cfg_getstr(cfg, "mib_path"))) {
                // error
                kszsw_ifs[intf].mib_path = NULL;
        } else {
                kszsw_ifs[intf].mib_path = strdup(tmpstr);
                logit(LOG_INFO, 0, "%s() got mib path %s as %s",
                        __func__,  iname, tmpstr);
        }

        if (!(tmpstr = cfg_getstr(cfg, "speed_path"))) {
                // error
                kszsw_ifs[intf].speed_path = NULL;
        } else {
                kszsw_ifs[intf].speed_path = strdup(tmpstr);
                logit(LOG_INFO, 0, "%s() got speed path %s as %s",
                        __func__,  iname, tmpstr);
        }

        if (!(tmpstr = cfg_getstr(cfg, "macaddr_str"))) {
                // error
                kszsw_ifs[intf].macaddr_str = NULL;
        } else {
                kszsw_ifs[intf].macaddr_str = strdup(tmpstr);
                kszsw_digest_mac_str(intf, kszsw_ifs[intf].macaddr_str);
                logit(LOG_INFO, 0, "%s() got port %s mac addr %s",
                        __func__,  iname, tmpstr);
        }

        if (!(tmpstr = cfg_getstr(cfg, "description"))) {
                // none specified
                kszsw_ifs[intf].description = NULL;
        } else {
                size_t i;
                for (i = 0; i < strlen(tmpstr); i++) {
                        if (tmpstr[i] > 0x7e || tmpstr[i] < 0x20){
                                fprintf(stderr,
                                        "kszsw description only printable chars please\n");
                                exit(0);
                        }
                }
                kszsw_ifs[intf].description = strdup(tmpstr);
                logit(LOG_INFO, 0, "%s() got description for %s set to (%s)",
                        __func__,  iname, tmpstr);
        }
}

void kszsw_xlate_cfg(cfg_t *cfg)
{
	cfg_t *kszswcfg;
	const char *iname;
	unsigned int i;
	int intf;

	for (i = 0; i < cfg_size(cfg, "kszsw"); i++) {

		kszswcfg = cfg_getnsec(cfg, "kszsw", i);
		iname = cfg_title(kszswcfg);

		logit(LOG_INFO, 0, "parsing kszsw for section %s", iname);

		/* exact match? */
		intf = find_ifname((char *)iname);
		if (intf >= 0) {
			kszsw_xlate_intf(kszswcfg, intf, iname);
			continue;
		}
	}
}


int sysfsread(const char *path, void *cb)
{
        typedef void *(func)(char *line);
        func *f = cb;
        ssize_t w = 0;
        int fd;
        char buf[8192];
        char *tmp;
        char *line;

        if (!cb) {
                printf("%s() cb is NULL\n", __func__);
                return -1;
        }

        if ((fd = open(path, O_RDONLY | O_NONBLOCK)) < 0) {
                printf("%s() failed to open %s for reading\n", __func__, path);
                return -2;
        }

        if ((w = read(fd, buf, sizeof(buf))) == -1) {
                return -3;
        }

        tmp = buf;
        line = tmp;

        while (*tmp) {
                if (*tmp == '\n') {
                        *tmp = 0x0;
                        f(line);
                        line = tmp + 1;
                }
                tmp++;
        }

        close(fd);

        return w;
}

typedef struct _iface_counters_t {
        uint32_t rx_total;
        uint32_t rx_hi;
        uint32_t rx_pause;
        uint32_t rx_bcast;
        uint32_t rx_mcast;
        uint32_t rx_ucast;
        uint32_t rx_discards;
        uint32_t rx_64_or_less;
        uint32_t rx_128_255;
        uint32_t rx_512_1023;
        uint32_t rx_1523_2000;
        uint32_t rx_undersize;
        uint32_t rx_fragments;
        uint32_t rx_symbol_err;
        uint32_t rx_align_err;
        uint32_t tx_late_col;
        uint32_t tx_total_col;
        uint32_t tx_single_col;

        uint32_t tx_total;
        uint32_t tx_hi;
        uint32_t tx_pause;
        uint32_t tx_bcast;
        uint32_t tx_mcast;
        uint32_t tx_ucast;
        uint32_t tx_discards;
        uint32_t rx_65_127;
        uint32_t rx_256_511;
        uint32_t rx_1024_1522;
        uint32_t rx_2001;
        uint32_t rx_oversize;
        uint32_t rx_jabbers;
        uint32_t rx_crc_err;
        uint32_t rx_mac_ctrl;
        uint32_t tx_deferred;
        uint32_t tx_exc_col;
        uint32_t tx_mult_col;
} iface_counters_t;

static iface_counters_t mib;
static int mib_line = 0;
void digest_mib_counters(char *line)
{
        switch (mib_line) {
        case 0:
                sscanf(line, "rx_total        = %u                 tx_total        = %u",
                        &mib.rx_total, &mib.tx_total);
                break;
        case 1:
                // rx_hi           = 0                     tx_hi           = 0
                break;
        case 2:
                sscanf(line, "rx_pause        = %u                     tx_pause        = %u",
                        &mib.rx_pause, &mib.tx_pause);
                break;
        case 3:
                sscanf(line, "rx_bcast        = %u                     tx_bcast        = %u",
                        &mib.rx_bcast, &mib.tx_bcast);
                break;
        case 4:
                sscanf(line, "rx_mcast        = %u                   tx_mcast        = %u",
                        &mib.rx_mcast, &mib.tx_mcast);
                break;
        case 5:
                sscanf(line, "rx_ucast        = %u                   tx_ucast        = %u",
                        &mib.rx_ucast, &mib.tx_ucast);
                break;
        case 6:
                sscanf(line, "rx_discards        = %u                   tx_discards        = %u",
                        &mib.rx_discards, &mib.tx_discards);
                break;
        case 7:
                //rx_64_or_less   = 2                     rx_65_127       = 904
                break;
        case 8:
                //rx_128_255      = 0                     rx_256_511      = 0
                break;
        case 9:
                //rx_512_1023     = 0                     rx_1024_1522    = 0
                break;
        case 10:
                //rx_1523_2000    = 0                     rx_2001         = 0
                break;
        case 11:
                //rx_undersize    = 0                     rx_oversize     = 0
                break;
        case 12:
                // rx_fragments    = 0                     rx_jabbers      = 0
                break;
        case 13:
                // rx_symbol_err   = 0                     rx_crc_err      = 0
                sscanf(line, "rx_symbol_err        = %u                   rx_crc_err        = %u",
                        &mib.rx_symbol_err, &mib.rx_crc_err);

                break;
        default:
                break;
        }
        mib_line++;
}

#define RESET_MIB_LINE()        do { mib_line = 0; } while(0);

int kszsw_gstats(int intf, netinfo_t *netinfo)
{
        if (!kszsw_ifs[intf].mib_path)
                return -1;

        RESET_MIB_LINE();

        sysfsread(kszsw_ifs[intf].mib_path, digest_mib_counters);

        // mm todo these might not be correct
        // rx
        netinfo->rx_bytes[intf] = mib.rx_total;
        netinfo->rx_mc_packets[intf] = mib.rx_mcast;
        netinfo->rx_bc_packets[intf] = mib.rx_bcast;
        netinfo->rx_packets[intf] = (mib.rx_bcast + mib.rx_mcast + mib.rx_ucast);
        netinfo->rx_errors[intf] = mib.rx_align_err + mib.rx_symbol_err;
        netinfo->rx_drops[intf] = mib.rx_discards;

        // tx
        netinfo->tx_bytes[intf] = mib.tx_total;
        netinfo->tx_mc_packets[intf] = mib.tx_mcast;
        netinfo->tx_bc_packets[intf] = mib.tx_bcast;
        netinfo->tx_packets[intf] = (mib.tx_bcast + mib.tx_mcast + mib.tx_ucast);
        netinfo->tx_errors[intf] = mib.tx_total_col;
        netinfo->tx_drops[intf] = mib.tx_discards;

	return 0;
}

char * kszsw_getifdesc(int intf)
{
       if (kszsw_ifs[intf].description) {
               return kszsw_ifs[intf].description;
       }
       return NULL;
}

void kszsw_get_netinfo(netinfo_t *netinfo)
{
	memset(netinfo, 0, sizeof(*netinfo));

        int intf;

        for (intf = 0; intf < MAX_NR_INTERFACES; intf++) {

                if (!kszsw_ifs[intf].mib_path) {
                        continue;
                }

                // type
                netinfo->if_type[intf] = 6; /* ethernetCsmacd(6) */

                // grab ksz mib stats from sysfs and cpy into netinfo
                kszsw_gstats(intf, netinfo);

                memcpy(netinfo->mac_addr[intf],
                        kszsw_ifs[intf].macaddr_bytes,
                        sizeof(netinfo->mac_addr[intf]));

                //mm todo this should be the switch MTU
                netinfo->if_mtu[intf] = 1500;

                char speedbuf[30];

                memset(speedbuf, 0, sizeof(speedbuf));

                read_file(kszsw_ifs[intf].speed_path, speedbuf, sizeof(speedbuf)-1);

                if (!strncmp(speedbuf,"unlinked", strlen("unlinked"))) {
                        netinfo->status[intf] = 2;
                        netinfo->if_speed[intf] = 0;
                } else {
                        netinfo->status[intf] = 1;
                        netinfo->if_speed[intf] = atoi(speedbuf);
                }

                netinfo->if_speed[intf] *= 1000000; /* to bps */

                netinfo->ifindex[intf] = intf;

                netinfo->lastchange[intf] = get_process_uptime();
                netinfo->stats[intf] = 1;


        }
}

#endif

#endif

