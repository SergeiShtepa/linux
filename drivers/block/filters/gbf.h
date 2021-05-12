/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * gbf.h - Header file for General Block Device Filter driver
 */
#ifndef __GBF_H__
#define __GBF_H__

int gbf_rule_add(dev_t dev_id, const char *rule_name, char *rule_exp,
		 bool add_to_head);

int gbf_rule_del(dev_t dev_id, const char *rule_name);

/* For debug purpose */
#define GBF_DEFAULT_FILTER

#endif
