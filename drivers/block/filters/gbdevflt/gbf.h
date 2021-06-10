/* SPDX-License-Identifier: GPL-2.0 */
/*
 * gbf.h - Header file for General Block Device Filter kernel module
 */
#ifndef __GBF_H__
#define __GBF_H__

#define GBF_RULE_NAME_LENGTH 32

int gbf_rule_add(dev_t dev_id, const char *rule_name, char *rule_exp,
		 bool add_to_head);

int gbf_rule_remove(dev_t dev_id, const char *rule_name);

#endif
