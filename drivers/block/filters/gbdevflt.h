/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * gbdevflt.h - Header file for General Block Device Filter driver
 */
#ifndef __GBDEVFLT_H__
#define __GBDEVFLT_H__

/*
 * The General Filter implements two rules: allow, deny.
 * 1. The "allow" rule to pass bio processing if the condition is met,
 *    otherwise the bio processing is rejected.
 * 2. The "deny" rule to reject bio processing if the condition is met,
 *    otherwise bio processing is allowed.
 * The list of rules can be expanded. For example, we can add a REDIRECT
 * rule to redirect the bio to another block device.
 */
enum {
	GBF_RULE_CONSENT_ALLOW,
	GBF_RULE_CONSENT_DENY
};
typedef unsigned int gbf_rule_consent_t;

/*
 * There can be several conditions for applying a rule. They can be combined.
 */
enum {
	GBF_RULE_JOIN_AND,
	GBF_RULE_JOIN_OR
};
typedef unsigned int gbf_rule_join_t;

/*
 * There can be a list of rules for each block device. We can add a rule
 * either to the beginning or to the end of this list.
 */
enum {
	GBF_RULE_ADD_HEAD,
	GBF_RULE_ADD_TAIL
};
typedef unsigned int gbf_rule_add_t;

/*
 * The "owner" rule checks the sender of the bio request.
 * The owner is determined by the bi_end_io() function.
 */
struct gbf_rule_owner {
	bio_end_io_t *bi_end_io; /* pointer to owners end_io function */
};

/*
 * The "range" rule checks which blocks are accessed.
 */
struct gbf_rule_range {
	sector_t first; /* offset of the first regions sector */
	sector_t last;	/* offset of the last sector for regions */
};

/*
 * The module exports this functions so that other kernel modules can add
 * or remove a rule directly, without sysfs involvement.
 */
int gbf_rule_add(dev_t dev_id, const char *rule_name,
		const gbf_rule_consent_t consent,
		const gbf_rule_add_t rule_add,
		const gbf_rule_join_t join,
		const struct gbf_rule_range *rule_range,
		const struct gbf_rule_owner *rule_owner);

int gbf_rule_del(dev_t dev_id, const char *rule_name);

/* For debug purpose */
#define GBF_DEFAULT_FILTER

#endif
