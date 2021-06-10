/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __GBF_SYSFS_H__
#define __GBF_SYSFS_H__

struct rule_info {
	struct list_head list;
	dev_t dev_id;
	char name[GBF_RULE_NAME_LENGTH + 1];
	char exp[1];
};

struct rule_info *gbf_rule_info_new(dev_t dev_id, const char *rule_name,
				    char *rule_exp);
void gbf_rules_list_append(struct rule_info *rule_info);
void gbf_rules_list_erase(dev_t dev_id, const char *rule_name);

int gbf_sysfs_init(const char *module_name);
void gbf_sysfs_done(void);

#endif
