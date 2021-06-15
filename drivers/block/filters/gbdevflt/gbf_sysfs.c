// SPDX-License-Identifier: GPL-2.0
/*
 * Implements module management via sysfs files.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/device.h>
#include <linux/blkdev.h>
#include <linux/parser.h>
#include "gbf.h"
#include "gbf_sysfs.h"

struct mutex rules_list_lock;
LIST_HEAD(rules_list);

enum {
	GBF_OPT_ERR = 0,
	GBF_OPT_NAME,
	GBF_OPT_PATH,
	GBF_OPT_TO,
	GBF_OPT_EXP
};

static const match_table_t gbf_add_tokens = {
	{GBF_OPT_NAME, "name=%s"},
	{GBF_OPT_PATH, "path=%s"},
	{GBF_OPT_TO, "to=%s"},
	{GBF_OPT_EXP, "exp=%s"},
	{GBF_OPT_ERR, NULL},
};

struct rule_add_opt {
	char *name;
	char *path;
	char *to;
	char *exp;
};

static inline void rule_add_free(struct rule_add_opt *opt)
{
	kfree(opt->name);
	kfree(opt->path);
	kfree(opt->to);
	kfree(opt->exp);
}

static int rule_add_parse(char *options, struct rule_add_opt *opt)
{
	int ret = 0;
	char *p;
	int token;
	substring_t args[MAX_OPT_ARGS];

	while ((p = strsep(&options, ";\n")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, gbf_add_tokens, args);
		switch (token) {
		case GBF_OPT_NAME:
			p = match_strdup(args);
			if (!p) {
				ret = -ENOMEM;
				goto out;
			}
			if (strlen(p) > GBF_RULE_NAME_LENGTH) {
				pr_err("Rule name too long\n");
				ret = -EINVAL;
				kfree(p);
				goto out;
			}

			opt->name = p;
			break;
		case GBF_OPT_PATH:
			p = match_strdup(args);
			if (!p) {
				ret = -ENOMEM;
				goto out;
			}

			opt->path = p;
			break;
		case GBF_OPT_TO:
			p = match_strdup(args);
			if (!p) {
				ret = -ENOMEM;
				goto out;
			}

			opt->to = p;
			break;
		case GBF_OPT_EXP:
			p = match_strdup(args);
			if (!p) {
				ret = -ENOMEM;
				goto out;
			}

			opt->exp = p;
			break;
		default:
			pr_err("Unknown parameter or missing value '%s'\n", p);
			ret = -EINVAL;
			goto out;
		}
	}
out:
	return ret;
}

static int rule_add_execute(struct rule_add_opt *opt)
{
	int ret;
	dev_t dev_id;
	bool add_to;

	if (!opt->name) {
		pr_err("Option 'name' not found\n");
		return -EINVAL;
	}
	if (!opt->path) {
		pr_err("Option 'path' not found\n");
		return -EINVAL;
	}
	if (!opt->exp) {
		pr_err("Option 'exp' not found\n");
		return -EINVAL;
	}
	add_to = (opt->to) && (strcmp(opt->to, "head") == 0);

	ret = lookup_bdev(opt->path, &dev_id);
	if (ret) {
		pr_err("Block device '%s' not found\n", opt->path);
		return ret;
	}

	ret = gbf_rule_add(dev_id, opt->name, opt->exp, add_to);
	if (ret)
		pr_err("Failed to add rule '%s' for device '%s'\n",
			opt->name, opt->path);
	return ret;
}

static const match_table_t gbf_remove_tokens = {
	{GBF_OPT_NAME, "name=%s"},
	{GBF_OPT_PATH, "path=%s"},
	{GBF_OPT_ERR, NULL},
};
struct rule_remove_opt {
	char *name;
	char *path;
};

static inline void rule_remove_free(struct rule_remove_opt *opt)
{
	kfree(opt->name);
	kfree(opt->path);
}

static int rule_remove_execute(struct rule_remove_opt *opt)
{
	int ret;
	dev_t dev_id;

	if (!opt->name) {
		pr_err("Option 'name' not found\n");
		return -EINVAL;
	}
	if (!opt->path) {
		pr_err("Option 'path' not found\n");
		return -EINVAL;
	}

	ret = lookup_bdev(opt->path, &dev_id);
	if (ret) {
		pr_err("Block device '%s' not found\n", opt->path);
		return ret;
	}

	ret = gbf_rule_remove(dev_id, opt->name);
	if (ret)
		pr_err("Failed to remove rule '%s' for device '%s'\n",
			opt->name, opt->path);
	return ret;
}

static int rule_remove_parse(char *options, struct rule_remove_opt *opt)
{
	int ret = 0;
	char *p;
	int token;
	substring_t args[MAX_OPT_ARGS];

	while ((p = strsep(&options, ";\n")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, gbf_remove_tokens, args);

		switch (token) {
		case GBF_OPT_NAME:
			p = match_strdup(&args[0]);
			if (!p) {
				ret = -ENOMEM;
				goto out;
			}
			if (strlen(p) > GBF_RULE_NAME_LENGTH) {
				pr_err("Rule name too long\n");
				ret = -EINVAL;
				kfree(p);
				goto out;
			}

			opt->name = p;
			break;
		case GBF_OPT_PATH:
			p = match_strdup(&args[0]);
			if (!p) {
				ret = -ENOMEM;
				goto out;
			}

			opt->path = p;
			break;
		default:
			pr_err("Unknown parameter or missing value '%s'\n", p);
			ret = -EINVAL;
			goto out;
		}
	}
out:
	return ret;
}

static ssize_t rule_add_store(struct class *class, struct class_attribute *attr,
			      const char *buf, size_t count)
{
	int ret = 0;
	char *options = NULL;
	struct rule_add_opt opt = {0};

	options = kmemdup_nul(buf, count, GFP_KERNEL);
	if (!options)
		return -ENOMEM;

	ret = rule_add_parse(options, &opt);
	if (ret) {
		pr_err("Failed to parse options %s\n", options);
		goto out;
	}
	ret = rule_add_execute(&opt);
	if (ret) {
		pr_err("Failed to add rule\n");
		goto out;
	}
out:
	rule_add_free(&opt);
	kfree(options);
	if (ret)
		return (ssize_t)ret;
	return count;
};

static ssize_t rule_remove_store(struct class *class,
				 struct class_attribute *attr,
				 const char *buf, size_t count)
{
	int ret = 0;
	char *options = NULL;
	struct rule_remove_opt opt = {0};

	options = kmemdup_nul(buf, count, GFP_KERNEL);
	if (!options)
		return -ENOMEM;

	ret = rule_remove_parse(options, &opt);
	if (ret) {
		pr_err("Failed to parse options %s\n", options);
		goto out;
	}
	ret = rule_remove_execute(&opt);
	if (ret) {
		pr_err("Failed to remove rule\n");
		goto out;
	}
out:
	rule_remove_free(&opt);
	kfree(options);
	if (ret)
		return (ssize_t)ret;
	return count;
};

/*
 * Displays a list of added rules. Each rule starts with a new line.
 * However, only one page of data can be output via sysfs. So if there are too
 * many rules, they will not be displayed completely. In this case, the "\n"
 * character will not be added at the end.
 */
static ssize_t rule_list_show(struct class *class, struct class_attribute *attr,
				 char *buf)
{
	struct rule_info *rule_info = NULL;
	size_t pos = 0;
	size_t line_sz;

	mutex_lock(&rules_list_lock);
	if (list_empty(&rules_list))
		goto out;

	list_for_each_entry(rule_info, &rules_list, list) {
		line_sz = snprintf(buf + pos, PAGE_SIZE - pos,
			"dev_id=%d:%d;name=%s;exp=%s;\n",
			 MAJOR(rule_info->dev_id), MINOR(rule_info->dev_id),
			 rule_info->name, rule_info->exp);
		if (line_sz > (PAGE_SIZE - pos)) {
			pos += line_sz;
			break;
		}
		if (line_sz == (PAGE_SIZE - pos)) {
			/* remove '\n' on the tail */
			pos += line_sz - 1;
			break;
		}

		pos += line_sz;
	}
out:
	mutex_unlock(&rules_list_lock);
	return pos;
}

CLASS_ATTR_WO(rule_add);
CLASS_ATTR_WO(rule_remove);
CLASS_ATTR_RO(rule_list);

static struct attribute *gbf_attrs[] = {
	&class_attr_rule_add.attr,
	&class_attr_rule_remove.attr,
	&class_attr_rule_list.attr,
	NULL,
};

static struct attribute_group gbf_attr_group = {
	.attrs = gbf_attrs,
};

static const struct attribute_group *gbf_attr_groups[] = {
	&gbf_attr_group,
	NULL,
};

static struct device *gbf_dev;
static struct class *gbf_dev_class;
static struct kobject *gbf_rules_kobj;

struct rule_info *gbf_rule_info_new(dev_t dev_id, const char *rule_name,
				    char *rule_exp)
{
	struct rule_info *rule_info = NULL;
	size_t rule_exp_len = strlen(rule_exp);

	rule_info = kzalloc(sizeof(struct rule_info) + rule_exp_len,
			    GFP_KERNEL);
	if (!rule_info)
		return NULL;

	INIT_LIST_HEAD(&rule_info->list);
	rule_info->dev_id = dev_id;
	strncpy(rule_info->name, rule_name, GBF_RULE_NAME_LENGTH);
	strncpy(rule_info->exp, rule_exp, rule_exp_len);
	return rule_info;
}

void gbf_rules_list_append(struct rule_info *rule_info)
{
	mutex_lock(&rules_list_lock);
	list_add_tail(&rule_info->list, &rules_list);
	mutex_unlock(&rules_list_lock);
}

void gbf_rules_list_erase(dev_t dev_id, const char *rule_name)
{
	struct rule_info *rule_info;

	/*
	 * A separate list "rules_list" and mutex "rules_list_lock" is used
	 * to avoid using the bdev_filter_lock() lock.
	 * This allows not to lock access to block devices when reading the
	 * list of available rules.
	 *
	 * However, if the function to remove a rule from one thread is called
	 * at the same time as the function to remove the same rule from
	 * another thread, the rule removal thread may overtake the add thread.
	 * To avoid this situation, the deletion from the list is repeated
	 * after the thread is forced out. Otherwise, the list may accumulate
	 * non-existent rules.
	 */
repeat:
	mutex_lock(&rules_list_lock);

	if (!list_empty(&rules_list)) {
		list_for_each_entry(rule_info, &rules_list, list) {
			if ((rule_info->dev_id == dev_id) &&
			    (strncmp(rule_info->name, rule_name,
			    	     GBF_RULE_NAME_LENGTH)==0)) {
				/* The rule was found. */
				list_del(&rule_info->list);
				kfree(rule_info);
				mutex_unlock(&rules_list_lock);
				return;
			}
		}
	}
	/* The rule was not found. Try again. */
	mutex_unlock(&rules_list_lock);
	schedule();
	goto repeat;
}

void gbf_rules_list_cleanup(void)
{
	mutex_lock(&rules_list_lock);
	while (!list_empty(&rules_list)) {
		struct rule_info *rule_info =
			list_first_entry(&rules_list, struct rule_info, list);

		list_del(&rule_info->list);
		kfree(rule_info);
	}
	mutex_unlock(&rules_list_lock);
}

int gbf_sysfs_init(const char *module_name)
{
	int ret = 0;

	mutex_init(&rules_list_lock);

	gbf_dev_class = class_create(THIS_MODULE, module_name);
	if (IS_ERR(gbf_dev_class))
		return PTR_ERR(gbf_dev_class);

	gbf_dev = device_create_with_groups(gbf_dev_class, NULL,
					    MKDEV(0, 0), NULL,
					    gbf_attr_groups, "ctl");
	if (IS_ERR(gbf_dev)) {
		ret =  PTR_ERR(gbf_dev);
		goto fail_device;
	}
	return 0;
fail_device:
	class_destroy(gbf_dev_class);
	return ret;
}

void gbf_sysfs_done(void)
{
	kobject_del(gbf_rules_kobj);
	kobject_put(gbf_rules_kobj);
	device_destroy(gbf_dev_class, MKDEV(0, 0));
	class_destroy(gbf_dev_class);

	gbf_rules_list_cleanup();
}
