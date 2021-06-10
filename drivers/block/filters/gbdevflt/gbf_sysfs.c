// SPDX-License-Identifier: GPL-2.0
/*
 * Implements module management via sysfs files.
 */
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/device.h>
#include <linux/blkdev.h>
#include <linux/parser.h>
#include "gbf_sysfs.h"
#include "gbf.h"

struct mutex sysfs_rules_lock;

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

	return gbf_rule_add(dev_id, opt->name, opt->exp, add_to);
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

	return gbf_rule_remove(dev_id, opt->name);
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

static void rule_file_add(char *name, char *path, char *exp)
{
	/* TODO: add rule file to sysfs */
	mutex_lock(&sysfs_rules_lock);

	mutex_unlock(&sysfs_rules_lock);
}

static void rule_file_remove(char *name, char *path)
{
	/* TODO: remove rule file from sysfs */
	mutex_lock(&sysfs_rules_lock);

	mutex_unlock(&sysfs_rules_lock);
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
		pr_err("Failed to execute add command with options %s\n", options);
		goto out;
	}
	rule_file_add(opt.name, opt.path, opt.exp);
out:
	rule_add_free(&opt);
	kfree(options);
	if (ret)
		return (ssize_t)ret;

	return count;
};

static ssize_t rule_remove_store(struct class *class, struct class_attribute *attr,
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
		pr_err("Failed to execute remove command with options %s\n", options);
		goto out;
	}
	rule_file_remove(opt.name, opt.name);
out:
	rule_remove_free(&opt);
	kfree(options);
	if (ret)
		return (ssize_t)ret;

	return count;
};

CLASS_ATTR_WO(rule_add);
CLASS_ATTR_WO(rule_remove);

static struct attribute *gbf_attrs[] = {
	&class_attr_rule_add.attr,
	&class_attr_rule_remove.attr,
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

int gbf_sysfs_init(const char *module_name)
{
	int ret = 0;

	mutex_init(&sysfs_rules_lock);

	gbf_dev_class = class_create(THIS_MODULE, module_name);
	if (IS_ERR(gbf_dev_class))
		return PTR_ERR(gbf_dev_class);

	//gbf_dev = device_create(gbf_dev_class, NULL,
	//			  MKDEV(0, 0), NULL, "ctl");
	gbf_dev = device_create_with_groups(gbf_dev_class, NULL,
					MKDEV(0, 0), NULL,
					gbf_attr_groups, "ctl");
	if (IS_ERR(gbf_dev)) {
		ret =  PTR_ERR(gbf_dev);
		goto fail_device;
	}

	/* should content actual rules */
	gbf_rules_kobj = kobject_create_and_add("rules", &gbf_dev->kobj);
	if (!gbf_rules_kobj) {
		ret = -ENOMEM;
		goto fail;
	}

	return 0;
fail:
	device_destroy(gbf_dev_class, MKDEV(0, 0));
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
}
