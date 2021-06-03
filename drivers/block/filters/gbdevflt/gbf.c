// SPDX-License-Identifier: GPL-2.0-only
/*
 * This file contains the basic logic for working with the rules.
 */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/blkdev.h>
#include <linux/delay.h>
#include "rpnexp.h"
#include "gbf.h"
#include "gbf_sysfs.h"

#define MODULE_NAME "gbdevflt"

LIST_HEAD(ctx_list);

static int gfp_rule_range(struct rpn_stack *stack, void *ctx)
{
	int ret;
	struct bio *bio = ctx;
	sector_t ofs;
	sector_t len;
	u64 result;

	ret = rpn_stack_pop(stack, &len);
	if (unlikely(ret))
		return ret;

	ret = rpn_stack_pop(stack, &ofs);
	if (unlikely(ret))
		return ret;

	result = (bio_offset(bio) <= (ofs + len - 1)) &&
		 (bio_end_sector(bio) > ofs);

	ret = rpn_stack_push(stack, result);
	if (unlikely(ret))
		return ret;

	return 0;
};

static int gfp_rule_owner(struct rpn_stack *stack, void *ctx)
{
	int ret;
	struct bio *bio = ctx;
	u64 owner;
	u64 result;

	ret = rpn_stack_pop(stack, &owner);
	if (unlikely(ret))
		return ret;

	result = (void *)bio->bi_end_io == (void *)owner;

	ret = rpn_stack_push(stack, result);
	if (unlikely(ret))
		return ret;

	return 0;
};

static int gfp_rule_read(struct rpn_stack *stack, void *ctx)
{
	int ret;
	struct bio *bio = ctx;
	u64 result;

	result = bio_has_data(bio) && !op_is_write(bio_op(bio));

	ret = rpn_stack_push(stack, result);
	if (unlikely(ret))
		return ret;

	return 0;
};

static int gfp_rule_write(struct rpn_stack *stack, void *ctx)
{
	int ret;
	struct bio *bio = ctx;
	u64 result;

	result = bio_has_data(bio) && op_is_write(bio_op(bio));

	ret = rpn_stack_push(stack, result);
	if (unlikely(ret))
		return ret;

	return 0;
};

static int gfp_rule_sleep(struct rpn_stack *stack, void *ctx)
{
	int ret;
	u64 usecs;

	ret = rpn_stack_pop(stack, &usecs);
	if (unlikely(ret))
		return ret;

	fsleep(usecs);

	ret = rpn_stack_push(stack, 1); /* always pass */
	if (unlikely(ret))
		return ret;

	return 0;
};

const struct rpn_ext_op gbf_op_dict[] = {
	{"range", gfp_rule_range},
	{"owner", gfp_rule_owner},
	{"read", gfp_rule_read},
	{"write", gfp_rule_write},
	{"sleep", gfp_rule_sleep},
	{NULL, NULL}
};

struct gbf_rule {
	struct list_head list;
	char name[GBF_RULE_NAME_LENGTH+1];
	struct rpn_bytecode bytecode;
};

static inline struct gbf_rule *gbf_rule_new(const char *rule_name,
					    char *rule_exp)
{
	int ret;
	struct gbf_rule *rule;

	rule = kzalloc(sizeof(struct gbf_rule), GFP_KERNEL);
	if (!rule)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&rule->list);
	strncpy(rule->name, rule_name, GBF_RULE_NAME_LENGTH);

	ret = rpn_parse_expression(rule_exp, gbf_op_dict, &rule->bytecode);
	if (ret) {
		pr_err("Failed to parse rule expression: \"%s\"\n", rule_exp);

		kfree(rule);
		return ERR_PTR(ret);
	}

	return rule;
}

static inline void gbf_rule_free(struct gbf_rule *rule)
{
	list_del(&rule->list);

	rpn_release_bytecode(&rule->bytecode);
	kfree(rule);
}

static inline void gbf_rules_cleanup(struct list_head *rules_list)
{
	struct gbf_rule *rule;

	while (!list_empty(rules_list)) {
		rule = list_first_entry(rules_list, struct gbf_rule, list);
		gbf_rule_free(rule);
	}
}

static int gbf_rule_apply(struct gbf_rule *rule, struct bio *bio)
{
	int ret = 0;
	u64 result;

	RPN_STACK(stack, CONFIG_GBDEVFLT_STACK_DEPTH);

	ret = rpn_execute_bytecode(rule->bytecode, gbf_op_dict, &stack, bio);
	if (unlikely(ret)) {
		pr_err("Failed to execute rule.\n");
		goto deny;
	}

	ret = rpn_stack_pop(&stack, &result);
	if (unlikely(ret)) {
		pr_err("Cannot get rules result.\n");
		goto deny;
	}

	if (result)
		return FLT_ST_PASS;
deny:
	bio->bi_status = BLK_STS_NOTSUPP;
	bio_endio(bio);
	return FLT_ST_COMPLETE;
}

struct gbf_ctx {
	struct list_head list;
	dev_t dev_id;
	struct list_head rules_list;
};

static inline struct gbf_ctx *gbf_ctx_new(dev_t dev_id)
{
	struct gbf_ctx *ctx;

	ctx = kzalloc(sizeof(struct gbf_ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	INIT_LIST_HEAD(&ctx->rules_list);
	ctx->dev_id = dev_id;

	INIT_LIST_HEAD(&ctx->list);
	list_add(&ctx->list, &ctx_list);

	return ctx;
}

static inline void gbf_ctx_free(struct gbf_ctx *ctx)
{
	list_del(&ctx->list);
	kfree(ctx);
}

static inline struct gbf_rule *gbf_ctx_find_rule(struct gbf_ctx *ctx,
					  const char *rule_name)
{
	struct gbf_rule *rule = NULL;

	if (list_empty(&ctx->rules_list))
		return NULL;

	list_for_each_entry(rule, &ctx->rules_list, list)
		if (strncmp(rule->name, rule_name, GBF_RULE_NAME_LENGTH) == 0)
			return rule;

	return NULL;
}

static inline struct gbf_rule *gbf_ctx_first_rule(struct gbf_ctx *ctx)
{
	if (list_empty(&ctx->rules_list))
		return NULL;

	return list_first_entry(&ctx->rules_list, struct gbf_rule, list);
}

static int gbf_submit_bio_cb(struct bio *bio, void *gbf_ctx)
{
	int st = FLT_ST_PASS;
	struct gbf_ctx *ctx = gbf_ctx;

	if (!list_empty(&ctx->rules_list)) {
		struct gbf_rule *rule;

		list_for_each_entry(rule, &ctx->rules_list, list) {
			st = gbf_rule_apply(rule, bio);
			if (st != FLT_ST_PASS)
				break;
		}
	}

	return st;
}

static void gbf_detach_cb(void *gbf_ctx)
{
	struct gbf_ctx *ctx = gbf_ctx;

	gbf_rules_cleanup(&ctx->rules_list);

	gbf_ctx_free(ctx);
}

static const struct filter_operations gbf_fops = {
	.submit_bio_cb = gbf_submit_bio_cb,
	.detach_cb = gbf_detach_cb
};

/**
 * gbf_rule_add() - add rule to generic block device filter
 * @dev_id: block device id
 * @rule_name: unique rule name
 * @rule_exp: rule expression in RPN
 * @add_to_head: boolean attribute allows to add a rule to the beginning
 * of the rule queue for a given block device.
 *
 * Description:
 * The added rule will be executed for each bio of this block device.
 * @rule_name must be unique to for this device. The length of the name is
 * limited by GBF_RULE_NAME_LENGTH.
 * @rule_exp it's a expression in reverse polish notation (RPN).
 * Basic arithmetic and logical operations are supported by build-in rpnexp
 * operands. External "range", "owner", "read" and "write" operations are
 * implemented specifically for processing bio.
 *
 * Example:
 * Block writes to the first 8 sectors of the block device.
 * rpn expression: 0 8 range write && !
 * equivalent ordinary arithmetic-logical expression: !(range(0,8) && write)
 */
int gbf_rule_add(dev_t dev_id, const char *rule_name, char *rule_exp,
		 bool add_to_head)
{
	int ret = 0;
	struct  block_device *bdev;
	struct gbf_ctx *ctx;
	struct gbf_ctx *new_ctx = NULL;
	struct gbf_rule *rule;

	bdev = bdev_filter_lock(dev_id);
	if (IS_ERR(bdev)) {
		pr_err("Failed to lock device [%d:%d]\n",
			MAJOR(dev_id), MINOR(dev_id));
		return PTR_ERR(bdev);
	}

	ctx = bdev_filter_find_ctx(bdev, MODULE_NAME);
	if (IS_ERR(ctx)) {
		new_ctx = gbf_ctx_new(dev_id);
		if (!new_ctx) {
			ret = -ENOMEM;
			goto out;
		}

		ret = bdev_filter_add(bdev, MODULE_NAME, &gbf_fops, new_ctx);
		if (ret)
			goto out;

		ctx = new_ctx;
	}

	rule = gbf_ctx_find_rule(ctx, rule_name);
	if (rule) {
		ret = -EALREADY;
		goto out;
	}

	rule = gbf_rule_new(rule_name, rule_exp);
	if (IS_ERR(rule)) {
		ret = PTR_ERR(rule);
		goto out;
	}

	if (add_to_head)
		list_add(&rule->list, &ctx->rules_list);
	else
		list_add_tail(&rule->list, &ctx->rules_list);
	pr_info("Rule \"%s\" was added\n", rule_name);
out:
	if (ret) {
		if (new_ctx)
			gbf_ctx_free(new_ctx);
	}
	bdev_filter_unlock(bdev);

	return ret;
}
EXPORT_SYMBOL_GPL(gbf_rule_add);

/**
 * gbf_rule_remove() - remove rule from generic block device filter
 * @dev_id: block device id
 * @rule_name: unique rule name
 *
 */
int gbf_rule_remove(dev_t dev_id, const char *rule_name)
{
	int ret = 0;
	struct block_device *bdev;
	struct gbf_ctx *ctx;
	struct gbf_rule *rule;

	bdev = bdev_filter_lock(dev_id);
	if (IS_ERR(bdev)) {
		pr_err("Failed to lock device [%d:%d]\n",
			MAJOR(dev_id), MINOR(dev_id));
		return PTR_ERR(bdev);
	}

	ctx = bdev_filter_find_ctx(bdev, MODULE_NAME);
	if (IS_ERR(ctx)) {
		pr_err("Filter [%s] is not exist on device [%d:%d]\n",
			MODULE_NAME, MAJOR(dev_id), MINOR(dev_id));
		pr_err("Failed to delete rule [%s]\n", rule_name);
		ret = -ENXIO;
		goto out;
	}

	if (rule_name == NULL)
		while (!list_empty(&ctx->rules_list)) {
			rule = gbf_ctx_first_rule(ctx);
			gbf_rule_free(rule);
		}
	else {
		rule = gbf_ctx_find_rule(ctx, rule_name);
		if (!rule) {
			pr_err("Rule is not exist on device [%d:%d]\n",
				MAJOR(dev_id), MINOR(dev_id));
			pr_err("Failed to delete rule [%s]\n", rule_name);
			ret = -ENOENT;
			goto out;
		}
		gbf_rule_free(rule);
	}

	if (list_empty(&ctx->rules_list)) {
		ret = bdev_filter_del(bdev, MODULE_NAME);
		if (ret)
			goto out;
	}
	pr_info("Rule \"%s\" was removed\n", rule_name);
out:
	bdev_filter_unlock(bdev);

	return ret;
}
EXPORT_SYMBOL_GPL(gbf_rule_remove);

static bool gbf_take_first_own_dev(dev_t *dev_id)
{
	struct gbf_ctx *ctx;

	if (list_empty(&ctx_list))
		return false;

	ctx = list_first_entry(&ctx_list, struct gbf_ctx, list);
	*dev_id = ctx->dev_id;
	return true;
}

static void gbf_cleanup(dev_t dev_id)
{
	int ret;
	struct block_device *bdev;

	bdev = bdev_filter_lock(dev_id);
	if (IS_ERR(bdev)) {
		pr_err("Failed to lock device [%d:%d]\n",
			MAJOR(dev_id), MINOR(dev_id));
		return;
	}

	ret = bdev_filter_del(bdev, MODULE_NAME);
	if (ret)
		pr_err("Failed to detach %s from device [%d:%d]\n",
			MODULE_NAME, MAJOR(dev_id), MINOR(dev_id));

	bdev_filter_unlock(bdev);
}

static void print_op_dict(const struct rpn_ext_op *op_dict)
{
	size_t inx = 0;

	pr_info("Extended operations dictionary content:\n");
	while (op_dict[inx].name != NULL) {
		pr_info(" %s\n", op_dict[inx].name);
		inx++;
	}
}

static int __init gbf_init(void)
{
	int ret = 0;

	pr_info("Init \"%s\" module.\n", MODULE_NAME);
	ret = gbf_sysfs_init(MODULE_NAME);
	if (ret) {
		pr_err("Failed to initialize sysfs interface.\n");
		return ret;
	}

	print_op_dict(gbf_op_dict);

	return ret;
}

static void __exit gbf_exit(void)
{
	dev_t dev_id;

	pr_info("Exit \"%s\" module.\n", MODULE_NAME);
	gbf_sysfs_done();

	while (gbf_take_first_own_dev(&dev_id))
		gbf_cleanup(dev_id);
}

module_init(gbf_init);
module_exit(gbf_exit);

MODULE_DESCRIPTION("Generic Block Device Filter");
MODULE_AUTHOR("Sergei Shtepa");
MODULE_LICENSE("GPL");
