// SPDX-License-Identifier: GPL-2.0-only
/*
 * This file contains the basic logic for working with the rules.
 */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/blkdev.h>
#include "rpnexp.h"
#include "gbf.h"
#include "gbf_sysfs.h"

#define MODULE_NAME "gbdevflt"

LIST_HEAD(ctx_list);
struct mutex ctx_list_lock;

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

const struct rpn_ext_op gbf_op_dict[] = {
	{"range", gfp_rule_range},
	{"owner", gfp_rule_owner},
	{"read", gfp_rule_read},
	{"write", gfp_rule_write},
	{NULL, NULL}
};

struct gbf_rule {
	struct list_head list;
	char name[GBF_RULE_NAME_LENGTH+1];
	u64 *bytecode;
};

static inline struct gbf_rule *gbf_rule_new(const char *rule_name,
					    char *rule_exp)
{
	struct gbf_rule *rule;

	rule = kzalloc(sizeof(struct gbf_rule), GFP_KERNEL);
	if (!rule)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&rule->list);
	strncpy(rule->name, rule_name, GBF_RULE_NAME_LENGTH);

	rule->bytecode = rpn_parse_expression(rule_exp, gbf_op_dict);
	if (IS_ERR(rule->bytecode)) {
		pr_err("Failed to parse rule expression: \"%s\"\n", rule_exp);

		kfree(rule);
		return ERR_PTR(PTR_ERR(rule->bytecode));
	}

	return rule;
}

static inline void gbf_rule_free(struct gbf_rule *rule)
{
	list_del(&rule->list);

	kfree(rule->bytecode);
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

	RPN_STACK(st, 8);

	ret = rpn_execute(rule->bytecode, &st, bio);
	if (unlikely(ret)) {
		pr_err("Failed to execute rule.");
		goto deny;
	}

	ret = rpn_stack_pop(&st, &result);
	if (unlikely(ret)) {
		pr_err("Cannot get rules result.");
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

static inline struct gbf_ctx *gbf_ctx_new(void)
{
	struct gbf_ctx *ctx;

	ctx = kzalloc(sizeof(struct gbf_ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	INIT_LIST_HEAD(&ctx->rules_list);

	return ctx;
}

static inline void gbf_ctx_free(struct gbf_ctx *ctx)
{
	list_del(&ctx->list);
	kfree(ctx);
}

static struct gbf_rule *gbf_ctx_find_rule(struct gbf_ctx *ctx,
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
	struct gbf_rule *rule;

	bdev = bdev_filter_lock(dev_id);
	if (IS_ERR(bdev))
		return PTR_ERR(bdev);

	ctx = bdev_filter_find_ctx(bdev, MODULE_NAME);
	if (IS_ERR(ctx)) {
		ctx = gbf_ctx_new();
		if (!ctx) {
			ret = -ENOMEM;
			goto out;
		}

		ret = bdev_filter_add(bdev, MODULE_NAME, &gbf_fops, ctx);
		if (ret)
			goto out;

		mutex_lock(&ctx_list_lock);
		list_add(&ctx->list, &ctx_list);
		mutex_unlock(&ctx_list_lock);
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

out:
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
	if (IS_ERR(bdev))
		return PTR_ERR(bdev);

	ctx = bdev_filter_find_ctx(bdev, MODULE_NAME);
	if (IS_ERR(ctx)) {
		pr_err("Filter [%s] is not exist on device [%d:%d]\n",
			MODULE_NAME, MAJOR(dev_id), MINOR(dev_id));
		pr_err("Failed to delete rule [%s]\n", rule_name);
		ret = -ENXIO;
		goto out;
	}

	rule = gbf_ctx_find_rule(ctx, rule_name);
	if (!rule) {
		pr_err("Rule is not exist on device [%d:%d]\n",
			MAJOR(dev_id), MINOR(dev_id));
		pr_err("Failed to delete rule [%s]\n", rule_name);
		ret = -ENOENT;
		goto out;
	}

	gbf_rule_free(rule);
out:
	bdev_filter_unlock(bdev);

	return ret;
}
EXPORT_SYMBOL_GPL(gbf_rule_remove);


static void gfb_cleanup(dev_t dev_id)
{
	int ret;
	struct block_device *bdev;

	bdev = bdev_filter_lock(dev_id);
	if (IS_ERR(bdev))
		return;

	ret = bdev_filter_del(bdev, MODULE_NAME);
	if (ret)
		pr_err("Failed to detach Generic Block Device Filter from device [%d:%d]",
			MAJOR(dev_id), MINOR(dev_id));

	bdev_filter_unlock(bdev);
}

static int __init gbf_init(void)
{
	int ret = 0;

	mutex_init(&ctx_list_lock);

	ret = gbf_sysfs_init(MODULE_NAME);
	if (ret) {
		pr_err("Failed to initialize sysfs interface.");
		return ret;
	}

	return ret;
}

static void __exit gbf_exit(void)
{
	mutex_lock(&ctx_list_lock);
	while (!list_empty(&ctx_list)){
		struct gbf_ctx *ctx;

		ctx = list_first_entry(&ctx_list, struct gbf_ctx, list);

		gfb_cleanup(ctx->dev_id);
		gbf_ctx_free(ctx);
	}
	mutex_unlock(&ctx_list_lock);

	gbf_sysfs_done();
}

module_init(gbf_init);
module_exit(gbf_exit);

MODULE_DESCRIPTION("Generic Block Device Filter");
MODULE_AUTHOR("Oracle Corporation");
MODULE_LICENSE("GPL");
