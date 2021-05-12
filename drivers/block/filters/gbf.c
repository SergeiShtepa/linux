// SPDX-License-Identifier: GPL-2.0-only

#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/blkdev.h>
#include "gbdevflt.h"

#define MODULE_NAME "gbdevflt"

#ifdef GBF_DEFAULT_FILTER
static uint g_bdev_mj = 7;
static uint g_bdev_mn = 1;
#endif

LIST_HEAD(ctx_list);
struct mutex ctx_list_lock;

#define GBF_RULE_NAME_LENGTH 31
struct gbf_rule {
	struct list_head list;
	char name[GBF_RULE_NAME_LENGTH+1];
	gbf_rule_consent_t consent;
	gbf_rule_join_t join;
	struct gbf_rule_range *range;
	struct gbf_rule_owner *owner;
};

static inline void gbf_rule_free(struct gbf_rule *rule)
{
	if (!rule)
		return;

	list_del(&rule->list);
	kfree(rule->range);
	kfree(rule->owner);
	kfree(rule);
}

static inline struct gbf_rule *gbf_rule_new(
	const char *rule_name,
	const gbf_rule_consent_t consent,
	const gbf_rule_join_t join,
	const struct gbf_rule_range *rule_range,
	const struct gbf_rule_owner *rule_owner)
{
	struct gbf_rule *rule;

	rule = kzalloc(sizeof(struct gbf_rule), GFP_KERNEL);
	if (!rule)
		return NULL;

	if (rule_range) {
		rule->range = kzalloc(sizeof(struct gbf_rule_range), GFP_KERNEL);
		if (!rule->range)
			goto fail;

		memcpy(rule->range, rule_range, sizeof(struct gbf_rule_range));
	}
	if (rule_owner) {
		rule->owner = kzalloc(sizeof(struct gbf_rule_owner), GFP_KERNEL);
		if (!rule->owner)
			goto fail;

		memcpy(rule->owner, rule_owner, sizeof(struct gbf_rule_owner));
	}

	strncpy(rule->name, rule_name, GBF_RULE_NAME_LENGTH);
	rule->consent = consent;
	rule->join = join;

	return rule;
fail:
	kfree(rule->range);
	kfree(rule->owner);
	kfree(rule);
	return NULL;
}

void inline gbf_rules_cleanup(struct list_head *rules_list)
{
	struct gbf_rule *rule;

	while(!list_empty(rules_list)) {
		rule = list_first_entry(rules_list, struct gbf_rule, list);
		gbf_rule_free(rule);
	}
}

static inline bool gbf_rule_range_apply(struct gbf_rule_range *range,
					sector_t bio_first, sector_t bio_last)
{
	return (bio_first <= range->last) && (bio_last >= range->first);
}

static inline bool gbf_rule_owner_apply(struct gbf_rule_owner *owner,
					bio_end_io_t *bi_end_io)
{
	return (owner->bi_end_io == bi_end_io);
}

static flt_st_t gbf_rule_apply(struct gbf_rule *rule, struct bio *bio)
{
	bool is_apply;
	unsigned char check = 0;
	unsigned char condition = 0;

	if (rule->range) {
		check |= 1;
		if (gbf_rule_range_apply(rule->range, bio_offset(bio), bio_end_sector(bio)-1))
			condition |= 1;
	}

	if (rule->owner) {
		check |= 2;
		if (gbf_rule_owner_apply(rule->owner, bio->bi_end_io))
			condition |= 2;
	}

	if ((check == 0))
		is_apply = true;
	else if ((check == 3) && (rule->join == GBF_RULE_JOIN_AND))
		is_apply = (condition == 3);
	else
		is_apply = !!condition;

	if (((rule->consent == GBF_RULE_CONSENT_ALLOW) && is_apply) ||
	    ((rule->consent == GBF_RULE_CONSENT_DENY) && !is_apply))
		return FLT_ST_PASS;

	bio->bi_status = BLK_STS_NOTSUPP;
	bio_endio(bio);
	return FLT_ST_COMPLETE;
}

struct gbf_ctx {
	struct list_head list;
	dev_t dev_id;
	struct list_head rules_list;
};

static inline struct gbf_ctx *gbf_ctx_new(void )
{
	struct gbf_ctx * ctx;

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

static inline struct gbf_rule *gbf_ctx_find_rule(struct gbf_ctx *ctx,
						 const char* rule_name)
{
	struct gbf_rule *rule = NULL;

	if (list_empty(&ctx->rules_list))
		return NULL;

	list_for_each_entry(rule, &ctx->rules_list, list)
		if (strncmp(rule->name, rule_name, GBF_RULE_NAME_LENGTH) == 0)
			return rule;

	return NULL;
}

static flt_st_t gbf_submit_bio_cb(struct bio *bio, void* gbf_ctx)
{
	flt_st_t st = FLT_ST_PASS;
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

static void gbf_detach_cb(void* gbf_ctx)
{
	struct gbf_ctx *ctx = gbf_ctx;

	gbf_rules_cleanup(&ctx->rules_list);

	gbf_ctx_free(ctx);
}

const static struct filter_operations gbf_fops = {
	.submit_bio_cb = gbf_submit_bio_cb,
	.detach_cb = gbf_detach_cb
};

/**
 *
 */
int gbf_rule_add(dev_t dev_id, const char *rule_name,
		const gbf_rule_consent_t consent,
		const gbf_rule_add_t rule_add,
		const gbf_rule_join_t join,
		const struct gbf_rule_range *rule_range,
		const struct gbf_rule_owner *rule_owner)
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

	rule = gbf_rule_new(rule_name, consent, join, rule_range, rule_owner);
	if (!rule) {
		ret = -ENOMEM;
		goto out;
	}

	if (rule_add == GBF_RULE_ADD_HEAD)
		list_add(&rule->list, &ctx->rules_list);
	else
		list_add_tail(&rule->list, &ctx->rules_list);

out:
	bdev_filter_unlock(bdev);

	return ret;
}
EXPORT_SYMBOL_GPL(gbf_rule_add);

/**
 *
 */
int gbf_rule_del(dev_t dev_id, const char* rule_name)
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
		pr_err("Filter [%s] is not exist\n", MODULE_NAME);
		pr_err("Failed to delete rule [%s]\n", rule_name);
		ret = -ENXIO;
		goto out;
	}

	rule = gbf_ctx_find_rule(ctx, rule_name);
	if (rule) {
		ret = -ENOENT;
		goto out;
	}

	gbf_rule_free(rule);
out:
	bdev_filter_unlock(bdev);

	return ret;
}
EXPORT_SYMBOL_GPL(gbf_rule_del);

static int __init gbf_init(void)
{
	int ret = 0;

	mutex_init(&ctx_list_lock);

#ifdef GBF_DEFAULT_FILTER
	ret = gbf_rule_add(MKDEV(g_bdev_mj, g_bdev_mn), "gbf_test",
			GBF_RULE_CONSENT_DENY,
			GBF_RULE_ADD_HEAD,
			GBF_RULE_JOIN_OR, NULL, NULL);
#endif
	return ret;
}

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

static void __exit gbf_exit(void)
{
	mutex_lock(&ctx_list_lock);
	while(!list_empty(&ctx_list)){
		struct gbf_ctx *ctx;

		ctx = list_first_entry(&ctx_list, struct gbf_ctx, list);

		gfb_cleanup(ctx->dev_id);
		gbf_ctx_free(ctx);
	}
	mutex_unlock(&ctx_list_lock);
}

module_init(gbf_init);
module_exit(gbf_exit);

#ifdef GBF_DEFAULT_FILTER
module_param_named( bdev_mj, g_bdev_mj, uint, 0644 );
MODULE_PARM_DESC( bdev_mj, "Major number of filtering block device." );
module_param_named( bdev_mn, g_bdev_mn, uint, 0644 );
MODULE_PARM_DESC( bdev_mn, "Minor number of filtering block device." );
#endif

MODULE_DESCRIPTION("Generic Block Device Filter");
MODULE_AUTHOR("Oracle Corporation");
MODULE_LICENSE("GPL");
