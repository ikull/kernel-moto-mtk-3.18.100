/*
 * (C) 2007 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/gen_stats.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_rateest.h>
#include <net/netfilter/xt_rateest.h>


<<<<<<< HEAD
static bool
xt_rateest_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_rateest_match_info *info = par->matchinfo;
	struct gnet_stats_rate_est64 *r;
	u_int32_t bps1, bps2, pps1, pps2;
	bool ret = true;

	spin_lock_bh(&info->est1->lock);
	r = &info->est1->rstats;
	if (info->flags & XT_RATEEST_MATCH_DELTA) {
		bps1 = info->bps1 >= r->bps ? info->bps1 - r->bps : 0;
		pps1 = info->pps1 >= r->pps ? info->pps1 - r->pps : 0;
	} else {
		bps1 = r->bps;
		pps1 = r->pps;
	}
	spin_unlock_bh(&info->est1->lock);

	if (info->flags & XT_RATEEST_MATCH_ABS) {
		bps2 = info->bps2;
		pps2 = info->pps2;
	} else {
		spin_lock_bh(&info->est2->lock);
		r = &info->est2->rstats;
		if (info->flags & XT_RATEEST_MATCH_DELTA) {
			bps2 = info->bps2 >= r->bps ? info->bps2 - r->bps : 0;
			pps2 = info->pps2 >= r->pps ? info->pps2 - r->pps : 0;
		} else {
			bps2 = r->bps;
			pps2 = r->pps;
=======
#define RATEEST_HSIZE	16
static struct hlist_head rateest_hash[RATEEST_HSIZE] __read_mostly;
static unsigned int jhash_rnd __read_mostly;
static bool rnd_inited __read_mostly;

static unsigned int xt_rateest_hash(const char *name)
{
	return jhash(name, FIELD_SIZEOF(struct xt_rateest, name), jhash_rnd) &
	       (RATEEST_HSIZE - 1);
}

static void xt_rateest_hash_insert(struct xt_rateest *est)
{
	unsigned int h;

	h = xt_rateest_hash(est->name);
	hlist_add_head(&est->list, &rateest_hash[h]);
}

static struct xt_rateest *__xt_rateest_lookup(const char *name)
{
	struct xt_rateest *est;
	unsigned int h;

	h = xt_rateest_hash(name);
	hlist_for_each_entry(est, &rateest_hash[h], list) {
		if (strcmp(est->name, name) == 0) {
			est->refcnt++;
			return est;
>>>>>>> 1fa5f92... Merge tag 'v3.18.35'>'3.18.100' by @DhirajSurvase
		}
		spin_unlock_bh(&info->est2->lock);
	}
<<<<<<< HEAD
=======

	return NULL;
}

struct xt_rateest *xt_rateest_lookup(const char *name)
{
	struct xt_rateest *est;

	mutex_lock(&xt_rateest_mutex);
	est = __xt_rateest_lookup(name);
	mutex_unlock(&xt_rateest_mutex);
	return est;
}
EXPORT_SYMBOL_GPL(xt_rateest_lookup);
>>>>>>> 1fa5f92... Merge tag 'v3.18.35'>'3.18.100' by @DhirajSurvase

	switch (info->mode) {
	case XT_RATEEST_MATCH_LT:
		if (info->flags & XT_RATEEST_MATCH_BPS)
			ret &= bps1 < bps2;
		if (info->flags & XT_RATEEST_MATCH_PPS)
			ret &= pps1 < pps2;
		break;
	case XT_RATEEST_MATCH_GT:
		if (info->flags & XT_RATEEST_MATCH_BPS)
			ret &= bps1 > bps2;
		if (info->flags & XT_RATEEST_MATCH_PPS)
			ret &= pps1 > pps2;
		break;
	case XT_RATEEST_MATCH_EQ:
		if (info->flags & XT_RATEEST_MATCH_BPS)
			ret &= bps1 == bps2;
		if (info->flags & XT_RATEEST_MATCH_PPS)
			ret &= pps1 == pps2;
		break;
	}

	ret ^= info->flags & XT_RATEEST_MATCH_INVERT ? true : false;
	return ret;
}

static int xt_rateest_mt_checkentry(const struct xt_mtchk_param *par)
{
	struct xt_rateest_match_info *info = par->matchinfo;
	struct xt_rateest *est1, *est2;
	int ret = -EINVAL;

<<<<<<< HEAD
	if (hweight32(info->flags & (XT_RATEEST_MATCH_ABS |
				     XT_RATEEST_MATCH_REL)) != 1)
		goto err1;
=======
	mutex_lock(&xt_rateest_mutex);
	est = __xt_rateest_lookup(info->name);
	if (est) {
		mutex_unlock(&xt_rateest_mutex);
		/*
		 * If estimator parameters are specified, they must match the
		 * existing estimator.
		 */
		if ((!info->interval && !info->ewma_log) ||
		    (info->interval != est->params.interval ||
		     info->ewma_log != est->params.ewma_log)) {
			xt_rateest_put(est);
			return -EINVAL;
		}
		info->est = est;
		return 0;
	}
>>>>>>> 1fa5f92... Merge tag 'v3.18.35'>'3.18.100' by @DhirajSurvase

	if (!(info->flags & (XT_RATEEST_MATCH_BPS | XT_RATEEST_MATCH_PPS)))
		goto err1;

	switch (info->mode) {
	case XT_RATEEST_MATCH_EQ:
	case XT_RATEEST_MATCH_LT:
	case XT_RATEEST_MATCH_GT:
		break;
	default:
		goto err1;
	}

	ret  = -ENOENT;
	est1 = xt_rateest_lookup(info->name1);
	if (!est1)
		goto err1;

	est2 = NULL;
	if (info->flags & XT_RATEEST_MATCH_REL) {
		est2 = xt_rateest_lookup(info->name2);
		if (!est2)
			goto err2;
	}

<<<<<<< HEAD
	info->est1 = est1;
	info->est2 = est2;
=======
	info->est = est;
	xt_rateest_hash_insert(est);
	mutex_unlock(&xt_rateest_mutex);
>>>>>>> 1fa5f92... Merge tag 'v3.18.35'>'3.18.100' by @DhirajSurvase
	return 0;

err2:
	xt_rateest_put(est1);
err1:
	mutex_unlock(&xt_rateest_mutex);
	return ret;
}

static void xt_rateest_mt_destroy(const struct xt_mtdtor_param *par)
{
	struct xt_rateest_match_info *info = par->matchinfo;

	xt_rateest_put(info->est1);
	if (info->est2)
		xt_rateest_put(info->est2);
}

static struct xt_match xt_rateest_mt_reg __read_mostly = {
	.name       = "rateest",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.match      = xt_rateest_mt,
	.checkentry = xt_rateest_mt_checkentry,
	.destroy    = xt_rateest_mt_destroy,
	.matchsize  = sizeof(struct xt_rateest_match_info),
	.me         = THIS_MODULE,
};

static int __init xt_rateest_mt_init(void)
{
	return xt_register_match(&xt_rateest_mt_reg);
}

static void __exit xt_rateest_mt_fini(void)
{
	xt_unregister_match(&xt_rateest_mt_reg);
}

MODULE_AUTHOR("Patrick McHardy <kaber@trash.net>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("xtables rate estimator match");
MODULE_ALIAS("ipt_rateest");
MODULE_ALIAS("ip6t_rateest");
module_init(xt_rateest_mt_init);
module_exit(xt_rateest_mt_fini);
