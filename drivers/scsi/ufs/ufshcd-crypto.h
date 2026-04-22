/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2019 Google LLC
 */

#ifndef _UFSHCD_CRYPTO_H
#define _UFSHCD_CRYPTO_H

#include "ufshcd.h"
#include "ufshci.h"
#include <linux/keyslot-manager.h>

#ifndef UFSHCD_QUIRK_KEYS_IN_PRDT
#define UFSHCD_QUIRK_KEYS_IN_PRDT	0
#endif

#ifdef CONFIG_SCSI_UFS_CRYPTO

static inline bool ufshcd_hba_is_crypto_supported(struct ufs_hba *hba)
{
	return hba->crypto_capabilities.reg_val;
}

static inline int ufshcd_num_keyslots(struct ufs_hba *hba)
{
	return hba->crypto_capabilities.config_count + 1;
}

static inline bool ufshcd_keyslot_valid(struct ufs_hba *hba,
					unsigned int slot)
{
	return slot < ufshcd_num_keyslots(hba);
}

static inline bool ufshcd_is_crypto_enabled(struct ufs_hba *hba)
{
	return hba->caps & UFSHCD_CAP_CRYPTO;
}

static inline bool ufshcd_lrbp_crypto_enabled(struct ufshcd_lrb *lrbp)
{
	return lrbp->crypto_enable;
}

static inline void
ufshcd_prepare_req_desc_hdr_crypto(struct ufshcd_lrb *lrbp, u32 *dword_0,
				   u32 *dword_1, u32 *dword_3)
{
	if (ufshcd_lrbp_crypto_enabled(lrbp)) {
		*dword_0 |= UTP_REQ_DESC_CRYPTO_ENABLE_CMD;
		*dword_0 |= lrbp->crypto_key_slot;
		*dword_1 = lower_32_bits(lrbp->data_unit_num);
		*dword_3 = upper_32_bits(lrbp->data_unit_num);
	}
}

static inline void ufshcd_crypto_clear_prdt(struct ufs_hba *hba,
					    struct ufshcd_lrb *lrbp)
{
	if (!(hba->quirks & UFSHCD_QUIRK_KEYS_IN_PRDT))
		return;

	if (!lrbp->cmd || !lrbp->cmd->request ||
	    !lrbp->cmd->request->bio ||
	    !lrbp->cmd->request->bio->bi_crypt_context)
		return;

	memzero_explicit(lrbp->ucd_prdt_ptr,
			 hba->sg_entry_size * scsi_sg_count(lrbp->cmd));
}

int ufshcd_crypto_cap_find(struct ufs_hba *hba,
			   enum blk_crypto_mode_num crypto_mode,
			   unsigned int data_unit_size);

enum blk_crypto_mode_num
ufshcd_blk_crypto_mode_num_for_alg_dusize(enum ufs_crypto_alg ufs_crypto_alg,
					  enum ufs_crypto_key_size key_size);

void ufshcd_crypto_enable_spec(struct ufs_hba *hba);
void ufshcd_crypto_disable_spec(struct ufs_hba *hba);
int ufshcd_hba_init_crypto_spec(struct ufs_hba *hba,
				const struct keyslot_mgmt_ll_ops *ksm_ops);
void ufshcd_crypto_setup_rq_keyslot_manager_spec(struct ufs_hba *hba,
						 struct request_queue *q);
void ufshcd_crypto_destroy_rq_keyslot_manager_spec(struct ufs_hba *hba,
						   struct request_queue *q);
int ufshcd_prepare_lrbp_crypto_spec(struct ufs_hba *hba,
				    struct scsi_cmnd *cmd,
				    struct ufshcd_lrb *lrbp);

void ufshcd_crypto_enable(struct ufs_hba *hba);
void ufshcd_crypto_disable(struct ufs_hba *hba);
int ufshcd_hba_init_crypto(struct ufs_hba *hba);
void ufshcd_crypto_setup_rq_keyslot_manager(struct ufs_hba *hba,
					    struct request_queue *q);
void ufshcd_crypto_destroy_rq_keyslot_manager(struct ufs_hba *hba,
					      struct request_queue *q);
int ufshcd_prepare_lrbp_crypto(struct ufs_hba *hba,
			       struct scsi_cmnd *cmd,
			       struct ufshcd_lrb *lrbp);
int ufshcd_map_sg_crypto(struct ufs_hba *hba, struct ufshcd_lrb *lrbp);
int ufshcd_complete_lrbp_crypto(struct ufs_hba *hba,
				struct scsi_cmnd *cmd,
				struct ufshcd_lrb *lrbp);
void ufshcd_crypto_debug(struct ufs_hba *hba);
int ufshcd_crypto_suspend(struct ufs_hba *hba, enum ufs_pm_op pm_op);
int ufshcd_crypto_resume(struct ufs_hba *hba, enum ufs_pm_op pm_op);
void ufshcd_crypto_set_vops(struct ufs_hba *hba,
			    struct ufs_hba_crypto_variant_ops *crypto_vops);

#else /* CONFIG_SCSI_UFS_CRYPTO */

static inline bool ufshcd_hba_is_crypto_supported(struct ufs_hba *hba)
{
	return false;
}

static inline int ufshcd_num_keyslots(struct ufs_hba *hba)
{
	return 0;
}

static inline bool ufshcd_keyslot_valid(struct ufs_hba *hba,
					unsigned int slot)
{
	return false;
}

static inline bool ufshcd_is_crypto_enabled(struct ufs_hba *hba)
{
	return false;
}

static inline bool ufshcd_lrbp_crypto_enabled(struct ufshcd_lrb *lrbp)
{
	return false;
}

static inline void
ufshcd_prepare_req_desc_hdr_crypto(struct ufshcd_lrb *lrbp, u32 *dword_0,
				   u32 *dword_1, u32 *dword_3) { }

static inline void ufshcd_crypto_clear_prdt(struct ufs_hba *hba,
					    struct ufshcd_lrb *lrbp) { }

static inline int ufshcd_crypto_cap_find(struct ufs_hba *hba,
					 enum blk_crypto_mode_num crypto_mode,
					 unsigned int data_unit_size)
{
	return -EINVAL;
}

static inline enum blk_crypto_mode_num
ufshcd_blk_crypto_mode_num_for_alg_dusize(enum ufs_crypto_alg ufs_crypto_alg,
					  enum ufs_crypto_key_size key_size)
{
	return BLK_ENCRYPTION_MODE_INVALID;
}

static inline void ufshcd_crypto_enable_spec(struct ufs_hba *hba) { }
static inline void ufshcd_crypto_disable_spec(struct ufs_hba *hba) { }
static inline int
ufshcd_hba_init_crypto_spec(struct ufs_hba *hba,
			    const struct keyslot_mgmt_ll_ops *ksm_ops)
{
	return 0;
}
static inline void
ufshcd_crypto_setup_rq_keyslot_manager_spec(struct ufs_hba *hba,
					    struct request_queue *q) { }
static inline void
ufshcd_crypto_destroy_rq_keyslot_manager_spec(struct ufs_hba *hba,
					      struct request_queue *q) { }
static inline int
ufshcd_prepare_lrbp_crypto_spec(struct ufs_hba *hba,
				struct scsi_cmnd *cmd,
				struct ufshcd_lrb *lrbp)
{
	return 0;
}

static inline void ufshcd_crypto_enable(struct ufs_hba *hba) { }
static inline void ufshcd_crypto_disable(struct ufs_hba *hba) { }
static inline int ufshcd_hba_init_crypto(struct ufs_hba *hba) { return 0; }
static inline void
ufshcd_crypto_setup_rq_keyslot_manager(struct ufs_hba *hba,
				       struct request_queue *q) { }
static inline void
ufshcd_crypto_destroy_rq_keyslot_manager(struct ufs_hba *hba,
					 struct request_queue *q) { }
static inline int
ufshcd_prepare_lrbp_crypto(struct ufs_hba *hba,
			   struct scsi_cmnd *cmd,
			   struct ufshcd_lrb *lrbp)
{
	return 0;
}
static inline int
ufshcd_map_sg_crypto(struct ufs_hba *hba, struct ufshcd_lrb *lrbp)
{
	return 0;
}
static inline int
ufshcd_complete_lrbp_crypto(struct ufs_hba *hba,
			    struct scsi_cmnd *cmd,
			    struct ufshcd_lrb *lrbp)
{
	return 0;
}
static inline void ufshcd_crypto_debug(struct ufs_hba *hba) { }
static inline int ufshcd_crypto_suspend(struct ufs_hba *hba,
					enum ufs_pm_op pm_op)
{
	return 0;
}
static inline int ufshcd_crypto_resume(struct ufs_hba *hba,
				       enum ufs_pm_op pm_op)
{
	return 0;
}
static inline void
ufshcd_crypto_set_vops(struct ufs_hba *hba,
		       struct ufs_hba_crypto_variant_ops *crypto_vops) { }

#endif /* CONFIG_SCSI_UFS_CRYPTO */

#endif /* _UFSHCD_CRYPTO_H */
