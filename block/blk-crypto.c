// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 Google LLC
 */

/*
 * Refer to Documentation/block/inline-encryption.rst for detailed explanation.
 */

#define pr_fmt(fmt) "blk-crypto: " fmt

#include <linux/blk-crypto.h>
#include <linux/blkdev.h>
#include <linux/keyslot-manager.h>
#include <linux/random.h>
#include <linux/siphash.h>
#include <linux/slab.h>

#include "blk-crypto-internal.h"

const struct blk_crypto_mode blk_crypto_modes[] = {
	[BLK_ENCRYPTION_MODE_AES_256_XTS] = {
		.cipher_str = "xts(aes)",
		.keysize = 64,
		.ivsize = 16,
	},
	[BLK_ENCRYPTION_MODE_AES_128_CBC_ESSIV] = {
		.cipher_str = "essiv(cbc(aes),sha256)",
		.keysize = 16,
		.ivsize = 16,
	},
	[BLK_ENCRYPTION_MODE_ADIANTUM] = {
		.cipher_str = "adiantum(xchacha12,aes)",
		.keysize = 32,
		.ivsize = 32,
	},
};

/* Check that all I/O segments are data unit aligned */
static int bio_crypt_check_alignment(struct bio *bio)
{
	const unsigned int data_unit_size =
				bio->bi_crypt_context->bc_key->data_unit_size;
	struct bvec_iter iter;
	struct bio_vec bv;

	bio_for_each_segment(bv, bio, iter) {
		if (!IS_ALIGNED(bv.bv_len | bv.bv_offset, data_unit_size))
			return -EIO;
	}
	return 0;
}

/**
 * blk_crypto_submit_bio - handle submitting bio for inline encryption
 *
 * @bio_ptr: pointer to original bio pointer
 *
 * If the bio doesn't have inline encryption enabled or the submitter already
 * specified a keyslot for the target device, do nothing.  Else, a raw key must
 * have been provided, so acquire a device keyslot for it if supported.  Else,
 * use the crypto API fallback.
 *
 * When the crypto API fallback is used for encryption, blk-crypto may choose to
 * split the bio into 2 - the first one that will continue to be processed and
 * the second one that will be resubmitted via generic_make_request.
 * A bounce bio will be allocated to encrypt the contents of the aforementioned
 * "first one", and *bio_ptr will be updated to this bounce bio.
 *
 * Return: 0 if bio submission should continue; nonzero if bio_endio() was
 *	   already called so bio submission should abort.
 */
int blk_crypto_submit_bio(struct bio **bio_ptr)
{
	struct bio *bio = *bio_ptr;
	struct request_queue *q;
	struct bio_crypt_ctx *bc = bio->bi_crypt_context;
	int err;

	if (!bc || !bio_has_data(bio))
		return 0;

	err = bio_crypt_check_alignment(bio);
	if (err) {
		bio->bi_status = BLK_STS_IOERR;
		goto out;
	}

	q = bio->bi_disk->queue;

	if (bc->bc_ksm) {
		/* Key already programmed into device? */
		if (q->ksm == bc->bc_ksm)
			return 0;

		/* Nope, release the existing keyslot. */
		bio_crypt_ctx_release_keyslot(bc);
	}

	/* Get device keyslot if supported */
	if (keyslot_manager_crypto_mode_supported(q->ksm,
				bc->bc_key->crypto_mode,
				blk_crypto_key_dun_bytes(bc->bc_key),
				bc->bc_key->data_unit_size,
				bc->bc_key->is_hw_wrapped)) {
		err = bio_crypt_ctx_acquire_keyslot(bc, q->ksm);
		if (!err)
			return 0;

		pr_warn_once("Failed to acquire keyslot for %s (err=%d).  Falling back to crypto API.\n",
			     bio->bi_disk->disk_name, err);
	}

	/* Fallback to crypto API */
	if (!blk_crypto_fallback_bio_prep(bio_ptr)) {
		err = -EIO;
		goto out;
	}

	return 0;
out:
	bio_endio(*bio_ptr);
	return err;
}

/**
 * blk_crypto_endio - clean up bio w.r.t inline encryption during bio_endio
 *
 * @bio: the bio to clean up
 *
 * If blk_crypto_submit_bio decided to fallback to crypto API for this bio,
 * we queue the bio for decryption into a workqueue and return false,
 * and call bio_endio(bio) at a later time (after the bio has been decrypted).
 *
 * If the bio is not to be decrypted by the crypto API, this function releases
 * the reference to the keyslot that blk_crypto_submit_bio got.
 *
 * Return: true if bio_endio should continue; false otherwise (bio_endio will
 * be called again when bio has been decrypted).
 */
bool blk_crypto_endio(struct bio *bio)
{
	struct bio_crypt_ctx *bc = bio->bi_crypt_context;

	if (!bc)
		return true;

	if (bc->bc_keyslot >= 0)
		bio_crypt_ctx_release_keyslot(bc);

	return true;
}

/**
 * blk_crypto_init_key() - Prepare a key for use with blk-crypto
 * @blk_key: Pointer to the blk_crypto_key to initialize.
 * @raw_key: Pointer to the raw key.
 * @raw_key_size: Size of raw key.  Must be at least the required size for the
 *                chosen @crypto_mode; see blk_crypto_modes[].  (It's allowed
 *                to be longer than the mode's actual key size, in order to
 *                support inline encryption hardware that accepts wrapped keys.
 *                @is_hw_wrapped has to be set for such keys)
 * @is_hw_wrapped: Denotes @raw_key is wrapped.
 * @crypto_mode: identifier for the encryption algorithm to use
 * @dun_bytes: number of bytes that will be used to specify the DUN when this
 *	       key is used
 * @data_unit_size: the data unit size to use for en/decryption
 *
 * Return: The blk_crypto_key that was prepared, or an ERR_PTR() on error.  When
 *	   done using the key, it must be freed with blk_crypto_free_key().
 */
int blk_crypto_init_key(struct blk_crypto_key *blk_key,
			const u8 *raw_key, unsigned int raw_key_size,
			bool is_hw_wrapped,
			enum blk_crypto_mode_num crypto_mode,
			unsigned int dun_bytes,
			unsigned int data_unit_size)
{
	const struct blk_crypto_mode *mode;
	static siphash_key_t hash_key;
	u32 hash;

	memset(blk_key, 0, sizeof(*blk_key));

	if (crypto_mode >= ARRAY_SIZE(blk_crypto_modes))
		return -EINVAL;

	BUILD_BUG_ON(BLK_CRYPTO_MAX_WRAPPED_KEY_SIZE < BLK_CRYPTO_MAX_KEY_SIZE);

	mode = &blk_crypto_modes[crypto_mode];
	if (is_hw_wrapped) {
		if (raw_key_size < mode->keysize ||
		    raw_key_size > BLK_CRYPTO_MAX_WRAPPED_KEY_SIZE)
			return -EINVAL;
	} else {
		if (raw_key_size != mode->keysize)
			return -EINVAL;
	}

	if (dun_bytes <= 0 || dun_bytes > BLK_CRYPTO_MAX_IV_SIZE)
		return -EINVAL;

	if (!is_power_of_2(data_unit_size))
		return -EINVAL;

	blk_key->crypto_mode = crypto_mode;
	blk_key->data_unit_size = data_unit_size;
	blk_key->data_unit_size_bits = ilog2(data_unit_size);
	blk_key->size = raw_key_size;
	blk_key->is_hw_wrapped = is_hw_wrapped;
	memcpy(blk_key->raw, raw_key, raw_key_size);

	/*
	 * The keyslot manager uses the SipHash of the key to implement O(1) key
	 * lookups while avoiding leaking information about the keys.  It's
	 * precomputed here so that it only needs to be computed once per key.
	 */
	get_random_once(&hash_key, sizeof(hash_key));
	hash = (u32)siphash(raw_key, raw_key_size, &hash_key);
	blk_crypto_key_set_hash_and_dun_bytes(blk_key, hash, dun_bytes);

	return 0;
}
EXPORT_SYMBOL_GPL(blk_crypto_init_key);

/**
 * blk_crypto_start_using_mode() - Start using blk-crypto on a device
 * @crypto_mode: the crypto mode that will be used
 * @dun_bytes: number of bytes that will be used to specify the DUN
 * @data_unit_size: the data unit size that will be used
 * @is_hw_wrapped_key: whether the key will be hardware-wrapped
 * @q: the request queue for the device
 *
 * Upper layers must call this function to ensure that either the hardware
 * supports the needed crypto settings, or the crypto API fallback has
 * transforms for the needed mode allocated and ready to go.
 *
 * Return: 0 on success; -ENOPKG if the hardware doesn't support the crypto
 *	   settings and blk-crypto-fallback is either disabled or the needed
 *	   algorithm is disabled in the crypto API; or another -errno code.
 */
int blk_crypto_start_using_mode(enum blk_crypto_mode_num crypto_mode,
				unsigned int dun_bytes,
				unsigned int data_unit_size,
				bool is_hw_wrapped_key,
				struct request_queue *q)
{
	if (keyslot_manager_crypto_mode_supported(q->ksm, crypto_mode,
						  dun_bytes, data_unit_size,
						  is_hw_wrapped_key))
		return 0;
	if (is_hw_wrapped_key) {
		pr_warn_once("hardware doesn't support wrapped keys\n");
		return -EOPNOTSUPP;
	}
	return blk_crypto_fallback_start_using_mode(crypto_mode);
}
EXPORT_SYMBOL_GPL(blk_crypto_start_using_mode);

/**
 * blk_crypto_evict_key() - Evict a key from any inline encryption hardware
 *			    it may have been programmed into
 * @q: The request queue who's keyslot manager this key might have been
 *     programmed into
 * @key: The key to evict
 *
 * Upper layers (filesystems) should call this function to ensure that a key
 * is evicted from hardware that it might have been programmed into. This
 * will call keyslot_manager_evict_key on the queue's keyslot manager, if one
 * exists, and supports the crypto algorithm with the specified data unit size.
 * Otherwise, it will evict the key from the blk-crypto-fallback's ksm.
 *
 * Return: 0 on success, -err on error.
 */
int blk_crypto_evict_key(struct request_queue *q,
			 const struct blk_crypto_key *key)
{
	if (q->ksm &&
	    keyslot_manager_crypto_mode_supported(q->ksm, key->crypto_mode,
						  blk_crypto_key_dun_bytes(key),
						  key->data_unit_size,
						  key->is_hw_wrapped))
		return keyslot_manager_evict_key(q->ksm, key);

	return blk_crypto_fallback_evict_key(key);
}
EXPORT_SYMBOL_GPL(blk_crypto_evict_key);

int bio_crypt_ctx_init(void)
{
	return 0;
}
EXPORT_SYMBOL_GPL(bio_crypt_ctx_init);

struct bio_crypt_ctx *bio_crypt_alloc_ctx(gfp_t gfp_mask)
{
	return kzalloc(sizeof(struct bio_crypt_ctx), gfp_mask);
}
EXPORT_SYMBOL_GPL(bio_crypt_alloc_ctx);

void bio_crypt_ctx_release_keyslot(struct bio_crypt_ctx *bc)
{
	if (!bc || !bc->bc_ksm || bc->bc_keyslot < 0)
		return;

	keyslot_manager_put_slot(bc->bc_ksm, bc->bc_keyslot);
	bc->bc_keyslot = -1;
	bc->bc_ksm = NULL;
}
EXPORT_SYMBOL_GPL(bio_crypt_ctx_release_keyslot);

int bio_crypt_ctx_acquire_keyslot(struct bio_crypt_ctx *bc,
				  struct keyslot_manager *ksm)
{
	int slot;

	if (!bc || !bc->bc_key || !ksm)
		return -EINVAL;

	if (bc->bc_ksm == ksm && bc->bc_keyslot >= 0)
		return 0;

	if (bc->bc_keyslot >= 0)
		bio_crypt_ctx_release_keyslot(bc);

	slot = keyslot_manager_get_slot_for_key(ksm, bc->bc_key);
	if (slot < 0)
		return slot;

	bc->bc_keyslot = slot;
	bc->bc_ksm = ksm;
	return 0;
}
EXPORT_SYMBOL_GPL(bio_crypt_ctx_acquire_keyslot);

void bio_crypt_free_ctx(struct bio *bio)
{
	if (!bio || !bio->bi_crypt_context)
		return;

	bio_crypt_ctx_release_keyslot(bio->bi_crypt_context);
	kfree(bio->bi_crypt_context);
	bio->bi_crypt_context = NULL;
}
EXPORT_SYMBOL_GPL(bio_crypt_free_ctx);

int bio_crypt_clone(struct bio *dst, struct bio *src, gfp_t gfp_mask)
{
	struct bio_crypt_ctx *src_bc = src->bi_crypt_context;
	struct bio_crypt_ctx *dst_bc;

	if (!src_bc)
		return 0;

	dst_bc = kmemdup(src_bc, sizeof(*dst_bc), gfp_mask);
	if (!dst_bc)
		return -ENOMEM;

	if (dst_bc->bc_ksm && dst_bc->bc_keyslot >= 0)
		keyslot_manager_get_slot(dst_bc->bc_ksm, dst_bc->bc_keyslot);

	dst->bi_crypt_context = dst_bc;
	return 0;
}
EXPORT_SYMBOL_GPL(bio_crypt_clone);

bool bio_crypt_ctx_compatible(struct bio *b_1, struct bio *b_2)
{
	struct bio_crypt_ctx *bc1 = b_1->bi_crypt_context;
	struct bio_crypt_ctx *bc2 = b_2->bi_crypt_context;

	if (!bc1 && !bc2)
		return true;
	if (!bc1 || !bc2)
		return false;

	if (bc1->bc_key != bc2->bc_key)
		return false;

	return !memcmp(bc1->bc_dun, bc2->bc_dun, sizeof(bc1->bc_dun));
}
EXPORT_SYMBOL_GPL(bio_crypt_ctx_compatible);

bool bio_crypt_ctx_mergeable(struct bio_crypt_ctx *bc1, unsigned int bc1_bytes,
			     struct bio_crypt_ctx *bc2)
{
	if (!bc1 && !bc2)
		return true;
	if (!bc1 || !bc2)
		return false;
	if (bc1->bc_key != bc2->bc_key)
		return false;

	return bio_crypt_dun_is_contiguous(bc1, bc1_bytes, bc2->bc_dun);
}
EXPORT_SYMBOL_GPL(bio_crypt_ctx_mergeable);

bool bio_crypt_rq_ctx_compatible(struct request *rq, struct bio *bio)
{
	if (!rq->crypt_ctx && !bio_has_crypt_ctx(bio))
		return true;
	if (!rq->crypt_ctx || !bio_has_crypt_ctx(bio))
		return false;

	return rq->crypt_ctx->bc_key == bio->bi_crypt_context->bc_key;
}
EXPORT_SYMBOL_GPL(bio_crypt_rq_ctx_compatible);

bool bio_crypt_should_process(struct request *rq)
{
	return rq && rq->crypt_ctx;
}
EXPORT_SYMBOL_GPL(bio_crypt_should_process);

bool __blk_crypto_bio_prep(struct bio **bio_ptr)
{
	return blk_crypto_submit_bio(bio_ptr) == 0;
}
EXPORT_SYMBOL_GPL(__blk_crypto_bio_prep);

static inline struct blk_ksm_keyslot *blk_crypto_encode_slot(unsigned int slot)
{
	return (struct blk_ksm_keyslot *)(unsigned long)(slot + 1);
}

static inline unsigned int blk_crypto_decode_slot(struct blk_ksm_keyslot *slot)
{
	return (unsigned int)((unsigned long)slot - 1);
}

blk_status_t __blk_crypto_rq_get_keyslot(struct request *rq)
{
	int err;

	if (!rq->crypt_ctx)
		return BLK_STS_OK;

	if (rq->crypt_keyslot)
		return BLK_STS_OK;

	err = bio_crypt_ctx_acquire_keyslot(rq->crypt_ctx, rq->q->ksm);
	if (err)
		return errno_to_blk_status(err);

	rq->crypt_keyslot = blk_crypto_encode_slot(rq->crypt_ctx->bc_keyslot);
	return BLK_STS_OK;
}
EXPORT_SYMBOL_GPL(__blk_crypto_rq_get_keyslot);

void __blk_crypto_rq_put_keyslot(struct request *rq)
{
	unsigned int slot;

	if (!rq->crypt_keyslot || !rq->crypt_ctx || !rq->crypt_ctx->bc_ksm)
		return;

	slot = blk_crypto_decode_slot(rq->crypt_keyslot);
	keyslot_manager_put_slot(rq->crypt_ctx->bc_ksm, slot);
	rq->crypt_keyslot = NULL;
	rq->crypt_ctx->bc_keyslot = -1;
	rq->crypt_ctx->bc_ksm = NULL;
}
EXPORT_SYMBOL_GPL(__blk_crypto_rq_put_keyslot);

void __blk_crypto_free_request(struct request *rq)
{
	if (!rq->crypt_ctx)
		return;

	__blk_crypto_rq_put_keyslot(rq);
	kfree(rq->crypt_ctx);
	rq->crypt_ctx = NULL;
}
EXPORT_SYMBOL_GPL(__blk_crypto_free_request);

int __blk_crypto_rq_bio_prep(struct request *rq, struct bio *bio,
			     gfp_t gfp_mask)
{
	if (!bio_has_crypt_ctx(bio))
		return 0;

	rq->crypt_ctx = kmemdup(bio->bi_crypt_context, sizeof(*rq->crypt_ctx),
				gfp_mask);
	if (!rq->crypt_ctx)
		return -ENOMEM;

	/*
	 * Requests acquire and release their own keyslot lifetime.
	 * Keep only the immutable key/DUN configuration when cloning.
	 */
	rq->crypt_ctx->bc_ksm = NULL;
	rq->crypt_ctx->bc_keyslot = -1;
	rq->crypt_keyslot = NULL;
	return 0;
}
EXPORT_SYMBOL_GPL(__blk_crypto_rq_bio_prep);

bool blk_ksm_register(struct keyslot_manager *ksm, struct request_queue *q)
{
	if (q->ksm && q->ksm != ksm)
		return false;

	q->ksm = ksm;
	return true;
}
EXPORT_SYMBOL_GPL(blk_ksm_register);

void blk_ksm_unregister(struct request_queue *q)
{
	q->ksm = NULL;
}
EXPORT_SYMBOL_GPL(blk_ksm_unregister);
