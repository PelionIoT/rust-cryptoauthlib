use std::cmp::min;
use std::mem::MaybeUninit;

use super::{AeadParam, AtcaAesCcmCtx, AtcaStatus, AteccDevice, KeyType, NonceTarget};

use super::{
    ATCA_AES_DATA_SIZE, ATCA_AES_GCM_IV_STD_LENGTH, ATCA_ATECC_SLOTS_COUNT,
    ATCA_ATECC_TEMPKEY_KEYID, ATCA_NONCE_SIZE,
};

use cryptoauthlib_sys::atca_aes_cmac_ctx_t;
use cryptoauthlib_sys::atca_aes_ctr_ctx_t;

impl AteccDevice {
    ///
    pub(crate) fn encrypt_aes_ccm(
        &self,
        aead_param: AeadParam,
        slot_id: u8,
        data: &mut [u8],
    ) -> Result<Vec<u8>, AtcaStatus> {
        // let mut ctx: AtcaAesCcmCtx = Default::default();
        let ctx: AtcaAesCcmCtx;

        // let mut tag_length: u8 = ATCA_AES_DATA_SIZE as u8;
        // if let Some(val) = &aead_param.tag_length {
        //     tag_length = *val
        // };

        match self.common_aes_ccm(aead_param, slot_id, data) {
            Err(err) => {
                println!("\u{001b}[1m\u{001b}[33mDUPA\u{001b}[0m ");
                return Err(err);
            }
            Ok(val) => {
                ctx = val;
                println!("\u{001b}[1m\u{001b}[33m{:02X?}\u{001b}[0m ", ctx);
            }
        }

        Err(AtcaStatus::AtcaUnimplemented)
    }

    ///
    pub(crate) fn decrypt_aes_ccm(
        &self,
        _aead_param: AeadParam,
        _slot_id: u8,
        _data: &mut [u8],
    ) -> Result<bool, AtcaStatus> {
        Err(AtcaStatus::AtcaUnimplemented)
    }

    /// a helper function implementing common functionality for AES GCM encryption and decryption
    fn common_aes_ccm(
        &self,
        aead_param: AeadParam,
        slot_id: u8,
        data: &mut [u8],
    ) -> Result<AtcaAesCcmCtx, AtcaStatus> {
        const MAX_IV_SIZE: usize = ATCA_AES_DATA_SIZE - 1;
        const MIN_IV_SIZE: usize = ATCA_AES_GCM_IV_STD_LENGTH;
        const MAX_TAG_SIZE: usize = ATCA_AES_DATA_SIZE;
        const MIN_TAG_SIZE: usize = 12;
        // const TAG_SIZE: usize = ATCA_AES_DATA_SIZE;

        if (slot_id > ATCA_ATECC_SLOTS_COUNT)
            || ((slot_id < ATCA_ATECC_SLOTS_COUNT)
                && (self.slots[slot_id as usize].config.key_type != KeyType::Aes))
        {
            return Err(AtcaStatus::AtcaInvalidId);
        }
        if (ATCA_ATECC_SLOTS_COUNT == slot_id) && aead_param.key.is_none() {
            return Err(AtcaStatus::AtcaBadParam);
        }
        if (data.is_empty() && aead_param.additional_data.is_none())
            || (aead_param.nonce.len() < MIN_IV_SIZE || aead_param.nonce.len() > MAX_IV_SIZE)
            || (aead_param.tag_length.is_some()
                && ((aead_param.tag_length < Some(MIN_TAG_SIZE as u8))
                    || (aead_param.tag_length > Some(MAX_TAG_SIZE as u8))))
            || (aead_param.tag.is_some()
                && ((aead_param.tag.clone().unwrap().len() < MIN_TAG_SIZE)
                    || (aead_param.tag.clone().unwrap().len() > MAX_TAG_SIZE)))
        {
            return Err(AtcaStatus::AtcaInvalidSize);
        }

        let mut ctx: AtcaAesCcmCtx;

        let mut tag_length: usize = ATCA_AES_DATA_SIZE;
        if let Some(val) = &aead_param.tag_length {
            tag_length = *val as usize
        };

        let mut result = AtcaStatus::AtcaSuccess;
        if let Some(val) = &aead_param.key {
            let mut key: Vec<u8> = val.to_vec();
            key.resize_with(ATCA_NONCE_SIZE, || 0x00);
            result = self.nonce(NonceTarget::TempKey, &key)
        }

        if AtcaStatus::AtcaSuccess != result {
            return Err(result);
        } else {
            let iv: Vec<u8> = aead_param.nonce;
            let mut additional_data_size: usize = 0;
            if let Some(val) = &aead_param.additional_data {
                additional_data_size = val.len();
            };
            let data_size = data.len();

            match self.aes_ccm_init(slot_id, &iv, additional_data_size, data_size, tag_length) {
                Err(err) => return Err(err),
                Ok(val) => ctx = val,
            };
        }

        if let Some(data_to_sign) = &aead_param.additional_data {
            match self.aes_ccm_aad_update(ctx, &data_to_sign) {
                Err(err) => return Err(err),
                Ok(val) => ctx = val,
            }
        }
        // if let Some(data_to_sign) = &aead_param.additional_data {
        //     let mut start_pos: usize = 0;
        //     let mut shift: usize = min(data_to_sign.len(), ATCA_AES_DATA_SIZE);
        //     while shift > 0 {
        //         let block = &data_to_sign[start_pos..(start_pos + shift)];
        //         match self.aes_ccm_aad_update(ctx, &block) {
        //             Err(err) => return Err(err),
        //             Ok(val) => {
        //                 ctx = val;
        //                 start_pos += shift;
        //                 let remaining_bytes = data_to_sign.len() - start_pos;
        //                 if 0 == remaining_bytes {
        //                     shift = 0
        //                 } else if remaining_bytes < ATCA_AES_DATA_SIZE {
        //                     shift = remaining_bytes
        //                 }
        //             }
        //         }
        //     }
        // }

        Ok(ctx)
    }

    ///
    fn aes_ccm_init(
        &self,
        slot_id: u8,
        iv: &[u8],
        aad_size: usize,
        text_size: usize,
        tag_size: usize,
    ) -> Result<AtcaAesCcmCtx, AtcaStatus> {
        // Length/nonce field specifications according to rfc3610.
        if iv.is_empty() || iv.len() < 7 || iv.len() > 13 {
            return Err(AtcaStatus::AtcaBadParam);
        }

        // Auth field specifications according to rfc3610.
        if !(3..=ATCA_AES_DATA_SIZE).contains(&tag_size) || (tag_size % 2 != 0) {
            return Err(AtcaStatus::AtcaBadParam);
        }

        // First block B of 16 bytes consisting of flags, nonce and l(m).
        let mut b: [u8; ATCA_AES_DATA_SIZE] = [0x00; ATCA_AES_DATA_SIZE];
        let mut counter: [u8; ATCA_AES_DATA_SIZE] = [0x00; ATCA_AES_DATA_SIZE];
        let mut ctx: AtcaAesCcmCtx = AtcaAesCcmCtx {
            iv_size: iv.len() as u8,
            ..Default::default()
        };

        // --------------------- Init sequence for authentication .......................//
        // Encoding the number of bytes in auth field.
        let m = ((tag_size - 2) / 2) as u8;
        // Encoding the number of bytes in length field.
        let l = (ATCA_AES_DATA_SIZE - iv.len() - 1 - 1) as u8;

        // Store M value in ctx for later use.
        ctx.m = m;

        //   ----------------------
        //   Bit Number   Contents
        //   ----------   ----------------------
        //   7            Reserved (always zero)
        //   6            Adata
        //   5 ... 3      M'
        //   2 ... 0      L'
        //   -----------------------
        // Formatting flag field
        b[0] = l | (m << 3) | (((aad_size > 0) as u8) << 6);

        //   ----------------------
        //   Octet Number   Contents
        //   ------------   ---------
        //   0              Flags
        //   1 ... 15-L     Nonce N
        //   16-L ... 15    l(m)
        //   -----------------------

        // Copying the IV into the nonce field.
        // b[1..(iv.len() + 1)].clone_from_slice(&iv);
        b[1..=iv.len()].clone_from_slice(&iv);

        // Update length field in B0 block.
        let mut size_left: usize = text_size;
        for i in 0..=l {
            b[(15 - i) as usize] = (size_left & 0xFF) as u8;
            size_left >>= 8;
        }

        // Init CBC-MAC context
        match self.aes_cmac_init(slot_id) {
            Ok(cbc_mac_ctx) => ctx.cbc_mac_ctx = cbc_mac_ctx,
            Err(err) => return Err(err),
        }

        // Processing initial block B0 through CBC-MAC.
        match self.aes_cmac_update(ctx.cbc_mac_ctx, &b) {
            Ok(cbc_mac_ctx) => ctx.cbc_mac_ctx = cbc_mac_ctx,
            Err(err) => return Err(err),
        }

        // Loading AAD size in ctx buffer.
        ctx.partial_aad[0] = ((aad_size >> 8) & 0xFF) as u8;
        ctx.partial_aad[1] = (aad_size & 0xFF) as u8;
        ctx.partial_aad_size = 2;

        // --------------------- Init sequence for encryption/decryption .......................//
        ctx.text_size = text_size;

        //   ----------------------
        //   Bit Number   Contents
        //   ----------   ----------------------
        //   7            Reserved (always zero)
        //   6            Reserved (always zero)
        //   5 ... 3      Zero
        //   2 ... 0      L'
        //   -----------------------

        // Updating Flags field
        counter[0] = l;
        //   ----------------------
        //   Octet Number   Contents
        //   ------------   ---------
        //   0              Flags
        //   1 ... 15-L     Nonce N
        //   16-L ... 15    Counter i
        //   -----------------------
        // Formatting to get the initial counter value
        counter[1..=iv.len()].clone_from_slice(&iv);
        ctx.counter[..].copy_from_slice(&counter);

        // Init CTR mode context with the counter value obtained from previous step.
        let counter_size: u8 = (ATCA_AES_DATA_SIZE - (ctx.iv_size as usize) - 1) as u8;
        match self.aes_ctr_init(slot_id, counter_size, &counter) {
            Ok(ctr_ctx) => ctx.ctr_ctx = ctr_ctx,
            Err(err) => return Err(err),
        }

        // Increment the counter to skip the first block, first will be later reused to get tag.
        match self.aes_ctr_increment(ctx.ctr_ctx) {
            Ok(ctr_ctx) => ctx.ctr_ctx = ctr_ctx,
            Err(err) => return Err(err),
        }

        Ok(ctx)
    }

    fn aes_ccm_aad_update(&self, ctx: AtcaAesCcmCtx, data: &[u8]) -> Result<AtcaAesCcmCtx, AtcaStatus> {
        // atca_aes_ccm_ctx_t* ctx, const uint8_t* aad, size_t aad_size) -> {
        // let mut block_count: usize = 0;
        let copy_size: usize;

        if data.is_empty() {
            return Ok(ctx)
        };

        let mut temp_ctx = ctx.clone();

        let rem_size: usize = ATCA_AES_DATA_SIZE - ctx.partial_aad_size;
        if data.len() > rem_size {
            copy_size = rem_size;
        } else {
            copy_size = data.len();
        }
    
        // Copy data into current block
        temp_ctx.partial_aad[ctx.partial_aad_size..].clone_from_slice(&data[..copy_size]);

        if temp_ctx.partial_aad_size + data.len() < ATCA_AES_DATA_SIZE {
            // Not enough data to finish off the current block
            temp_ctx.partial_aad_size += data.len();
            return Ok(temp_ctx);
        }

    // // Process the current block
    // if (ATCA_SUCCESS != (status = atcab_aes_cbcmac_update(&ctx->cbc_mac_ctx, ctx->partial_aad, ATCA_AES128_BLOCK_SIZE)))
    // {
    //     return status;
    // }

    // // Process any additional blocks
    // aad_size -= copy_size; // Adjust to the remaining aad bytes
    // block_count = aad_size / ATCA_AES128_BLOCK_SIZE;
    // if (block_count > 0)
    // {
    //     if (ATCA_SUCCESS != (status = atcab_aes_cbcmac_update(&ctx->cbc_mac_ctx,  &aad[copy_size],  block_count * ATCA_AES128_BLOCK_SIZE)))
    //     {
    //         return status;
    //     }
    // }

    // // Save any remaining data
    // ctx->partial_aad_size = aad_size % ATCA_AES128_BLOCK_SIZE;
    // memcpy(ctx->partial_aad, &aad[copy_size + block_count * ATCA_AES128_BLOCK_SIZE], ctx->partial_aad_size);

    // return ATCA_SUCCESS;
    Ok(ctx)
}

    // -----------------------------------------------------------
    //
    // -----------------------------------------------------------

    ///
    fn aes_ctr_init(
        &self,
        slot_id: u8,
        counter_size: u8,
        iv: &[u8],
    ) -> Result<atca_aes_ctr_ctx_t, AtcaStatus> {
        const BLOCK_IDX: u8 = 0;

        if iv.len() != ATCA_AES_DATA_SIZE {
            return Err(AtcaStatus::AtcaInvalidSize);
        }
        let mut slot = slot_id as u16;
        if slot_id == ATCA_ATECC_SLOTS_COUNT {
            slot = ATCA_ATECC_TEMPKEY_KEYID;
        }

        let ctx: atca_aes_ctr_ctx_t = {
            let ctx = MaybeUninit::<atca_aes_ctr_ctx_t>::zeroed();
            unsafe { ctx.assume_init() }
        };
        let ctx_ptr = Box::into_raw(Box::new(ctx));

        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_aes_ctr_init(
                ctx_ptr,
                slot,
                BLOCK_IDX,
                counter_size,
                iv.as_ptr(),
            )
        });

        match result {
            AtcaStatus::AtcaSuccess => Ok({
                let result = unsafe { *ctx_ptr };
                unsafe { Box::from_raw(ctx_ptr) };
                result
            }),
            _ => Err(result),
        }
    }

    fn aes_ctr_increment(&self, ctx: atca_aes_ctr_ctx_t) -> Result<atca_aes_ctr_ctx_t, AtcaStatus> {
        let ctx_ptr = Box::into_raw(Box::new(ctx));

        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_aes_ctr_increment(ctx_ptr)
        });

        let ctx = unsafe { *ctx_ptr };
        unsafe { Box::from_raw(ctx_ptr) };

        match result {
            AtcaStatus::AtcaSuccess => Ok(ctx),
            _ => Err(result),
        }
    }

    fn aes_cmac_init(&self, slot_id: u8) -> Result<atca_aes_cmac_ctx_t, AtcaStatus> {
        const BLOCK_IDX: u8 = 0;

        let mut slot = slot_id as u16;
        if slot_id == ATCA_ATECC_SLOTS_COUNT {
            slot = ATCA_ATECC_TEMPKEY_KEYID;
        }

        let ctx: atca_aes_cmac_ctx_t = {
            let ctx = MaybeUninit::<atca_aes_cmac_ctx_t>::zeroed();
            unsafe { ctx.assume_init() }
        };
        let ctx_ptr = Box::into_raw(Box::new(ctx));

        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_aes_cmac_init(ctx_ptr, slot, BLOCK_IDX)
        });

        match result {
            AtcaStatus::AtcaSuccess => Ok({
                let result = unsafe { *ctx_ptr };
                unsafe { Box::from_raw(ctx_ptr) };
                result
            }),
            _ => Err(result),
        }
    }

    fn aes_cmac_update(
        &self,
        ctx: atca_aes_cmac_ctx_t,
        data: &[u8],
    ) -> Result<atca_aes_cmac_ctx_t, AtcaStatus> {
        let ctx_ptr = Box::into_raw(Box::new(ctx));

        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_aes_cmac_update(ctx_ptr, data.as_ptr(), data.len() as u32)
        });

        let ctx = unsafe { *ctx_ptr };
        unsafe { Box::from_raw(ctx_ptr) };

        match result {
            AtcaStatus::AtcaSuccess => Ok(ctx),
            _ => Err(result),
        }
    }
}
