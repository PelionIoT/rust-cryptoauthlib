use std::cmp::min;
use std::mem::MaybeUninit;

use super::{AeadParam, AtcaStatus, AteccDevice, KeyType, NonceTarget};

use super::{
    ATCA_AES_DATA_SIZE, ATCA_AES_GCM_IV_STD_LENGTH, ATCA_ATECC_SLOTS_COUNT,
    ATCA_ATECC_TEMPKEY_KEYID, ATCA_NONCE_SIZE,
};

use cryptoauthlib_sys::atca_aes_gcm_ctx_t;

impl AteccDevice {
    /// function that performs encryption in AES GCM mode
    pub(crate) fn encrypt_aes_gcm(
        &self,
        aead_param: AeadParam,
        slot_id: u8,
        data: &mut Vec<u8>,
    ) -> Result<Vec<u8>, AtcaStatus> {
        let mut tag_length: u8 = ATCA_AES_DATA_SIZE as u8;
        if let Some(val) = &aead_param.tag_length {
            tag_length = *val
        };

        let mut ctx: atca_aes_gcm_ctx_t = self.common_aes_gcm(aead_param, slot_id, data)?;

        if !data.is_empty() {
            let mut start_pos: usize = 0;
            let mut shift: usize = min(data.len(), ATCA_AES_DATA_SIZE);

            while shift > 0 {
                let block = &data[start_pos..(start_pos + shift)];
                let mut encr_block: [u8; ATCA_AES_DATA_SIZE] = [0; ATCA_AES_DATA_SIZE];

                ctx = self.aes_gcm_encrypt_update(ctx, block, &mut encr_block)?;
                data[start_pos..(shift + start_pos)].clone_from_slice(&encr_block[..shift]);

                start_pos += shift;
                let remaining_bytes = data.len() - start_pos;
                if 0 == remaining_bytes {
                    shift = 0
                } else if remaining_bytes < ATCA_AES_DATA_SIZE {
                    shift = remaining_bytes
                }
            }
        }

        let tag = self.aes_gcm_encrypt_finish(ctx, tag_length)?;
        Ok(tag)
    }

    /// function that performs decryption in AES GCM mode
    pub(crate) fn decrypt_aes_gcm(
        &self,
        aead_param: AeadParam,
        slot_id: u8,
        data: &mut Vec<u8>,
    ) -> Result<bool, AtcaStatus> {
        let tag_to_check: Vec<u8>;

        if let Some(val) = aead_param.tag.clone() {
            tag_to_check = val;
        } else {
            return Err(AtcaStatus::AtcaBadParam);
        }

        let mut ctx: atca_aes_gcm_ctx_t = self.common_aes_gcm(aead_param, slot_id, data)?;

        if !data.is_empty() {
            let mut start_pos: usize = 0;
            let mut shift: usize = min(data.len(), ATCA_AES_DATA_SIZE);

            while shift > 0 {
                let block = &data[start_pos..(start_pos + shift)];
                let mut encr_block: [u8; ATCA_AES_DATA_SIZE] = [0; ATCA_AES_DATA_SIZE];

                ctx = self.aes_gcm_decrypt_update(ctx, block, &mut encr_block)?;
                data[start_pos..(shift + start_pos)].clone_from_slice(&encr_block[..shift]);

                start_pos += shift;
                let remaining_bytes = data.len() - start_pos;
                if 0 == remaining_bytes {
                    shift = 0
                } else if remaining_bytes < ATCA_AES_DATA_SIZE {
                    shift = remaining_bytes
                }
            }
        }

        let is_verified = self.aes_gcm_decrypt_finish(ctx, &tag_to_check)?;
        Ok(is_verified)
    }

    /// a helper function implementing common functionality for AES GCM encryption and decryption
    fn common_aes_gcm(
        &self,
        aead_param: AeadParam,
        slot_id: u8,
        data: &mut Vec<u8>,
    ) -> Result<atca_aes_gcm_ctx_t, AtcaStatus> {
        const MAX_IV_SIZE: usize = ATCA_AES_DATA_SIZE - 1;
        const MIN_IV_SIZE: usize = ATCA_AES_GCM_IV_STD_LENGTH;
        const MAX_TAG_SIZE: usize = ATCA_AES_DATA_SIZE;
        const MIN_TAG_SIZE: usize = 12;

        if (slot_id > ATCA_ATECC_SLOTS_COUNT)
            || ((slot_id < ATCA_ATECC_SLOTS_COUNT)
                && (self.slots[slot_id as usize].config.key_type != KeyType::Aes))
        {
            return Err(AtcaStatus::AtcaInvalidId);
        }
        if (ATCA_ATECC_SLOTS_COUNT == slot_id) && aead_param.key.is_none()
            || (aead_param.tag_length.is_some() && aead_param.tag.is_some())
        {
            return Err(AtcaStatus::AtcaBadParam);
        }
        if (data.is_empty() && aead_param.additional_data.is_none())
            || (aead_param.nonce.len() < MIN_IV_SIZE || aead_param.nonce.len() > MAX_IV_SIZE)
            || (aead_param.tag_length.is_some()
                && ((aead_param.tag_length < Some(MIN_TAG_SIZE as u8))
                    || (aead_param.tag_length > Some(MAX_TAG_SIZE as u8))))
            || (aead_param.tag.is_some()
                && ((aead_param.tag.as_ref().unwrap().len() < MIN_TAG_SIZE)
                    || (aead_param.tag.as_ref().unwrap().len() > MAX_TAG_SIZE)))
        {
            return Err(AtcaStatus::AtcaInvalidSize);
        }

        if let Some(val) = &aead_param.key {
            let mut key: Vec<u8> = val.to_vec();
            key.resize(ATCA_NONCE_SIZE, 0x00);
            let result = self.nonce(NonceTarget::TempKey, &key);
            if AtcaStatus::AtcaSuccess != result {
                return Err(result);
            }
        }

        let iv: Vec<u8> = aead_param.nonce;
        let mut ctx = self.aes_gcm_init(slot_id, &iv)?;

        if let Some(data_to_sign) = &aead_param.additional_data {
            let mut start_pos: usize = 0;
            let mut shift: usize = min(data_to_sign.len(), ATCA_AES_DATA_SIZE);
            while shift > 0 {
                let block = &data_to_sign[start_pos..(start_pos + shift)];
                ctx = self.aes_gcm_aad_update(ctx, block)?;
                start_pos += shift;
                let remaining_bytes = data_to_sign.len() - start_pos;
                if 0 == remaining_bytes {
                    shift = 0
                } else if remaining_bytes < ATCA_AES_DATA_SIZE {
                    shift = remaining_bytes
                }
            }
        }

        Ok(ctx)
    }

    /// Initialize context for AES GCM operation with an existing IV, which
    /// is common when starting a decrypt operation
    fn aes_gcm_init(&self, slot_id: u8, iv: &[u8]) -> Result<atca_aes_gcm_ctx_t, AtcaStatus> {
        const BLOCK_IDX: u8 = 0;

        let mut slot = slot_id as u16;
        if slot_id == ATCA_ATECC_SLOTS_COUNT {
            slot = ATCA_ATECC_TEMPKEY_KEYID;
        }

        let ctx_ptr = Box::into_raw(Box::new({
            let ctx = MaybeUninit::<atca_aes_gcm_ctx_t>::zeroed();
            unsafe { ctx.assume_init() }
        }));

        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_aes_gcm_init(
                ctx_ptr,
                slot,
                BLOCK_IDX,
                iv.as_ptr(),
                iv.len() as u64,
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

    /// Process Additional Authenticated Data (AAD) using GCM mode and a
    /// key within the ATECC608 device
    fn aes_gcm_aad_update(
        &self,
        ctx: atca_aes_gcm_ctx_t,
        data: &[u8],
    ) -> Result<atca_aes_gcm_ctx_t, AtcaStatus> {
        if data.len() > ATCA_AES_DATA_SIZE {
            return Err(AtcaStatus::AtcaInvalidSize);
        }

        let ctx_ptr = Box::into_raw(Box::new(ctx));

        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_aes_gcm_aad_update(ctx_ptr, data.as_ptr(), data.len() as u32)
        });

        let ctx = unsafe { *ctx_ptr };
        unsafe { Box::from_raw(ctx_ptr) };

        match result {
            AtcaStatus::AtcaSuccess => Ok(ctx),
            _ => Err(result),
        }
    } // AteccDevice::aes_gcm_aad_update()

    /// Encrypt data using GCM mode and a key within the ATECC608 device.
    /// aes_gcm_init() should be called before the first use of this function.
    fn aes_gcm_encrypt_update(
        &self,
        ctx: atca_aes_gcm_ctx_t,
        data: &[u8],
        encrypted: &mut [u8; ATCA_AES_DATA_SIZE],
    ) -> Result<atca_aes_gcm_ctx_t, AtcaStatus> {
        if data.len() > ATCA_AES_DATA_SIZE {
            return Err(AtcaStatus::AtcaInvalidSize);
        }

        let ctx_ptr = Box::into_raw(Box::new(ctx));
        *encrypted = [0; ATCA_AES_DATA_SIZE];

        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_aes_gcm_encrypt_update(
                ctx_ptr,
                data.as_ptr(),
                data.len() as u32,
                encrypted.as_mut_ptr(),
            )
        });

        let ctx = unsafe { *ctx_ptr };
        unsafe { Box::from_raw(ctx_ptr) };

        match result {
            AtcaStatus::AtcaSuccess => Ok(ctx),
            _ => Err(result),
        }
    } // AteccDevice::aes_gcm_encrypt_update()

    /// Decrypt data using GCM mode and a key within the ATECC608 device.
    /// aes_gcm_init() should be called before the first use of this function
    fn aes_gcm_decrypt_update(
        &self,
        ctx: atca_aes_gcm_ctx_t,
        data: &[u8],
        encrypted: &mut [u8; ATCA_AES_DATA_SIZE],
    ) -> Result<atca_aes_gcm_ctx_t, AtcaStatus> {
        if data.len() > ATCA_AES_DATA_SIZE {
            return Err(AtcaStatus::AtcaInvalidSize);
        }

        let ctx_ptr = Box::into_raw(Box::new(ctx));
        *encrypted = [0; ATCA_AES_DATA_SIZE];

        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_aes_gcm_decrypt_update(
                ctx_ptr,
                data.as_ptr(),
                data.len() as u32,
                encrypted.as_mut_ptr(),
            )
        });

        let ctx = unsafe { *ctx_ptr };
        unsafe { Box::from_raw(ctx_ptr) };

        match result {
            AtcaStatus::AtcaSuccess => Ok(ctx),
            _ => Err(result),
        }
    } // AteccDevice::aes_gcm_decrypt_update()

    /// Complete a GCM encrypt operation returning the authentication tag
    fn aes_gcm_encrypt_finish(
        &self,
        ctx: atca_aes_gcm_ctx_t,
        tag_length: u8,
    ) -> Result<Vec<u8>, AtcaStatus> {
        let ctx_ptr = Box::into_raw(Box::new(ctx));
        let mut tag: [u8; ATCA_AES_DATA_SIZE] = [0; ATCA_AES_DATA_SIZE];

        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_aes_gcm_encrypt_finish(
                ctx_ptr,
                tag.as_mut_ptr(),
                tag_length as u64,
            )
        });

        unsafe { Box::from_raw(ctx_ptr) };

        match result {
            AtcaStatus::AtcaSuccess => Ok({
                let mut out_tag: Vec<u8> = vec![0x00; tag_length as usize];
                out_tag.copy_from_slice(&tag[..tag_length as usize]);
                out_tag
            }),
            _ => Err(result),
        }
    } // AteccDevice::aes_gcm_encrypt_finish()

    /// Complete a GCM decrypt operation verifying the authentication tag
    fn aes_gcm_decrypt_finish(
        &self,
        ctx: atca_aes_gcm_ctx_t,
        tag: &[u8],
    ) -> Result<bool, AtcaStatus> {
        let ctx_ptr = Box::into_raw(Box::new(ctx));
        let mut is_verified: bool = false;

        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_aes_gcm_decrypt_finish(
                ctx_ptr,
                tag.as_ptr(),
                tag.len() as u64,
                &mut is_verified,
            )
        });

        unsafe { Box::from_raw(ctx_ptr) };

        match result {
            AtcaStatus::AtcaSuccess => Ok(is_verified),
            _ => Err(result),
        }
    }
}
