use std::cmp::min;
use std::mem::MaybeUninit;

use super::{AtcaDeviceType, AtcaStatus, AteccDevice, KeyType, MacParam, NonceTarget};

use super::{
    ATCA_AES_DATA_SIZE, ATCA_AES_KEY_SIZE, ATCA_ATECC_SLOTS_COUNT, ATCA_ATECC_TEMPKEY_KEYID,
    ATCA_NONCE_SIZE, ATCA_SHA2_256_DIGEST_SIZE, SHA_MODE_TARGET_TEMPKEY,
};

use cryptoauthlib_sys::atca_aes_cmac_ctx_t;

impl AteccDevice {
    /// function that calculates the MAC code of the HMAC-SHA256 type
    pub(crate) fn compute_mac_hmac_sha256(
        &self,
        mac_param: MacParam,
        slot_id: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, AtcaStatus> {
        let mut mac_length: u8 = ATCA_SHA2_256_DIGEST_SIZE as u8;
        if let Some(val) = &mac_param.mac_length {
            mac_length = *val
        };

        let mac = self.common_mac_hmac_sha256(mac_param, slot_id, data, mac_length as usize)?;

        Ok(mac)
    } // AteccDevice::compute_mac_hmac_sha256()

    /// function that verifies the MAC code of the HMAC-SHA256 type
    pub(crate) fn verify_mac_hmac_sha256(
        &self,
        mac_param: MacParam,
        slot_id: u8,
        data: &[u8],
    ) -> Result<bool, AtcaStatus> {
        let mac_to_check: Vec<u8>;

        if let Some(val) = mac_param.mac.clone() {
            mac_to_check = val;
        } else {
            return Err(AtcaStatus::AtcaBadParam);
        }

        let mac = self.common_mac_hmac_sha256(mac_param, slot_id, data, mac_to_check.len())?;

        Ok(mac == mac_to_check)
    } // AteccDevice::verify_mac_hmac_sha256()

    /// a helper function implementing common functionality for HMAC-SHA256
    fn common_mac_hmac_sha256(
        &self,
        mac_param: MacParam,
        slot_id: u8,
        data: &[u8],
        mac_length: usize,
    ) -> Result<Vec<u8>, AtcaStatus> {
        let result = self.common_mac_hmac(mac_param, slot_id);
        if result != AtcaStatus::AtcaSuccess {
            return Err(result);
        }
        let mut slot = slot_id as u16;
        if slot_id == ATCA_ATECC_SLOTS_COUNT {
            slot = ATCA_ATECC_TEMPKEY_KEYID;
        }

        let mut mac: [u8; ATCA_SHA2_256_DIGEST_SIZE] = [0x00; ATCA_SHA2_256_DIGEST_SIZE];

        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_sha_hmac(
                data.as_ptr(),
                data.len() as u64,
                slot,
                mac.as_mut_ptr(),
                SHA_MODE_TARGET_TEMPKEY,
            )
        });

        match result {
            AtcaStatus::AtcaSuccess => Ok({
                let mut out_mac: Vec<u8> = vec![0x00; mac_length as usize];
                out_mac.copy_from_slice(&mac[..mac_length as usize]);
                out_mac
            }),
            _ => Err(result),
        }
    } // AteccDevice::common_mac_hmac_sha256()

    /// function that calculates the MAC code of the CMAC type
    pub(crate) fn compute_mac_cmac(
        &self,
        mac_param: MacParam,
        slot_id: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, AtcaStatus> {
        let mut mac_length: u8 = ATCA_AES_DATA_SIZE as u8;
        if let Some(val) = &mac_param.mac_length {
            mac_length = *val
        };

        let mac = self.common_mac_cmac(mac_param, slot_id, data, mac_length as usize)?;

        Ok(mac)
    } // AteccDevice::compute_mac_cmac()

    /// function that verifies the MAC code of the CMAC type
    pub(crate) fn verify_mac_cmac(
        &self,
        mac_param: MacParam,
        slot_id: u8,
        data: &[u8],
    ) -> Result<bool, AtcaStatus> {
        let mac_to_check: Vec<u8>;

        if let Some(val) = mac_param.mac.clone() {
            mac_to_check = val;
        } else {
            return Err(AtcaStatus::AtcaBadParam);
        }

        let mac = self.common_mac_cmac(mac_param, slot_id, data, mac_to_check.len())?;

        Ok(mac == mac_to_check)
    } // AteccDevice::verify_mac_cmac()

    /// a helper function implementing common functionality for CMAC
    fn common_mac_cmac(
        &self,
        mac_param: MacParam,
        slot_id: u8,
        data: &[u8],
        mac_length: usize,
    ) -> Result<Vec<u8>, AtcaStatus> {
        let result = self.common_mac(mac_param, slot_id);
        if result != AtcaStatus::AtcaSuccess {
            return Err(result);
        }

        let mut ctx = self.aes_cmac_init(slot_id)?;

        let mut start_pos: usize = 0;
        let mut shift: usize = min(data.len(), ATCA_AES_DATA_SIZE);
        while shift > 0 {
            let block = &data[start_pos..(start_pos + shift)];
            ctx = self.aes_cmac_update(ctx, block)?;
            start_pos += shift;
            let remaining_bytes = data.len() - start_pos;
            if remaining_bytes < ATCA_AES_DATA_SIZE {
                shift = remaining_bytes
            }
        }

        let mac = self.aes_cmac_finish(ctx, mac_length as u8)?;
        Ok(mac)
    } // AteccDevice::common_mac_cmac()

    /// function that calculates the MAC code of the CBC-MAC type
    /// read this: https://blog.cryptographyengineering.com/2013/02/15/why-i-hate-cbc-mac/ and don't use this mode directly
    pub(crate) fn compute_mac_cbcmac(
        &self,
        mac_param: MacParam,
        slot_id: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, AtcaStatus> {
        let mut mac_length: u8 = ATCA_AES_DATA_SIZE as u8;
        if let Some(val) = &mac_param.mac_length {
            mac_length = *val
        };

        let mac = self.common_mac_cbcmac(mac_param, slot_id, data, mac_length as usize)?;

        Ok(mac)
    } // AteccDevice::compute_mac_cbcmac()

    /// function that verifies the MAC code of the CBC-MAC type
    /// read this: https://blog.cryptographyengineering.com/2013/02/15/why-i-hate-cbc-mac/ and don't use this mode directly
    pub(crate) fn verify_mac_cbcmac(
        &self,
        mac_param: MacParam,
        slot_id: u8,
        data: &[u8],
    ) -> Result<bool, AtcaStatus> {
        let mac_to_check: Vec<u8>;

        if let Some(val) = mac_param.mac.clone() {
            mac_to_check = val;
        } else {
            return Err(AtcaStatus::AtcaBadParam);
        }

        let mac = self.common_mac_cbcmac(mac_param, slot_id, data, mac_to_check.len())?;

        Ok(mac == mac_to_check)
    } // AteccDevice::verify_mac_cbcmac()

    /// a helper function implementing common functionality for CBC-MAC
    fn common_mac_cbcmac(
        &self,
        mac_param: MacParam,
        slot_id: u8,
        data: &[u8],
        mac_length: usize,
    ) -> Result<Vec<u8>, AtcaStatus> {
        let result = self.common_mac(mac_param, slot_id);
        if result != AtcaStatus::AtcaSuccess {
            return Err(result);
        }

        let mut ctx = self.aes_cbcmac_init(slot_id);

        let mut start_pos: usize = 0;
        let mut shift: usize = min(data.len(), ATCA_AES_DATA_SIZE);
        while shift > 0 {
            let block = &data[start_pos..(start_pos + shift)];
            ctx = self.aes_cbcmac_update(ctx, block)?;
            start_pos += shift;
            let remaining_bytes = data.len() - start_pos;
            if remaining_bytes < ATCA_AES_DATA_SIZE {
                shift = remaining_bytes
            }
        }

        let mac = self.aes_cbcmac_finish(ctx, mac_length)?;
        Ok(mac)
    } // AteccDevice::common_mac_cbcmac()

    /// Initialize a CMAC calculation using an AES-128 key in the device
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
    } // AteccDevice::aes_cmac_init()

    /// Add data to an initialized CMAC calculation
    fn aes_cmac_update(
        &self,
        ctx: atca_aes_cmac_ctx_t,
        data: &[u8],
    ) -> Result<atca_aes_cmac_ctx_t, AtcaStatus> {
        if data.len() > ATCA_AES_DATA_SIZE {
            return Err(AtcaStatus::AtcaInvalidSize);
        }

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
    } // AteccDevice::aes_cmac_update()

    /// Finish a CMAC operation returning the CMAC value
    fn aes_cmac_finish(
        &self,
        ctx: atca_aes_cmac_ctx_t,
        mac_length: u8,
    ) -> Result<Vec<u8>, AtcaStatus> {
        let ctx_ptr = Box::into_raw(Box::new(ctx));
        let mut mac: [u8; ATCA_AES_DATA_SIZE] = [0; ATCA_AES_DATA_SIZE];

        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_aes_cmac_finish(ctx_ptr, mac.as_mut_ptr(), mac_length as u32)
        });

        unsafe { Box::from_raw(ctx_ptr) };

        match result {
            AtcaStatus::AtcaSuccess => Ok({
                let mut out_mac: Vec<u8> = vec![0x00; mac_length as usize];
                out_mac.copy_from_slice(&mac[..mac_length as usize]);
                out_mac
            }),
            _ => Err(result),
        }
    } // AteccDevice::aes_cmac_finish()

    /// Initialize context for AES CBC-MAC operation
    pub(crate) fn aes_cbcmac_init(&self, slot_id: u8) -> atca_aes_cmac_ctx_t {
        let mut slot = slot_id as u16;
        if slot_id == ATCA_ATECC_SLOTS_COUNT {
            slot = ATCA_ATECC_TEMPKEY_KEYID;
        }

        let mut ctx: atca_aes_cmac_ctx_t = {
            let ctx = MaybeUninit::<atca_aes_cmac_ctx_t>::zeroed();
            unsafe { ctx.assume_init() }
        };

        ctx.cbc_ctx.key_id = slot;
        ctx.cbc_ctx.key_block = 0x00;

        ctx
    } // AteccDevice::aes_cbcmac_init()

    /// Calculate AES CBC-MAC with key stored within ECC608A device.
    /// aes_cbcmac_init() should be called before the first use of this function.
    pub(crate) fn aes_cbcmac_update(
        &self,
        ctx: atca_aes_cmac_ctx_t,
        data: &[u8],
    ) -> Result<atca_aes_cmac_ctx_t, AtcaStatus> {
        if data.is_empty() {
            // Nothing to do
            return Ok(ctx);
        }

        // Process full blocks of data with AES-CBC
        let mut temp_ctx = ctx;
        let mut idx: usize = 0;
        let mut buffer: [u8; ATCA_AES_DATA_SIZE] = [0x00; ATCA_AES_DATA_SIZE];

        for i in 0..(data.len() / ATCA_AES_DATA_SIZE) {
            let start_pos = i * ATCA_AES_DATA_SIZE;
            let end_pos = start_pos + ATCA_AES_DATA_SIZE;
            idx += 1;

            temp_ctx.cbc_ctx = self.aes_cbc_encrypt_block(
                temp_ctx.cbc_ctx,
                &data[start_pos..end_pos],
                &mut buffer,
            )?;
        }

        // Store incomplete block to context structure
        let start_pos = idx * ATCA_AES_DATA_SIZE;
        match start_pos < data.len() {
            true => {
                temp_ctx.block_size = (data.len() - start_pos) as u32;
                temp_ctx.block[..(temp_ctx.block_size as usize)]
                    .copy_from_slice(&data[start_pos..(start_pos + temp_ctx.block_size as usize)]);
            }
            false => temp_ctx.block_size = 0,
        }

        Ok(temp_ctx)
    } // AteccDevice::aes_cbcmac_update()

    /// Finish a CBC-MAC operation returning the CBC-MAC value. If the data
    /// provided to the aes_cbcmac_update() function has incomplete
    /// block this function will return an error code
    pub(crate) fn aes_cbcmac_finish(
        &self,
        ctx: atca_aes_cmac_ctx_t,
        tag_size: usize,
    ) -> Result<Vec<u8>, AtcaStatus> {
        let mut tag: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE];
        if tag_size > ATCA_AES_DATA_SIZE {
            return Err(AtcaStatus::AtcaBadParam);
        }

        // Check for incomplete data block
        if ctx.block_size != 0 {
            return Err(AtcaStatus::AtcaInvalidSize); // Returns INVALID_SIZE if incomplete blocks are present
        }

        // All processing is already done, copying the mac to result buffer
        tag[..tag_size].copy_from_slice(&ctx.cbc_ctx.ciphertext[..tag_size]);
        tag.resize(tag_size, 0x00);
        tag.shrink_to_fit();
        Ok(tag)
    } // AteccDevice::aes_cbcmac_finish()

    /// auxiliary function checking input parameters common to CMAC and CBC-MAC modes
    fn common_mac(&self, mac_param: MacParam, slot_id: u8) -> AtcaStatus {
        const MIN_MAC_SIZE: usize = 1;
        const MAX_MAC_SIZE: usize = ATCA_AES_DATA_SIZE;

        if (slot_id > ATCA_ATECC_SLOTS_COUNT)
            || ((slot_id < ATCA_ATECC_SLOTS_COUNT)
                && (self.slots[slot_id as usize].config.key_type != KeyType::Aes))
        {
            return AtcaStatus::AtcaInvalidId;
        }
        if (ATCA_ATECC_SLOTS_COUNT == slot_id) && mac_param.key.is_none()
            || (mac_param.mac_length.is_some() && mac_param.mac.is_some())
        {
            return AtcaStatus::AtcaBadParam;
        }
        if (mac_param.mac_length.is_some()
            && ((mac_param.mac_length < Some(MIN_MAC_SIZE as u8))
                || (mac_param.mac_length > Some(MAX_MAC_SIZE as u8))))
            || (mac_param.mac.is_some()
                && ((mac_param.mac.as_ref().unwrap().len() < MIN_MAC_SIZE)
                    || (mac_param.mac.as_ref().unwrap().len() > MAX_MAC_SIZE)))
            || (mac_param.key.is_some()
                && (mac_param.key.as_ref().unwrap().len() != ATCA_AES_KEY_SIZE))
        {
            return AtcaStatus::AtcaInvalidSize;
        }

        if let Some(mut key) = mac_param.key {
            key.resize(ATCA_NONCE_SIZE, 0x00);
            let result = self.nonce(NonceTarget::TempKey, &key);
            if AtcaStatus::AtcaSuccess != result {
                return result;
            }
        }

        AtcaStatus::AtcaSuccess
    }

    // auxiliary function checking input parameters for the HMAC-SHA256 mode
    fn common_mac_hmac(&self, mac_param: MacParam, slot_id: u8) -> AtcaStatus {
        const MIN_MAC_SIZE: usize = 1;
        const MAX_MAC_SIZE: usize = ATCA_SHA2_256_DIGEST_SIZE;

        if (slot_id > ATCA_ATECC_SLOTS_COUNT)
            || ((slot_id < ATCA_ATECC_SLOTS_COUNT)
                && (self.slots[slot_id as usize].config.key_type != KeyType::ShaOrText))
        {
            return AtcaStatus::AtcaInvalidId;
        }
        if (ATCA_ATECC_SLOTS_COUNT == slot_id)
            && (mac_param.key.is_none() || (self.get_device_type() != AtcaDeviceType::ATECC608A))
            || (mac_param.mac_length.is_some() && mac_param.mac.is_some())
        {
            return AtcaStatus::AtcaBadParam;
        }
        if (mac_param.mac_length.is_some()
            && ((mac_param.mac_length < Some(MIN_MAC_SIZE as u8))
                || (mac_param.mac_length > Some(MAX_MAC_SIZE as u8))))
            || (mac_param.mac.is_some()
                && ((mac_param.mac.as_ref().unwrap().len() < MIN_MAC_SIZE)
                    || (mac_param.mac.as_ref().unwrap().len() > MAX_MAC_SIZE)))
            || (mac_param.key.is_some()
                && (mac_param.key.as_ref().unwrap().len() > ATCA_SHA2_256_DIGEST_SIZE))
        {
            return AtcaStatus::AtcaInvalidSize;
        }

        if let Some(mut key) = mac_param.key {
            key.resize(ATCA_NONCE_SIZE, 0x00);
            let result = self.nonce(NonceTarget::TempKey, &key);
            if AtcaStatus::AtcaSuccess != result {
                return result;
            }
        }

        AtcaStatus::AtcaSuccess
    }
}
