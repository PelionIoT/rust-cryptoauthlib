use std::cmp::min;
use std::mem::MaybeUninit;

use super::{AeadParam, AtcaAesCcmCtx, AtcaStatus, AteccDevice, KeyType, NonceTarget};

use super::{
    ATCA_AES_DATA_SIZE, ATCA_ATECC_SLOTS_COUNT, ATCA_ATECC_TEMPKEY_KEYID, ATCA_NONCE_SIZE,
};

use cryptoauthlib_sys::atca_aes_cbc_ctx_t;
use cryptoauthlib_sys::atca_aes_cmac_ctx_t;
use cryptoauthlib_sys::atca_aes_ctr_ctx_t;

impl AteccDevice {
    /// function that performs encryption in AES CCM mode
    pub(crate) fn encrypt_aes_ccm(
        &self,
        aead_param: AeadParam,
        slot_id: u8,
        data: &mut [u8],
    ) -> Result<Vec<u8>, AtcaStatus> {
        let mut ctx: AtcaAesCcmCtx = self.common_aes_ccm(aead_param, slot_id, data)?;
        ctx = self.aes_ccm_update(ctx, data, true)?;

        let result = self.aes_ccm_finish(ctx)?;
        Ok(result)
    }

    /// function that performs decryption in AES CCM mode
    pub(crate) fn decrypt_aes_ccm(
        &self,
        aead_param: AeadParam,
        slot_id: u8,
        data: &mut [u8],
    ) -> Result<bool, AtcaStatus> {
        let tag_to_check: Vec<u8>;

        if let Some(val) = aead_param.tag.clone() {
            tag_to_check = val;
        } else {
            return Err(AtcaStatus::AtcaBadParam);
        }

        let mut ctx: AtcaAesCcmCtx = self.common_aes_ccm(aead_param, slot_id, data)?;
        ctx = self.aes_ccm_update(ctx, data, false)?;

        let result = self.aes_ccm_decrypt_finish(ctx, &tag_to_check)?;
        Ok(result)
    }

    /// a helper function implementing common functionality for AES CCM encryption and decryption
    fn common_aes_ccm(
        &self,
        aead_param: AeadParam,
        slot_id: u8,
        data: &mut [u8],
    ) -> Result<AtcaAesCcmCtx, AtcaStatus> {
        const MAX_IV_SIZE: usize = 13;
        const MIN_IV_SIZE: usize = 7;
        const MAX_TAG_SIZE: usize = ATCA_AES_DATA_SIZE;
        const MIN_TAG_SIZE: usize = 4;
        const MAX_AAD_SIZE: usize = 0xFEFF; // RFC-3610 -> (2^16) - (2^8) - 1;

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
                    || (aead_param.tag_length > Some(MAX_TAG_SIZE as u8))
                    || (aead_param.tag_length.unwrap() % 2 != 0)))
            || (aead_param.tag.is_some()
                && ((aead_param.tag.clone().unwrap().len() < MIN_TAG_SIZE)
                    || (aead_param.tag.clone().unwrap().len() > MAX_TAG_SIZE)
                    || (aead_param.tag.clone().unwrap().len() % 2 != 0)))
        {
            return Err(AtcaStatus::AtcaInvalidSize);
        }

        let mut tag_length: usize = ATCA_AES_DATA_SIZE;
        if let Some(val) = &aead_param.tag_length {
            tag_length = *val as usize
        } else if let Some(val) = &aead_param.tag {
            tag_length = val.len();
        }

        if let Some(val) = &aead_param.key {
            let mut key: Vec<u8> = val.to_vec();
            key.resize_with(ATCA_NONCE_SIZE, || 0x00);
            let result = self.nonce(NonceTarget::TempKey, &key);
            if AtcaStatus::AtcaSuccess != result {
                return Err(result)
            }
        }

        let iv: Vec<u8> = aead_param.nonce;
        let mut additional_data_size: usize = 0;
        if let Some(val) = &aead_param.additional_data {
            additional_data_size = val.len();
            if additional_data_size > MAX_AAD_SIZE {
                return Err(AtcaStatus::AtcaInvalidSize);
            }
        };
        let data_size = data.len();
        let mut ctx: AtcaAesCcmCtx = self.aes_ccm_init(slot_id, &iv, additional_data_size, data_size, tag_length)?;

        if let Some(data_to_sign) = &aead_param.additional_data {
            ctx = self.aes_ccm_aad_update(ctx, &data_to_sign)?;
        }

        Ok(ctx)
    }

    /// Initialize context for AES CCM operation with an existing IV, which
    /// is common when starting a decrypt operation
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
        b[1..=iv.len()].clone_from_slice(&iv);

        // Update length field in B0 block.
        let mut size_left: usize = text_size;

        for i in 0..=l {
            b[(15 - i) as usize] = (size_left & 0xFF) as u8;
            size_left >>= 8;
        }

        // Init CBC-MAC context
        ctx.cbc_mac_ctx = self.aes_cbcmac_init(slot_id);

        // Processing initial block B0 through CBC-MAC.
        ctx.cbc_mac_ctx = self.aes_cbcmac_update(ctx.cbc_mac_ctx, &b)?;

        if aad_size > 0 {
            // Loading AAD size in ctx buffer.
            ctx.partial_aad[0] = ((aad_size >> 8) & 0xFF) as u8;
            ctx.partial_aad[1] = (aad_size & 0xFF) as u8;
            ctx.partial_aad_size = 2;
        }

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
        let counter_size: u8 = (ATCA_AES_DATA_SIZE - iv.len() - 1) as u8;
        ctx.ctr_ctx = self.aes_ctr_init(slot_id, counter_size, &counter)?;

        // Increment the counter to skip the first block, first will be later reused to get tag.
        ctx.ctr_ctx = self.aes_ctr_increment(ctx.ctr_ctx)?;
        Ok(ctx)
    }

    /// Process Additional Authenticated Data (AAD) using CCM mode and a
    /// key within the ATECC608A device
    fn aes_ccm_aad_update(
        &self,
        ctx: AtcaAesCcmCtx,
        data: &[u8],
    ) -> Result<AtcaAesCcmCtx, AtcaStatus> {
        if data.is_empty() {
            return Ok(ctx);
        };

        let mut temp_ctx: AtcaAesCcmCtx = ctx;
        let copy_size: usize;
        let mut aad_size: usize = data.len();
        let rem_size: usize = ATCA_AES_DATA_SIZE - temp_ctx.partial_aad_size;
        match aad_size > rem_size {
            true => copy_size = rem_size,
            false => copy_size = aad_size,
        }

        // Copy data into current block
        let start_pos = temp_ctx.partial_aad_size;
        let end_pos = min(ATCA_AES_DATA_SIZE, start_pos + copy_size);
        temp_ctx.partial_aad[start_pos..end_pos].clone_from_slice(&data[..copy_size]);

        if temp_ctx.partial_aad_size + aad_size < ATCA_AES_DATA_SIZE {
            // Not enough data to finish off the current block
            temp_ctx.partial_aad_size += aad_size;
            return Ok(temp_ctx);
        }

        // Process the current block
        temp_ctx.cbc_mac_ctx =
            self.aes_cbcmac_update(temp_ctx.cbc_mac_ctx, &temp_ctx.partial_aad)?;

        // Process any additional blocks
        aad_size -= copy_size; // Adjust to the remaining aad bytes
        let block_count = aad_size / ATCA_AES_DATA_SIZE;
        if block_count > 0 {
            temp_ctx.cbc_mac_ctx = self.aes_cbcmac_update(
                temp_ctx.cbc_mac_ctx,
                &data[copy_size..((block_count * ATCA_AES_DATA_SIZE) + copy_size)],
            )?;
        }

        // Save any remaining data
        temp_ctx.partial_aad_size = aad_size % ATCA_AES_DATA_SIZE;
        let start_pos = copy_size + (block_count * ATCA_AES_DATA_SIZE);
        temp_ctx.partial_aad[..temp_ctx.partial_aad_size]
            .clone_from_slice(&data[start_pos..(start_pos + temp_ctx.partial_aad_size)]);

        Ok(temp_ctx)
    }

    /// Finish processing Additional Authenticated Data (AAD) using CCM mode
    fn aes_ccm_aad_finish(&self, ctx: AtcaAesCcmCtx) -> Result<AtcaAesCcmCtx, AtcaStatus> {
        // Pad and process any incomplete aad data blocks
        let mut temp_ctx = ctx;

        if temp_ctx.partial_aad_size > 0 {
            let mut buffer: [u8; ATCA_AES_DATA_SIZE] = [0x00; ATCA_AES_DATA_SIZE];
            buffer[..temp_ctx.partial_aad_size]
                .copy_from_slice(&temp_ctx.partial_aad[..temp_ctx.partial_aad_size]);

            temp_ctx.cbc_mac_ctx = self.aes_cbcmac_update(temp_ctx.cbc_mac_ctx, &buffer)?;

            // Reset ctx partial aad size variable
            temp_ctx.partial_aad_size = 0
        }

        Ok(temp_ctx)
    }

    /// Process data using CCM mode and a key within the ATECC608A device.
    /// aes_ccm_init() should be called before the first use of this function.
    fn aes_ccm_update(
        &self,
        ctx: AtcaAesCcmCtx,
        data: &mut [u8],
        is_encrypt: bool,
    ) -> Result<AtcaAesCcmCtx, AtcaStatus> {
        let mut temp_ctx = ctx;
        temp_ctx = self.aes_ccm_aad_finish(temp_ctx)?;

        if data.is_empty() {
            // Nothing to do
            return Ok(temp_ctx);
        }

        let mut data_idx: usize = 0;
        let input_size: usize = data.len();

        while data_idx < input_size {
            if 0 == (temp_ctx.data_size % (ATCA_AES_DATA_SIZE as u32)) {
                // Need to calculate next encrypted counter block
                temp_ctx.enc_cb = self.aes_encrypt_block(
                    temp_ctx.ctr_ctx.key_id,
                    temp_ctx.ctr_ctx.key_block,
                    &temp_ctx.ctr_ctx.cb,
                )?;

                // Increment counter
                temp_ctx.ctr_ctx = self.aes_ctr_increment(temp_ctx.ctr_ctx)?;
            }

            // Process data with current encrypted counter block
            let end_idx = min(ATCA_AES_DATA_SIZE, data.len() - data_idx);
            for idx in ((temp_ctx.data_size as usize) % ATCA_AES_DATA_SIZE)..end_idx {
                // Save the current ciphertext block depending on whether this is an encrypt or decrypt operation
                if is_encrypt {
                    temp_ctx.ciphertext_block[idx] = data[data_idx]
                }

                data[data_idx] ^= temp_ctx.enc_cb[idx];

                if !is_encrypt {
                    temp_ctx.ciphertext_block[idx] = data[data_idx]
                }

                temp_ctx.data_size += 1;
                data_idx += 1;
            }

            if 0 == (temp_ctx.data_size % (ATCA_AES_DATA_SIZE as u32)) {
                // Adding data to CBC-MAC to calculate tag
                temp_ctx.cbc_mac_ctx =
                    self.aes_cbcmac_update(temp_ctx.cbc_mac_ctx, &temp_ctx.ciphertext_block[..])?;
            }
        }

        Ok(temp_ctx)
    }

    /// Complete a CCM decrypt operation authenticating provided tag
    #[inline]
    fn aes_ccm_decrypt_finish(&self, ctx: AtcaAesCcmCtx, tag: &[u8]) -> Result<bool, AtcaStatus> {
        let val = self.aes_ccm_finish(ctx)?;
        let matching = tag
            .iter()
            .zip(val.iter())
            .filter(|&(tag, val)| tag == val)
            .count();
        match matching == tag.len() && matching == val.len() {
            true => Ok(true),
            false => Ok(false),
        }
    }

    /// Complete a CCM operation returning the authentication tag
    fn aes_ccm_finish(&self, ctx: AtcaAesCcmCtx) -> Result<Vec<u8>, AtcaStatus> {
        // Finish and get the tag
        let mut tag: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE];
        let mut t: [u8; ATCA_AES_DATA_SIZE] = [0x00; ATCA_AES_DATA_SIZE];
        let mut u: [u8; ATCA_AES_DATA_SIZE] = [0x00; ATCA_AES_DATA_SIZE];
        let mut buffer: [u8; ATCA_AES_DATA_SIZE] = [0x00; ATCA_AES_DATA_SIZE];
        let mut temp_ctx = ctx;

        let end_idx = (temp_ctx.data_size as usize) % ATCA_AES_DATA_SIZE;
        if end_idx != 0 {
            buffer[..end_idx].copy_from_slice(&temp_ctx.ciphertext_block[..end_idx]);

            // Adding data to CBC-MAC to calculate tag
            temp_ctx.cbc_mac_ctx = self.aes_cbcmac_update(temp_ctx.cbc_mac_ctx, &buffer)?;
        }

        // Update tag size
        let tag_size = ((temp_ctx.m * 2) + 2) as usize;

        let val = self.aes_cbcmac_finish(temp_ctx.cbc_mac_ctx, tag_size)?;
        t[..val.len()].copy_from_slice(&val[..val.len()]);

        // Init CTR mode context
        let mut slot = temp_ctx.ctr_ctx.key_id as u8;
        if temp_ctx.ctr_ctx.key_id == ATCA_ATECC_TEMPKEY_KEYID {
            slot = ATCA_ATECC_SLOTS_COUNT;
        }

        temp_ctx.ctr_ctx =
            self.aes_ctr_init(slot, temp_ctx.ctr_ctx.key_block, &temp_ctx.counter)?;
        temp_ctx.ctr_ctx = self.aes_ctr_block(temp_ctx.ctr_ctx, &t, &mut u)?;

        tag.copy_from_slice(&u);
        tag.resize(tag_size, 0x00);
        tag.shrink_to_fit();

        Ok(tag)
    }

    // -----------------------------------------------------------
    // Auxiliary functions
    // -----------------------------------------------------------

    /// Initialize context for AES CTR operation with an existing IV, which
    /// is common when start a decrypt operation
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

    /// Increments AES CTR counter value
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

    /// Process a block of data using CTR mode and a key within the device.
    /// aes_ctr_init() should be called before the first use of this function.
    fn aes_ctr_block(
        &self,
        ctx: atca_aes_ctr_ctx_t,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<atca_aes_ctr_ctx_t, AtcaStatus> {
        let ctx_ptr = Box::into_raw(Box::new(ctx));

        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_aes_ctr_block(ctx_ptr, input.as_ptr(), output.as_mut_ptr())
        });

        let ctx = unsafe { *ctx_ptr };
        unsafe { Box::from_raw(ctx_ptr) };

        match result {
            AtcaStatus::AtcaSuccess => Ok(ctx),
            _ => Err(result),
        }
    }

    /// Initialize context for AES CBC-MAC operation
    fn aes_cbcmac_init(&self, slot_id: u8) -> atca_aes_cmac_ctx_t {
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
    }

    /// Calculate AES CBC-MAC with key stored within ECC608A device.
    /// aes_cbcmac_init() should be called before the first use of this function.
    fn aes_cbcmac_update(
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

        for i in 0..(data.len() / ATCA_AES_DATA_SIZE) {
            let start_pos = i * ATCA_AES_DATA_SIZE;
            let end_pos = start_pos + ATCA_AES_DATA_SIZE;
            idx += 1;

            let val = self.aes_cbc_encrypt_block(temp_ctx.cbc_ctx, &data[start_pos..end_pos])?;
            match val.len() {
                ATCA_AES_DATA_SIZE => temp_ctx.cbc_ctx.ciphertext.copy_from_slice(&val), // Save copy of ciphertext for next block operation
                _ => return Err(AtcaStatus::AtcaFuncFail),
            }
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
    }

    /// Finish a CBC-MAC operation returning the CBC-MAC value. If the data
    /// provided to the aes_cbcmac_update() function has incomplete
    /// block this function will return an error code
    fn aes_cbcmac_finish(
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
            return Err(AtcaStatus::AtcaInvalidSize) // Returns INVALID_SIZE if incomplete blocks are present
        }

        // All processing is already done, copying the mac to result buffer
        tag[..tag_size].copy_from_slice(&ctx.cbc_ctx.ciphertext[..tag_size]);
        tag.resize(tag_size, 0x00);
        tag.shrink_to_fit();
        Ok(tag)
    }

    /// Encrypt a block of data using CBC mode and a key within the device.
    fn aes_cbc_encrypt_block(
        &self,
        ctx: atca_aes_cbc_ctx_t,
        data: &[u8],
    ) -> Result<Vec<u8>, AtcaStatus> {
        if data.is_empty() {
            return Err(AtcaStatus::AtcaBadParam);
        }
        if data.len() != ATCA_AES_DATA_SIZE {
            return Err(AtcaStatus::AtcaInvalidSize);
        }

        let mut input: [u8; ATCA_AES_DATA_SIZE] = [0x00; ATCA_AES_DATA_SIZE];
        // XOR plaintext with previous block's ciphertext to get input value to block encrypt
        for i in 0..ATCA_AES_DATA_SIZE {
            input[i] = data[i] ^ ctx.ciphertext[i];
        }

        // Block encrypt of input data
        let val = self.aes_encrypt_block(ctx.key_id, ctx.key_block, &input)?;
        Ok(val.to_vec())
    }

    /// Perform an AES-128 encrypt operation with a key in the device
    fn aes_encrypt_block(
        &self,
        key_id: u16,
        key_block: u8,
        input: &[u8],
    ) -> Result<[u8; ATCA_AES_DATA_SIZE], AtcaStatus> {
        if input.len() != ATCA_AES_DATA_SIZE {
            return Err(AtcaStatus::AtcaInvalidSize);
        }

        let mut ciphertext: [u8; ATCA_AES_DATA_SIZE] = [0x00; ATCA_AES_DATA_SIZE];

        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_aes_encrypt(
                key_id,
                key_block,
                input.as_ptr(),
                ciphertext.as_mut_ptr(),
            )
        });

        match result {
            AtcaStatus::AtcaSuccess => Ok(ciphertext),
            _ => Err(result),
        }
    }
}
