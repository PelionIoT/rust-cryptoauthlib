use std::cmp::min;
use std::mem::MaybeUninit;

use super::{
    AtcaStatus, AteccDevice, CipherOperation, CipherParam, FeedbackMode, KeyType, NonceTarget,
};

use super::{
    ATCA_AES_DATA_SIZE, ATCA_AES_KEY_SIZE, ATCA_ATECC_SLOTS_COUNT, ATCA_ATECC_TEMPKEY_KEYID,
    ATCA_NONCE_SIZE,
};

use cryptoauthlib_sys::atca_aes_cbc_ctx_t;
use cryptoauthlib_sys::atca_aes_ctr_ctx_t;

impl AteccDevice {
    /// Function that performs encryption/decryption in AES ECB mode
    pub(crate) fn cipher_aes_ecb(
        &self,
        cipher_param: CipherParam,
        slot_id: u8,
        data: &mut Vec<u8>,
        operation: CipherOperation,
    ) -> AtcaStatus {
        const BLOCK_IDX: u8 = 0;

        let slot: u16;
        match self.cipher_aes_common(slot_id, data.len(), cipher_param.key) {
            Ok(val) => slot = val,
            Err(err) => return err,
        }

        if (data.len() % ATCA_AES_DATA_SIZE) != 0x00 {
            return AtcaStatus::AtcaInvalidSize;
        }

        for idx in 0..(data.len() / ATCA_AES_DATA_SIZE) {
            let start_pos = idx * ATCA_AES_DATA_SIZE;
            let end_pos = start_pos + ATCA_AES_DATA_SIZE;

            match operation {
                CipherOperation::Encrypt => {
                    match self.aes_encrypt_block(slot, BLOCK_IDX, &data[start_pos..end_pos]) {
                        Ok(encr_block) => data[start_pos..end_pos].clone_from_slice(&encr_block),
                        Err(err) => return err,
                    }
                }
                CipherOperation::Decrypt => {
                    match self.aes_decrypt_block(slot, BLOCK_IDX, &data[start_pos..end_pos]) {
                        Ok(decr_block) => data[start_pos..end_pos].clone_from_slice(&decr_block),
                        Err(err) => return err,
                    }
                }
            }
        }

        AtcaStatus::AtcaSuccess
    } // AteccDevice::cipher_aes_ecb()

    /// Function that performs encryption/decryption in AES CBC mode
    pub(crate) fn cipher_aes_cbc(
        &self,
        cipher_param: CipherParam,
        slot_id: u8,
        data: &mut Vec<u8>,
        operation: CipherOperation,
    ) -> AtcaStatus {
        match self.cipher_aes_common(slot_id, data.len(), cipher_param.key) {
            Ok(_) => (),
            Err(err) => return err,
        }

        if (data.len() % ATCA_AES_DATA_SIZE) != 0x00 {
            return AtcaStatus::AtcaInvalidSize;
        }
        if cipher_param.iv.is_none() {
            return AtcaStatus::AtcaBadParam;
        }

        let mut ctx: atca_aes_cbc_ctx_t;
        match self.aes_cbc_init(slot_id, &cipher_param.iv.unwrap()) {
            Ok(val) => ctx = val,
            Err(err) => return err,
        }

        let mut block: [u8; ATCA_AES_DATA_SIZE] = [0x00; ATCA_AES_DATA_SIZE];

        for idx in 0..(data.len() / ATCA_AES_DATA_SIZE) {
            let start_pos = idx * ATCA_AES_DATA_SIZE;
            let end_pos = start_pos + ATCA_AES_DATA_SIZE;

            match operation {
                CipherOperation::Encrypt => {
                    match self.aes_cbc_encrypt_block(ctx, &data[start_pos..end_pos], &mut block) {
                        Ok(val) => ctx = val,
                        Err(err) => return err,
                    }
                }
                CipherOperation::Decrypt => {
                    match self.aes_cbc_decrypt_block(ctx, &data[start_pos..end_pos], &mut block) {
                        Ok(val) => ctx = val,
                        Err(err) => return err,
                    }
                }
            }
            data[start_pos..end_pos].clone_from_slice(&block)
        }

        AtcaStatus::AtcaSuccess
    } // AteccDevice::cipher_aes_cbc()

    /// Function that performs encryption/decryption in AES CBC with PKCS#7 padding mode
    pub(crate) fn cipher_aes_cbc_pkcs7(
        &self,
        cipher_param: CipherParam,
        slot_id: u8,
        data: &mut Vec<u8>,
        operation: CipherOperation,
    ) -> AtcaStatus {
        if data.is_empty() {
            return AtcaStatus::AtcaInvalidSize;
        }

        if operation == CipherOperation::Encrypt {
            let padding: u8 = (ATCA_AES_DATA_SIZE - (data.len() % ATCA_AES_DATA_SIZE)) as u8;
            let extended_data: Vec<u8> = vec![padding; padding as usize];

            data.extend_from_slice(&extended_data);
        }

        let result = self.cipher_aes_cbc(cipher_param, slot_id, data, operation);
        if AtcaStatus::AtcaSuccess != result {
            return result;
        }

        if operation == CipherOperation::Decrypt {
            let padding: u8 = data[data.len() - 1];
            if padding as usize > ATCA_AES_DATA_SIZE {
                return AtcaStatus::AtcaInvalidSize;
            }
            data.resize(data.len() - padding as usize, 0x00);
            data.shrink_to_fit();
        }

        AtcaStatus::AtcaSuccess
    } // AteccDevice::cipher_aes_cbc_pkcs7()

    /// Function that performs encryption/decryption in AES CTR mode
    pub(crate) fn cipher_aes_ctr(
        &self,
        cipher_param: CipherParam,
        slot_id: u8,
        data: &mut Vec<u8>,
    ) -> AtcaStatus {
        match self.cipher_aes_common(slot_id, data.len(), cipher_param.key) {
            Ok(_) => (),
            Err(err) => return err,
        }
        if cipher_param.iv.is_none() || cipher_param.counter_size.is_none() {
            return AtcaStatus::AtcaBadParam;
        }
        if cipher_param.counter_size.is_some()
            && (cipher_param.counter_size.unwrap() > (ATCA_AES_DATA_SIZE as u8))
        {
            return AtcaStatus::AtcaInvalidSize;
        }

        let mut ctx: atca_aes_ctr_ctx_t;
        match self.aes_ctr_init(
            slot_id,
            cipher_param.counter_size.unwrap(),
            &cipher_param.iv.unwrap(),
        ) {
            Ok(val) => ctx = val,
            Err(err) => return err,
        }

        let mut input: [u8; ATCA_AES_DATA_SIZE] = [0x00; ATCA_AES_DATA_SIZE];
        let mut output: [u8; ATCA_AES_DATA_SIZE] = [0x00; ATCA_AES_DATA_SIZE];
        let mut start_pos: usize = 0;
        let mut shift: usize = min(data.len(), ATCA_AES_DATA_SIZE);

        while shift > 0 {
            input[..shift].clone_from_slice(&data[start_pos..(start_pos + shift)]);

            match self.aes_ctr_block(ctx, &input, &mut output) {
                Ok(val) => ctx = val,
                Err(err) => return err,
            }

            data[start_pos..(start_pos + shift)].clone_from_slice(&output[..shift]);

            start_pos += shift;
            let remaining_bytes = data.len() - start_pos;
            match 0 == remaining_bytes {
                true => shift = 0,
                false => {
                    if remaining_bytes < ATCA_AES_DATA_SIZE {
                        shift = remaining_bytes
                    }
                }
            }
        }

        AtcaStatus::AtcaSuccess
    } // AteccDevice::cipher_aes_ctr()

    /// Function that performs encryption/decryption in AES CFB mode
    pub(crate) fn cipher_aes_cfb(
        &self,
        cipher_param: CipherParam,
        slot_id: u8,
        data: &mut Vec<u8>,
        operation: CipherOperation,
    ) -> AtcaStatus {
        self.cipher_aes_feedback(cipher_param, slot_id, data, operation, FeedbackMode::Cfb)
    } // AteccDevice::cipher_aes_cfb()

    /// Function that performs encryption/decryption in AES OFB mode
    pub(crate) fn cipher_aes_ofb(
        &self,
        cipher_param: CipherParam,
        slot_id: u8,
        data: &mut Vec<u8>,
        operation: CipherOperation,
    ) -> AtcaStatus {
        self.cipher_aes_feedback(cipher_param, slot_id, data, operation, FeedbackMode::Ofb)
    } // AteccDevice::cipher_aes_ofb()

    /// Function that performs common encryption/decryption in AES cipher feedback modes
    fn cipher_aes_feedback(
        &self,
        cipher_param: CipherParam,
        slot_id: u8,
        data: &mut Vec<u8>,
        operation: CipherOperation,
        mode: FeedbackMode,
    ) -> AtcaStatus {
        const BLOCK_IDX: u8 = 0;

        let slot: u16;
        match self.cipher_aes_common(slot_id, data.len(), cipher_param.key) {
            Ok(val) => slot = val,
            Err(err) => return err,
        }
        if cipher_param.iv.is_none() {
            return AtcaStatus::AtcaBadParam;
        }

        let mut block: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE];
        let mut start_pos: usize = 0;
        let mut shift: usize = min(data.len(), ATCA_AES_DATA_SIZE);
        block.clone_from_slice(&cipher_param.iv.unwrap());

        while shift > 0 {
            if CipherOperation::Encrypt == operation {
                match self.aes_encrypt_block(slot, BLOCK_IDX, &block) {
                    Ok(encr_block) => {
                        block = encr_block
                            .iter()
                            .zip(data[start_pos..(shift + start_pos)].iter())
                            .map(|(&x1, &x2)| x1 ^ x2)
                            .collect();
                        data[start_pos..(shift + start_pos)].clone_from_slice(&block);
                        if FeedbackMode::Ofb == mode && (ATCA_AES_DATA_SIZE == shift) {
                            block[..shift].clone_from_slice(&encr_block[..shift])
                        }
                    }
                    Err(err) => return err,
                }
            } else {
                match self.aes_encrypt_block(slot, BLOCK_IDX, &block) {
                    Ok(mut decr_block) => {
                        if FeedbackMode::Cfb == mode {
                            block[..shift].clone_from_slice(&data[start_pos..(shift + start_pos)]);
                            decr_block
                                .iter_mut()
                                .zip(block.iter())
                                .for_each(|(x1, x2)| *x1 ^= *x2);
                            data[start_pos..(shift + start_pos)]
                                .clone_from_slice(&decr_block[..shift]);
                        } else {
                            block = decr_block
                                .iter()
                                .zip(data[start_pos..(shift + start_pos)].iter())
                                .map(|(&x1, &x2)| x1 ^ x2)
                                .collect();
                            data[start_pos..(shift + start_pos)].clone_from_slice(&block);
                            if ATCA_AES_DATA_SIZE == shift {
                                block.clone_from_slice(&decr_block)
                            }
                        }
                    }
                    Err(err) => return err,
                }
            }

            start_pos += shift;
            let remaining_bytes = data.len() - start_pos;
            match 0 == remaining_bytes {
                true => shift = 0,
                false => {
                    if remaining_bytes < ATCA_AES_DATA_SIZE {
                        shift = remaining_bytes
                    }
                }
            }
        }

        AtcaStatus::AtcaSuccess
    } // AteccDevice::cipher_aes_feedback()

    /// Initialize context for AES CTR operation with an existing IV
    pub(crate) fn aes_ctr_init(
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
    } // AteccDevice::aes_ctr_init()

    /// Increments AES CTR counter value
    pub(crate) fn aes_ctr_increment(
        &self,
        ctx: atca_aes_ctr_ctx_t,
    ) -> Result<atca_aes_ctr_ctx_t, AtcaStatus> {
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
    } // AteccDevice::aes_ctr_increment()

    /// Process a block of data using CTR mode and a key within the device.
    /// aes_ctr_init() should be called before the first use of this function.
    pub(crate) fn aes_ctr_block(
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
    } // AteccDevice::aes_ctr_block()

    /// Initialize context for AES CBC operation.
    pub(crate) fn aes_cbc_init(
        &self,
        slot_id: u8,
        iv: &[u8],
    ) -> Result<atca_aes_cbc_ctx_t, AtcaStatus> {
        const BLOCK_IDX: u8 = 0;

        if iv.len() != ATCA_AES_DATA_SIZE {
            return Err(AtcaStatus::AtcaInvalidSize);
        }
        let mut slot = slot_id as u16;
        if slot_id == ATCA_ATECC_SLOTS_COUNT {
            slot = ATCA_ATECC_TEMPKEY_KEYID;
        }

        let ctx: atca_aes_cbc_ctx_t = {
            let ctx = MaybeUninit::<atca_aes_cbc_ctx_t>::zeroed();
            unsafe { ctx.assume_init() }
        };
        let ctx_ptr = Box::into_raw(Box::new(ctx));

        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_aes_cbc_init(ctx_ptr, slot, BLOCK_IDX, iv.as_ptr())
        });

        match result {
            AtcaStatus::AtcaSuccess => Ok({
                let result = unsafe { *ctx_ptr };
                unsafe { Box::from_raw(ctx_ptr) };
                result
            }),
            _ => Err(result),
        }
    } // AteccDevice::aes_cbc_init()

    /// Encrypt a block of data using CBC mode and a key within the device.
    /// aes_cbc_init() should be called before the first use of this function.
    pub(crate) fn aes_cbc_encrypt_block(
        &self,
        ctx: atca_aes_cbc_ctx_t,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<atca_aes_cbc_ctx_t, AtcaStatus> {
        let ctx_ptr = Box::into_raw(Box::new(ctx));

        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_aes_cbc_encrypt_block(
                ctx_ptr,
                plaintext.as_ptr(),
                ciphertext.as_mut_ptr(),
            )
        });

        let ctx = unsafe { *ctx_ptr };
        unsafe { Box::from_raw(ctx_ptr) };

        match result {
            AtcaStatus::AtcaSuccess => Ok(ctx),
            _ => Err(result),
        }
    } // AteccDevice::aes_cbc_encrypt_block()

    /// Decrypt a block of data using CBC mode and a key within the device.
    /// aes_cbc_init() should be called before the first use of this function.
    pub(crate) fn aes_cbc_decrypt_block(
        &self,
        ctx: atca_aes_cbc_ctx_t,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<atca_aes_cbc_ctx_t, AtcaStatus> {
        let ctx_ptr = Box::into_raw(Box::new(ctx));

        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_aes_cbc_decrypt_block(
                ctx_ptr,
                ciphertext.as_ptr(),
                plaintext.as_mut_ptr(),
            )
        });

        let ctx = unsafe { *ctx_ptr };
        unsafe { Box::from_raw(ctx_ptr) };

        match result {
            AtcaStatus::AtcaSuccess => Ok(ctx),
            _ => Err(result),
        }
    } // AteccDevice::aes_cbc_decrypt_block()

    /// Perform an AES-128 encrypt operation with a key in the device
    pub(crate) fn aes_encrypt_block(
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
    } // AteccDevice::aes_encrypt_block()

    /// Perform an AES-128 decrypt operation with a key in the device
    pub(crate) fn aes_decrypt_block(
        &self,
        key_id: u16,
        key_block: u8,
        input: &[u8],
    ) -> Result<[u8; ATCA_AES_DATA_SIZE], AtcaStatus> {
        if input.len() != ATCA_AES_DATA_SIZE {
            return Err(AtcaStatus::AtcaInvalidSize);
        }

        let mut plaintext: [u8; ATCA_AES_DATA_SIZE] = [0x00; ATCA_AES_DATA_SIZE];

        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_aes_decrypt(
                key_id,
                key_block,
                input.as_ptr(),
                plaintext.as_mut_ptr(),
            )
        });

        match result {
            AtcaStatus::AtcaSuccess => Ok(plaintext),
            _ => Err(result),
        }
    } // AteccDevice::aes_decrypt_block()

    /// A helper function that implements common input parameter tests
    /// and set for AES cipher modes
    fn cipher_aes_common(
        &self,
        slot_id: u8,
        data_size: usize,
        key: Option<Vec<u8>>,
    ) -> Result<u16, AtcaStatus> {
        if (slot_id > ATCA_ATECC_SLOTS_COUNT)
            || ((slot_id < ATCA_ATECC_SLOTS_COUNT)
                && (self.slots[slot_id as usize].config.key_type != KeyType::Aes))
        {
            return Err(AtcaStatus::AtcaInvalidId);
        }
        if (ATCA_ATECC_SLOTS_COUNT == slot_id)
            && (key.is_none()
                || (key.is_some() && (key.as_ref().unwrap().len() != ATCA_AES_KEY_SIZE)))
        {
            return Err(AtcaStatus::AtcaBadParam);
        }
        if 0 == data_size {
            return Err(AtcaStatus::AtcaInvalidSize);
        }

        let mut slot = slot_id as u16;
        if slot_id == ATCA_ATECC_SLOTS_COUNT {
            slot = ATCA_ATECC_TEMPKEY_KEYID;
            if let Some(val) = &key {
                let mut key: Vec<u8> = val.to_vec();
                key.resize_with(ATCA_NONCE_SIZE, || 0x00);
                let result = self.nonce(NonceTarget::TempKey, &key);
                if AtcaStatus::AtcaSuccess != result {
                    return Err(result);
                }
            }
        }

        Ok(slot)
    } // AteccDevice::cipher_aes_common()
}
