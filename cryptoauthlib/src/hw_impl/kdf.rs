use std::ptr;

use super::{
    AtcaDeviceType, AtcaStatus, AteccDevice, HkdfMsgLoc, InfoCmdType, KdfAlgorithm, KdfParams,
    KdfPrfKeyLen, KdfPrfTargetLen, KdfResult, KdfSource, KdfTarget, KeyType, OutputProtectionState,
    WriteConfig,
};

use super::{
    ATCA_AES_DATA_SIZE, ATCA_ATECC_MIN_SLOT_IDX_FOR_PUB_KEY, ATCA_ATECC_SLOTS_COUNT,
    ATCA_KDF_MAX_MSG_SIZE, ATCA_SHA2_256_DIGEST_SIZE,
};

use super::atcab_get_bit_value;

impl AteccDevice {
    /// KDF command function, which derives a new key in PRF, AES, or HKDF modes.
    /// Generally this function combines a source key with an input string and
    /// creates a result key/digest/array. (only relevant for the ATECC608x chip)
    pub(crate) fn kdf(
        &self,
        algorithm: KdfAlgorithm,
        parameters: KdfParams,
        message: Option<&[u8]>,
        message_length: usize,
    ) -> Result<KdfResult, AtcaStatus> {
        const MAX_RESULT_SIZE: usize = 64;
        const HKDF_RESULT_SIZE: usize = 32;
        const KDF_DETAILS_HKDF_ZERO_KEY: u32 = 0x00000004;
        const KDF_MODE_ALG_PRF: u8 = 0x00;
        const KDF_MODE_ALG_AES: u8 = 0x20;
        const KDF_MODE_ALG_HKDF: u8 = 0x40;

        if self.check_that_configuration_is_not_locked(true) {
            return Err(AtcaStatus::AtcaNotLocked);
        }

        self.check_kdf_input_parameters(&algorithm, &parameters, message, message_length)?;

        let fake_msg: [u8; 0x01] = [0x00];
        let msg_ptr: *const u8 = if let Some(msg) = message {
            msg.as_ptr()
        } else {
            fake_msg.as_ptr()
        };

        let mode: u8 = (parameters.source.clone() as u8)
            | (parameters.target.clone() as u8)
            | match algorithm {
                KdfAlgorithm::Prf(_) => KDF_MODE_ALG_PRF,
                KdfAlgorithm::Hkdf(_) => KDF_MODE_ALG_HKDF,
                KdfAlgorithm::Aes => KDF_MODE_ALG_AES,
            };

        let msg_len: u32 = (message_length as u32) << 24;
        let details: u32 = match algorithm.clone() {
            KdfAlgorithm::Prf(details) => {
                msg_len | (details.key_length as u32) | (details.target_length as u32)
            }
            KdfAlgorithm::Hkdf(details) => {
                let mut result = msg_len | details.msg_loc as u32;
                if details.zero_key {
                    result |= KDF_DETAILS_HKDF_ZERO_KEY
                }
                if let Some(val) = details.msg_slot {
                    result |= (val as u32) << 8
                }

                result
            }
            KdfAlgorithm::Aes => 0x00000000,
        };

        let key_id: u16 = self.parse_kdf_slot(&parameters)?;

        let mut out_data: Vec<u8> = vec![0x00; MAX_RESULT_SIZE];
        let out_data_ptr: *mut u8 = match parameters.target {
            KdfTarget::Output | KdfTarget::OutputEnc => out_data.as_mut_ptr(),
            _ => ptr::null_mut(),
        };

        let mut out_nonce: Vec<u8> = vec![0x00; MAX_RESULT_SIZE];
        let out_nonce_ptr: *mut u8 = match parameters.target {
            KdfTarget::OutputEnc => out_nonce.as_mut_ptr(),
            _ => ptr::null_mut(),
        };

        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_kdf(
                mode,
                key_id,
                details,
                msg_ptr,
                out_data_ptr,
                out_nonce_ptr,
            )
        });

        match result {
            AtcaStatus::AtcaSuccess => {
                let new_data_size = match algorithm {
                    KdfAlgorithm::Aes => ATCA_AES_DATA_SIZE,
                    KdfAlgorithm::Prf(details) => usize::from(details.target_length),
                    KdfAlgorithm::Hkdf(_details) => HKDF_RESULT_SIZE,
                };
                let new_nonce_size = match new_data_size > ATCA_SHA2_256_DIGEST_SIZE {
                    true => ATCA_SHA2_256_DIGEST_SIZE,
                    false => new_data_size,
                };
                let output = KdfResult {
                    out_data: if out_data_ptr.is_null() {
                        None
                    } else {
                        out_data.resize(new_data_size, 0x00);
                        Some(out_data)
                    },
                    out_nonce: if out_nonce_ptr.is_null() {
                        None
                    } else {
                        out_nonce.resize(new_nonce_size, 0x00);
                        Some(out_nonce)
                    },
                };
                Ok(output)
            }
            _ => Err(result),
        }
    } // AteccDevice::kdf()

    /// Auxiliary function that searches input parameters
    /// for the slot number in ATECC608x chip (if provided)
    fn parse_kdf_slot(&self, parameters: &KdfParams) -> Result<u16, AtcaStatus> {
        let mut slot: u16 = 0x0000;

        if let Some(val) = parameters.source_slot_id {
            if parameters.source == KdfSource::Slot {
                if val < ATCA_ATECC_SLOTS_COUNT {
                    slot = val as u16;
                } else {
                    return Err(AtcaStatus::AtcaInvalidId);
                }
            } else {
                return Err(AtcaStatus::AtcaBadParam);
            }
        } else if parameters.source == KdfSource::Slot {
            return Err(AtcaStatus::AtcaInvalidId);
        }

        if let Some(val) = parameters.target_slot_id {
            if parameters.target == KdfTarget::Slot {
                if val < ATCA_ATECC_SLOTS_COUNT {
                    let is_pub_info = self.slots[val as usize].config.pub_info;
                    let is_write_config_always =
                        self.slots[val as usize].config.write_config == WriteConfig::Always;
                    let is_proper_key_type = (self.slots[val as usize].config.key_type
                        == KeyType::ShaOrText)
                        || (self.slots[val as usize].config.key_type == KeyType::Aes);
                    if is_pub_info && is_write_config_always && is_proper_key_type {
                        slot += (val as u16) << 8;
                    } else {
                        return Err(AtcaStatus::AtcaBadParam);
                    }
                } else {
                    return Err(AtcaStatus::AtcaInvalidId);
                }
            } else {
                return Err(AtcaStatus::AtcaBadParam);
            }
        } else if parameters.target == KdfTarget::Slot {
            return Err(AtcaStatus::AtcaInvalidId);
        }

        Ok(slot)
    } // AteccDevice::parse_kdf_slot()

    /// Auxiliary function checking correctness of the combination of input parameters to call KDF function.
    fn check_kdf_input_parameters(
        &self,
        algorithm: &KdfAlgorithm,
        parameters: &KdfParams,
        message: Option<&[u8]>,
        message_length: usize,
    ) -> Result<(), AtcaStatus> {
        const TEMPKEY_VALID_BYTE: usize = 1;
        const TEMPKEY_VALID_BIT: u8 = 7;
        const TEMPKEY_CAPACITY: usize = 64;

        if self.get_device_type() != AtcaDeviceType::ATECC608A
            || !self.is_kdf_input_parameters_combination_ok(algorithm, parameters)
        {
            return Err(AtcaStatus::AtcaBadParam);
        }
        if message.is_none()
            && (match algorithm {
                KdfAlgorithm::Aes | KdfAlgorithm::Prf(_) => true,
                KdfAlgorithm::Hkdf(details) => {
                    !(matches!(details.msg_loc, HkdfMsgLoc::Slot | HkdfMsgLoc::TempKey))
                }
            })
        {
            return Err(AtcaStatus::AtcaBadParam);
        }
        if message.is_some()
            && (match algorithm {
                KdfAlgorithm::Hkdf(details) => match details.msg_loc {
                    HkdfMsgLoc::Iv => {
                        let iv_len: usize = self.chip_options.kdf_iv_str.len();
                        let iv_loc: usize = self.chip_options.kdf_iv_location_at;

                        if message_length < (iv_loc + iv_len) {
                            true
                        } else {
                            message.unwrap()[iv_loc..(iv_loc + iv_len)]
                                != self.chip_options.kdf_iv_str
                        }
                    }
                    _ => false,
                },
                _ => false,
            })
        {
            return Err(AtcaStatus::AtcaBadParam);
        }
        let msg_in_tempkey: bool = match algorithm {
            KdfAlgorithm::Hkdf(details) => details.msg_loc == HkdfMsgLoc::TempKey,
            _ => false,
        };
        let source_is_tempkey: bool = parameters.source == KdfSource::TempKey;
        if source_is_tempkey && msg_in_tempkey && (parameters.target == KdfTarget::TempKey) {
            return Err(AtcaStatus::AtcaBadParam);
        }
        if source_is_tempkey || msg_in_tempkey {
            // checking if the contents of TempKey register are valid
            let result = self.info_cmd(InfoCmdType::State)?;
            if !atcab_get_bit_value(result[TEMPKEY_VALID_BYTE], TEMPKEY_VALID_BIT) {
                return Err(AtcaStatus::AtcaBadParam);
            }
        }
        if (message_length > ATCA_KDF_MAX_MSG_SIZE)
            || (if let Some(msg) = message {
                msg.len() < message_length
            } else {
                false
            })
            || (match algorithm {
                KdfAlgorithm::Aes => message_length != ATCA_AES_DATA_SIZE,
                KdfAlgorithm::Hkdf(details) => match details.msg_loc {
                    HkdfMsgLoc::TempKey => message_length > TEMPKEY_CAPACITY,
                    HkdfMsgLoc::Slot => match details.msg_slot {
                        Some(slot_id) => {
                            (slot_id >= ATCA_ATECC_SLOTS_COUNT)
                                || (message_length
                                    > (self.get_slot_capacity(slot_id).bytes as usize))
                        }
                        None => return Err(AtcaStatus::AtcaBadParam),
                    },
                    _ => false,
                },
                _ => false,
            })
        {
            return Err(AtcaStatus::AtcaInvalidSize);
        }

        Ok(())
    } // AteccDevice::check_kdf_input_parameters()

    /// Auxiliary subfunction checking correctness of the combination of input parameters to call KDF function.
    fn is_kdf_input_parameters_combination_ok(
        &self,
        algorithm: &KdfAlgorithm,
        parameters: &KdfParams,
    ) -> bool {
        let mut result: bool = true;

        if (OutputProtectionState::ForbiddenOutputOutsideChip
            == self.chip_options.kdf_output_protection)
            || ((OutputProtectionState::EncryptedOutputOnly
                == self.chip_options.kdf_output_protection)
                && (parameters.target == KdfTarget::Output))
        {
            result = false
        } else {
            match algorithm {
                KdfAlgorithm::Aes => {
                    if !(self.chip_options.kdf_aes_enabled && self.chip_options.aes_enabled) {
                        result = false
                    }
                }
                KdfAlgorithm::Prf(details) => {
                    // given slot will not hold required amount of data
                    let bad_slot_id: bool = (parameters.source_slot_id.is_some()
                        && (parameters.source_slot_id.unwrap()
                            < ATCA_ATECC_MIN_SLOT_IDX_FOR_PUB_KEY))
                        || (parameters.target_slot_id.is_some()
                            && (parameters.target_slot_id.unwrap()
                                < ATCA_ATECC_MIN_SLOT_IDX_FOR_PUB_KEY));

                    if ((details.key_length == KdfPrfKeyLen::Len48)
                        || (details.key_length == KdfPrfKeyLen::Len64))
                        && ((parameters.source == KdfSource::TempKeyUp)
                            || (parameters.source == KdfSource::AltKeyBuf)
                            || bad_slot_id)
                    {
                        result = false
                    }

                    if (details.target_length == KdfPrfTargetLen::Len64)
                        && ((parameters.target == KdfTarget::TempKeyUp)
                            || (parameters.target == KdfTarget::AltKeyBuf)
                            || bad_slot_id)
                    {
                        result = false
                    }
                }
                KdfAlgorithm::Hkdf(details) => {
                    if (details.msg_loc == HkdfMsgLoc::Iv) && !self.chip_options.kdf_iv_enabled {
                        result = false
                    }
                }
            }
        }

        result
    } // AteccDevice::is_kdf_input_parameters_combination_ok()
}
