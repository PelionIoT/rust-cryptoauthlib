use std::ptr;

use super::{
    AtcaDeviceType, AtcaStatus, AteccDevice, EcdhParams, EcdhResult, EcdhSource, EcdhTarget,
    OutputProtectionState, WriteConfig,
};

use super::{
    ATCA_ATECC_PUB_KEY_SIZE, ATCA_ATECC_SLOTS_COUNT, ATCA_ECDH_KEY_SIZE, ATCA_SHA2_256_DIGEST_SIZE,
};

impl AteccDevice {
    /// Function for generating premaster secret key using ECDH
    pub(crate) fn ecdh(
        &self,
        parameters: EcdhParams,
        peer_public_key: &[u8],
    ) -> Result<EcdhResult, AtcaStatus> {
        if self.check_that_configuration_is_not_locked(true) {
            return Err(AtcaStatus::AtcaNotLocked);
        }

        let key_id: u16 = self.parse_ecdh_input_parameters(&parameters, peer_public_key.len())?;

        let mode: u8 = parameters.key_source.clone() as u8
            | parameters.out_target.clone() as u8
            | ((parameters.out_encrypt as u8) << 0x01);

        let mut out_data: Vec<u8> = vec![0x00; ATCA_ECDH_KEY_SIZE];
        let out_data_ptr: *mut u8 = match parameters.out_target {
            EcdhTarget::Output => out_data.as_mut_ptr(),
            EcdhTarget::Compatibility => match self.slots[key_id as usize]
                .config
                .ecc_key_attr
                .ecdh_secret_out
            {
                false => out_data.as_mut_ptr(),
                _ => ptr::null_mut(),
            },
            _ => ptr::null_mut(),
        };

        let mut out_nonce: Vec<u8> = vec![0x00; ATCA_ECDH_KEY_SIZE];
        let out_nonce_ptr: *mut u8 = match parameters.out_target {
            EcdhTarget::Output => out_nonce.as_mut_ptr(),
            _ => ptr::null_mut(),
        };

        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_ecdh_base(
                mode,
                key_id,
                peer_public_key.as_ptr(),
                out_data_ptr,
                out_nonce_ptr,
            )
        });

        match result {
            AtcaStatus::AtcaSuccess => {
                let output = EcdhResult {
                    pms: if out_data_ptr.is_null() {
                        None
                    } else {
                        out_data.resize(ATCA_ECDH_KEY_SIZE, 0x00);
                        Some(out_data)
                    },
                    out_nonce: if out_nonce_ptr.is_null() {
                        None
                    } else {
                        out_nonce.resize(ATCA_SHA2_256_DIGEST_SIZE, 0x00);
                        Some(out_nonce)
                    },
                };
                Ok(output)
            }
            _ => Err(result),
        }
    } // AteccDevice::ecdh()

    /// Auxiliary function that searches input parameters
    /// for the slot number in ATECCx08A/B chip (if provided)
    fn parse_ecdh_slot(&self, parameters: &EcdhParams) -> Result<u16, AtcaStatus> {
        let mut slot: u16 = 0x0000;

        if (parameters.key_source == EcdhSource::Slot)
            || (parameters.out_target == EcdhTarget::Slot)
        {
            match parameters.slot_id {
                Some(val) => {
                    if val < ATCA_ATECC_SLOTS_COUNT {
                        if (parameters.out_target == EcdhTarget::Slot)
                            && (self.slots[val as usize].config.write_config != WriteConfig::Always)
                        {
                            return Err(AtcaStatus::AtcaBadParam);
                        }
                        if (parameters.key_source == EcdhSource::Slot)
                            && !self.slots[val as usize].config.ecc_key_attr.ecdh_operation
                        {
                            return Err(AtcaStatus::AtcaInvalidId);
                        }
                        slot = val as u16;
                    } else {
                        return Err(AtcaStatus::AtcaInvalidId);
                    }
                }
                None => return Err(AtcaStatus::AtcaBadParam),
            }
        } else if parameters.slot_id.is_some() {
            return Err(AtcaStatus::AtcaBadParam);
        }

        Ok(slot)
    } // AteccDevice::parse_ecdh_slot()

    /// Auxiliary function checking correctness of the combination of input parameters to call ECDH function.
    fn parse_ecdh_input_parameters(
        &self,
        parameters: &EcdhParams,
        peer_public_key_length: usize,
    ) -> Result<u16, AtcaStatus> {
        let mut slot: u16 = 0x0000;
        let device_type = self.get_device_type();

        if (device_type != AtcaDeviceType::ATECC508A) && (device_type != AtcaDeviceType::ATECC608A)
        {
            return Err(AtcaStatus::AtcaBadOpcode);
        }

        let mut bad_param: bool = (device_type == AtcaDeviceType::ATECC508A)
            && ((parameters.key_source != EcdhSource::Slot)
                || (parameters.out_target != EcdhTarget::Compatibility)
                || parameters.out_encrypt);

        bad_param = bad_param
            || ((parameters.key_source == EcdhSource::Slot)
                && (parameters.out_target == EcdhTarget::Slot));

        if !bad_param {
            slot = self.parse_ecdh_slot(parameters)?;

            if (device_type == AtcaDeviceType::ATECC608A) && self.chip_options.io_key_enabled {
                let ecdh_out_to_n_plus_1: bool = self.slots[slot as usize]
                    .config
                    .ecc_key_attr
                    .ecdh_secret_out;

                match self.chip_options.ecdh_output_protection {
                    OutputProtectionState::ClearTextAllowed => {
                        if parameters.out_encrypt {
                            match parameters.out_target {
                                EcdhTarget::Compatibility => {
                                    if ecdh_out_to_n_plus_1 {
                                        bad_param = true;
                                    }
                                }
                                EcdhTarget::Slot | EcdhTarget::TempKey => bad_param = true,
                                _ => (),
                            }
                        }
                    }
                    OutputProtectionState::EncryptedOutputOnly => match parameters.out_target {
                        EcdhTarget::Compatibility => {
                            if !parameters.out_encrypt || ecdh_out_to_n_plus_1 {
                                bad_param = true;
                            }
                        }
                        EcdhTarget::Slot | EcdhTarget::TempKey => {
                            if parameters.out_encrypt {
                                bad_param = true;
                            }
                        }
                        EcdhTarget::Output => {
                            if !parameters.out_encrypt {
                                bad_param = true;
                            }
                        }
                    },
                    OutputProtectionState::ForbiddenOutputOutsideChip => {
                        match parameters.out_target {
                            EcdhTarget::Compatibility => {
                                if parameters.out_encrypt && ecdh_out_to_n_plus_1 {
                                    bad_param = true;
                                }
                            }
                            EcdhTarget::Slot | EcdhTarget::TempKey => {
                                if parameters.out_encrypt {
                                    bad_param = true;
                                }
                            }
                            EcdhTarget::Output => bad_param = true,
                        }
                    }
                    _ => bad_param = true,
                }
            }
        }

        if bad_param {
            return Err(AtcaStatus::AtcaBadParam);
        }

        if peer_public_key_length != ATCA_ATECC_PUB_KEY_SIZE {
            return Err(AtcaStatus::AtcaInvalidSize);
        }

        Ok(slot)
    } // AteccDevice::parse_ecdh_input_parameters()
}
