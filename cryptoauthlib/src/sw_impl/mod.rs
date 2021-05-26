use super::{
    AtcaDeviceType, AtcaIfaceCfg, AtcaIfaceType, AtcaSlot, AtcaStatus, AteccDeviceTrait,
    InfoCmdType, KeyType, NonceTarget, OutputProtectionState, SignMode, VerifyMode,
};

use super::{ATCA_RANDOM_BUFFER_SIZE, ATCA_SERIAL_NUM_SIZE};
use rand::{distributions::Standard, Rng};

pub struct AteccDevice {
    dev_type: AtcaDeviceType,
}

// Software ATECC implements following functions:
// new(), random(), get_device_type(), is_configuration_locked(), get_config(), release().
// All aothers are considered to be mocked.
// Depending on set device type they either:
// - always fails
// - always succeed
// - fail if they are not implemented but only mocked.
impl Default for AteccDevice {
    fn default() -> AteccDevice {
        AteccDevice {
            dev_type: AtcaDeviceType::AtcaTestDevNone,
        }
    }
}

impl AteccDeviceTrait for AteccDevice {
    fn random(&self, rand_out: &mut Vec<u8>) -> AtcaStatus {
        let vector: Vec<u8> = rand::thread_rng()
            .sample_iter(Standard)
            .take(ATCA_RANDOM_BUFFER_SIZE)
            .collect();
        rand_out.resize(ATCA_RANDOM_BUFFER_SIZE, 0u8);
        rand_out.copy_from_slice(&vector);
        match self.dev_type {
            AtcaDeviceType::AtcaTestDevFailUnimplemented | AtcaDeviceType::AtcaTestDevSuccess => {
                AtcaStatus::AtcaSuccess
            }
            _ => AtcaStatus::AtcaUnimplemented,
        }
    }
    /// Request ATECC to compute a message hash (SHA256)
    fn sha(&self, _message: Vec<u8>, _digest: &mut Vec<u8>) -> AtcaStatus {
        self.default_dev_status()
    }
    /// Execute a Nonce command in pass-through mode to load one of the
    /// device's internal buffers with a fixed value.
    /// For the ATECC608A, available targets are TempKey (32 or 64 bytes), Message
    /// Digest Buffer (32 or 64 bytes), or the Alternate Key Buffer (32 bytes). For
    /// all other devices, only TempKey (32 bytes) is available.
    fn nonce(&self, _target: NonceTarget, _data: &[u8]) -> AtcaStatus {
        self.default_dev_status()
    }
    /// Execute a Nonce command to generate a random nonce combining a host
    /// nonce and a device random number.
    fn nonce_rand(&self, _host_nonce: &[u8], _rand_out: &mut Vec<u8>) -> AtcaStatus {
        self.default_dev_status()
    }
    /// Request ATECC to generate a cryptographic key
    fn gen_key(&self, _key_type: KeyType, _slot_id: u8) -> AtcaStatus {
        self.default_dev_status()
    }
    /// Request ATECC to import a cryptographic key
    fn import_key(&self, _key_type: KeyType, _key_data: &[u8], _slot_number: u8) -> AtcaStatus {
        self.default_dev_status()
    }
    /// Request ATECC to export a cryptographic key
    fn export_key(&self, _key_type: KeyType, _key_data: &mut Vec<u8>, _slot_id: u8) -> AtcaStatus {
        self.default_dev_status()
    }
    /// Depending on the socket configuration, this function calculates
    /// public key based on an existing private key in the socket
    /// or exports the public key directly
    fn get_public_key(&self, _slot_id: u8, _public_key: &mut Vec<u8>) -> AtcaStatus {
        self.default_dev_status()
    }
    /// Request ATECC to generate an ECDSA signature
    fn sign_hash(&self, _mode: SignMode, _slot_id: u8, _signature: &mut Vec<u8>) -> AtcaStatus {
        self.default_dev_status()
    }
    /// Request ATECC to verify ECDSA signature
    fn verify_hash(
        &self,
        _mode: VerifyMode,
        _hash: &[u8],
        _signature: &[u8],
    ) -> Result<bool, AtcaStatus> {
        match self.dev_type {
            AtcaDeviceType::AtcaTestDevSuccess => Ok(true),
            _ => Err(self.default_dev_status()),
        }
    }
    /// Request ATECC to return own device type
    fn get_device_type(&self) -> AtcaDeviceType {
        self.dev_type
    }
    /// Request ATECC to check if its configuration is locked.
    /// If true, a chip can be used for cryptographic operations
    fn is_configuration_locked(&self) -> bool {
        match self.dev_type {
            AtcaDeviceType::AtcaTestDevFailUnimplemented | AtcaDeviceType::AtcaTestDevSuccess => {
                true
            }
            _ => false,
        }
    }
    /// Request ATECC to check if its Data Zone is locked.
    /// If true, a chip can be used for cryptographic operations
    fn is_data_zone_locked(&self) -> bool {
        matches!(self.default_dev_status(), AtcaStatus::AtcaSuccess)
    }
    /// Returns a structure containing configuration data read from ATECC
    /// during initialization of the AteccDevice object.
    fn get_config(&self, _atca_slots: &mut Vec<AtcaSlot>) -> AtcaStatus {
        match self.dev_type {
            AtcaDeviceType::AtcaTestDevSuccess | AtcaDeviceType::AtcaTestDevFailUnimplemented => {
                AtcaStatus::AtcaSuccess
            }
            _ => AtcaStatus::AtcaUnimplemented,
        }
    }
    /// Command accesses some static or dynamic information from the ATECC chip
    fn info_cmd(&self, _command: InfoCmdType) -> Result<Vec<u8>, AtcaStatus> {
        match self.dev_type {
            AtcaDeviceType::AtcaTestDevSuccess => Ok(Vec::new()),
            _ => Err(self.default_dev_status()),
        }
    }

    fn add_access_key(&self, _slot_id: u8, _encryption_key: &[u8]) -> AtcaStatus {
        self.default_dev_status()
    }

    fn flush_access_keys(&self) -> AtcaStatus {
        self.default_dev_status()
    }

    fn get_serial_number(&self) -> [u8; ATCA_SERIAL_NUM_SIZE] {
        let mut serial_number = [0; ATCA_SERIAL_NUM_SIZE];
        if AtcaDeviceType::AtcaTestDevSuccess == self.dev_type {
            serial_number[0] = 0x01;
            serial_number[1] = 0x23;
        }

        serial_number
    }

    fn is_aes_enabled(&self) -> bool {
        matches!(self.default_dev_status(), AtcaStatus::AtcaSuccess)
    }

    fn is_kdf_aes_enabled(&self) -> bool {
        matches!(self.default_dev_status(), AtcaStatus::AtcaSuccess)
    }

    fn is_io_protection_key_enabled(&self) -> bool {
        matches!(self.default_dev_status(), AtcaStatus::AtcaSuccess)
    }

    fn get_ecdh_output_protection_state(&self) -> OutputProtectionState {
        OutputProtectionState::ClearTextAllowed
    }

    fn get_kdf_output_protection_state(&self) -> OutputProtectionState {
        OutputProtectionState::ClearTextAllowed
    }

    /// ATECC device instance destructor
    fn release(&self) -> AtcaStatus {
        match self.dev_type {
            AtcaDeviceType::AtcaTestDevFailUnimplemented | AtcaDeviceType::AtcaTestDevSuccess => {
                AtcaStatus::AtcaSuccess
            }
            _ => AtcaStatus::AtcaUnimplemented,
        }
    }

    //--------------------------------------------------
    //
    // Functions available only during testing
    //
    //--------------------------------------------------

    /// A generic function that reads data from the chip
    #[cfg(test)]
    fn read_zone(
        &self,
        _zone: u8,
        _slot: u16,
        _block: u8,
        _offset: u8,
        data: &mut Vec<u8>,
        _len: u8,
    ) -> AtcaStatus {
        data.clear();
        self.default_dev_status()
    }
    /// Request ATECC to read and return own configuration zone.
    /// Note: this function returns raw data, function get_config(..) implements a more
    /// structured return value.
    #[cfg(test)]
    fn read_config_zone(&self, _config_data: &mut Vec<u8>) -> AtcaStatus {
        self.default_dev_status()
    }
    /// Compare internal config zone contents vs. config_data.
    /// Diagnostic function.
    #[cfg(test)]
    fn cmp_config_zone(&self, _config_data: &mut Vec<u8>) -> Result<bool, AtcaStatus> {
        match self.dev_type {
            AtcaDeviceType::AtcaTestDevSuccess => Ok(true),
            _ => Err(self.default_dev_status()),
        }
    }
    #[cfg(test)]
    fn get_access_key(&self, _slot_id: u8, _key: &mut Vec<u8>) -> AtcaStatus {
        self.default_dev_status()
    }
}

impl AteccDevice {
    pub fn new(r_iface_cfg: AtcaIfaceCfg) -> Result<AteccDevice, String> {
        let mut device = AteccDevice::default();
        match r_iface_cfg.iface_type {
            AtcaIfaceType::AtcaTestIface => (),
            _ => {
                let err = format!(
                    "Software implementation of an AteccDevice does not support interface {}",
                    r_iface_cfg.iface_type.to_string()
                );
                return Err(err);
            }
        }
        device.dev_type = match r_iface_cfg.devtype {
            AtcaDeviceType::AtcaTestDevFail => AtcaDeviceType::AtcaTestDevFail,
            AtcaDeviceType::AtcaTestDevSuccess => AtcaDeviceType::AtcaTestDevSuccess,
            AtcaDeviceType::AtcaTestDevFailUnimplemented => {
                AtcaDeviceType::AtcaTestDevFailUnimplemented
            }
            _ => {
                let err = format!(
                    "Software implementation of an AteccDevice does not support interface {}",
                    r_iface_cfg.devtype.to_string()
                );
                return Err(err);
            }
        };
        Ok(device)
    }
    fn default_dev_status(&self) -> AtcaStatus {
        match self.dev_type {
            AtcaDeviceType::AtcaTestDevSuccess => AtcaStatus::AtcaSuccess,
            _ => AtcaStatus::AtcaUnimplemented,
        }
    }
}
