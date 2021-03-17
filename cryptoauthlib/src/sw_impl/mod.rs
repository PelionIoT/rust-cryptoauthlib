use rand::{distributions::Standard, Rng};
// Only temporarily!
#[allow(unused_imports,deprecated)]
use super::{AtcaIfaceCfg, AtcaIface, AtcaIfaceI2c, AtcaStatus, AtcaDeviceType, AtcaIfaceType, AtcaIfaceCfgPtrWrapper, AtcaSlot, KeyType, NonceTarget, 
    SignEcdsaParam, VerifyEcdsaParam, SignMode, VerifyMode, InfoCmdType, WriteConfig, AtcaDevice, ReadKey, EccKeyAttr, SlotConfig};
use super::ATCA_RANDOM_BUFFER_SIZE;

pub struct AteccDevice {
    result: AtcaStatus,
}

impl Default for AteccDevice {
    fn default() -> AteccDevice {
        AteccDevice {
            result: AtcaStatus::AtcaSuccess,
        }
    }
}

impl super::AteccDevice for AteccDevice {
    fn random(&self, rand_out: &mut Vec<u8>) -> AtcaStatus {
        let result :Vec<u8> = rand::thread_rng().sample_iter(Standard).take(ATCA_RANDOM_BUFFER_SIZE).collect();
        rand_out.copy_from_slice(&result);
        self.result
    }
    /// Request ATECC to compute a message hash (SHA256)
    fn sha(&self, _message: Vec<u8>, _digest: &mut Vec<u8>) -> AtcaStatus {
        self.result
    }
    /// Execute a Nonce command in pass-through mode to load one of the
    /// device's internal buffers with a fixed value.
    /// For the ATECC608A, available targets are TempKey (32 or 64 bytes), Message
    /// Digest Buffer (32 or 64 bytes), or the Alternate Key Buffer (32 bytes). For
    /// all other devices, only TempKey (32 bytes) is available.
    fn nonce(&self, _target: super::NonceTarget, _data: &[u8]) -> AtcaStatus {
        self.result
    }
    /// Execute a Nonce command to generate a random nonce combining a host
    /// nonce and a device random number.
    fn nonce_rand(&self, _host_nonce: &[u8], _rand_out: &mut Vec<u8>) -> AtcaStatus {
        self.result
    }
    /// Request ATECC to generate a cryptographic key
    fn gen_key(&self, _key_type: KeyType, _slot_number: u8) -> AtcaStatus {
        self.result
    }
    /// Request ATECC to import a cryptographic key
    fn import_key(&self, _key_type: KeyType, _key_data: &[u8], _slot_number: u8) -> AtcaStatus {
        self.result
    }
    /// Function to calculate the public key from an existing private key in a slot
    fn get_public_key(&self, _slot_number: u8, _public_key: &mut Vec<u8>) -> AtcaStatus {
        self.result
    }
    /// Request ATECC to generate an ECDSA signature
    fn sign_hash(&self, _mode: SignMode, _slot_number: u8, _signature: &mut Vec<u8>) -> AtcaStatus {
        self.result
    }
    /// Request ATECC to verify ECDSA signature
    fn verify_hash(&self, _mode: VerifyMode, _hash: &[u8], _signature: &[u8]) -> Result<bool, AtcaStatus> {
        match self.result {
            AtcaStatus::AtcaSuccess => Ok(true),
            _ => Err(self.result),
        }
    }
    /// Request ATECC to return own device type
    fn get_device_type(&self) -> AtcaDeviceType {
        match self.result {
            AtcaStatus::AtcaSuccess => AtcaDeviceType::AtcaTestDevSuccess,
            _ => AtcaDeviceType::AtcaTestDevFail,
        }
    }
    /// Request ATECC to check if its configuration is locked.
    /// If true, a chip can be used for cryptographic operations
    fn configuration_is_locked(&self) -> Result<bool, AtcaStatus> {
        match self.result {
            AtcaStatus::AtcaSuccess => Ok(true),
            _ => Err(self.result),
        }
    }
    /// Request ATECC to check if its Data Zone is locked.
    /// If true, a chip can be used for cryptographic operations
    fn data_zone_is_locked(&self) -> Result<bool, AtcaStatus> {
        match self.result {
            AtcaStatus::AtcaSuccess => Ok(true),
            _ => Err(self.result),
        }
    }
    /// Request ATECC to read and return own configuration zone.
    /// Note: this function returns raw data, function get_config(..) implements a more
    /// structured return value.
    fn read_config_zone(&self, _config_data: &mut Vec<u8>) -> AtcaStatus {
        self.result
    }
    /// Compare internal config zone contents vs. config_data.
    /// Diagnostic function.
    fn cmp_config_zone(&self, _config_data: &mut Vec<u8>, _same_config: &mut bool) -> AtcaStatus {
        self.result
    }
    /// Returns a structure containing configuration data read from ATECC
    /// during initialization of the AteccDevice object.
    fn get_config(&self, _atca_slots: &mut Vec<AtcaSlot>) -> AtcaStatus {
        self.result
    }
    /// ATECC device instance destructor
    fn release(&self) -> AtcaStatus {
        self.result
    }
}

impl AteccDevice {
    pub fn new(r_iface_cfg: AtcaIfaceCfg) -> Result<AteccDevice,String> {
        let mut device = AteccDevice::default();
        match r_iface_cfg.iface_type {
            AtcaIfaceType::AtcaTestIface => (),
            _ => {
                let err = format!("Software implementation of an AteccDevice does not support interface {}", r_iface_cfg.iface_type.to_string());
                return Err(err);
            }
        }
        device.result = match r_iface_cfg.devtype {
            AtcaDeviceType::AtcaTestDevFail => AtcaStatus::AtcaFuncFail,
            AtcaDeviceType::AtcaTestDevSuccess => AtcaStatus::AtcaSuccess,
            _ => {
                let err = format!("Software implementation of an AteccDevice does not support interface {}",r_iface_cfg.devtype.to_string());
                return Err(err);
            }
        };
        Ok(device)
    }
}
