#![allow(clippy::upper_case_acronyms)]

#[macro_use]
extern crate strum_macros; // 0.10.0
#[macro_use]
extern crate lazy_static;

include!("types.rs");
include!("constants.rs");

mod atca_iface_cfg;
mod hw_impl;
mod sw_impl;
#[cfg(test)]
mod unit_tests;

#[cfg(test)]
use cryptoauthlib_sys::atca_aes_cbc_ctx_t;

pub trait AteccDeviceTrait {
    /// Request ATECC to generate a vector of random bytes
    fn random(&self, rand_out: &mut Vec<u8>) -> AtcaStatus;
    /// Request ATECC to compute a message hash (SHA256)
    fn sha(&self, message: Vec<u8>, digest: &mut Vec<u8>) -> AtcaStatus;
    /// Execute a Nonce command in pass-through mode to load one of the
    /// device's internal buffers with a fixed value.
    /// For the ATECC608A, available targets are TempKey (32 or 64 bytes), Message
    /// Digest Buffer (32 or 64 bytes), or the Alternate Key Buffer (32 bytes). For
    /// all other devices, only TempKey (32 bytes) is available.
    fn nonce(&self, target: NonceTarget, data: &[u8]) -> AtcaStatus;
    /// Execute a Nonce command to generate a random nonce combining a host
    /// nonce and a device random number.
    fn nonce_rand(&self, host_nonce: &[u8], rand_out: &mut Vec<u8>) -> AtcaStatus;
    /// Request ATECC to generate a cryptographic key
    fn gen_key(&self, key_type: KeyType, slot_id: u8) -> AtcaStatus;
    /// Request ATECC to import a cryptographic key
    fn import_key(&self, key_type: KeyType, key_data: &[u8], slot_id: u8) -> AtcaStatus;
    /// Request ATECC to export a cryptographic key.
    /// For cryptographic security reasons,
    /// with KeyType = P256EccKey this function exports only public key
    fn export_key(&self, key_type: KeyType, key_data: &mut Vec<u8>, slot_id: u8) -> AtcaStatus;
    /// Depending on the socket configuration, this function calculates
    /// public key based on an existing private key in the socket
    /// or exports the public key directly
    fn get_public_key(&self, slot_id: u8, public_key: &mut Vec<u8>) -> AtcaStatus;
    /// Request ATECC to generate an ECDSA signature
    fn sign_hash(&self, mode: SignMode, slot_id: u8, signature: &mut Vec<u8>) -> AtcaStatus;
    /// Request ATECC to verify ECDSA signature
    fn verify_hash(
        &self,
        mode: VerifyMode,
        hash: &[u8],
        signature: &[u8],
    ) -> Result<bool, AtcaStatus>;
    /// Data encryption function in AES unauthenticated cipher alhorithms modes
    fn cipher_encrypt(
        &self,
        algorithm: CipherAlgorithm,
        slot_id: u8,
        data: &mut Vec<u8>,
    ) -> AtcaStatus;
    /// Data decryption function in AES unauthenticated cipher alhorithms modes
    fn cipher_decrypt(
        &self,
        algorithm: CipherAlgorithm,
        slot_id: u8,
        data: &mut Vec<u8>,
    ) -> AtcaStatus;
    /// Data encryption function in AES AEAD (authenticated encryption with associated data) modes
    fn aead_encrypt(
        &self,
        algorithm: AeadAlgorithm,
        slot_id: u8,
        data: &mut Vec<u8>,
    ) -> Result<Vec<u8>, AtcaStatus>;
    /// Data decryption function in AES AEAD (authenticated encryption with associated data) modes
    fn aead_decrypt(
        &self,
        algorithm: AeadAlgorithm,
        slot_id: u8,
        data: &mut Vec<u8>,
    ) -> Result<bool, AtcaStatus>;
    /// A function that calculates the MAC (Message Authentication Code) value for a message
    fn mac_compute(
        &self,
        algorithm: MacAlgorithm,
        slot_id: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, AtcaStatus>;
    /// A function that verifies the value of MAC (Message Authentication Code) for a message
    fn mac_verify(
        &self,
        algorithm: MacAlgorithm,
        slot_id: u8,
        data: &[u8],
    ) -> Result<bool, AtcaStatus>;
    /// KDF command function, which derives a new key in PRF, AES, or HKDF modes.
    /// According to RFC-5869, the HKDF mode consists of two steps, extract and expand.
    /// The "HMAC-Hash" base operation is implemented in the ATECC608x chip,
    /// so to perform full HKDF operation, proceed as described in chapter 2 of RFC-5869,
    /// first calculate PRK = HMAC-Hash(salt, IKM) and then use obtained PRK
    /// to obtain the resulting OKM, again using the same "HMAC-Hash" function,
    /// i.e. this "fn kdf", according to the algorithm from section 2.3 of RFC-5869.
    fn kdf(
        &self,
        algorithm: KdfAlgorithm,
        parameters: KdfParams,
        message: Option<&[u8]>,
        message_length: usize,
    ) -> Result<KdfResult, AtcaStatus>;
    /// Request ATECC to return own device type
    fn get_device_type(&self) -> AtcaDeviceType;
    /// Request ATECC to check if its configuration is locked.
    /// If true, a chip can be used for cryptographic operations
    fn is_configuration_locked(&self) -> bool;
    /// Request ATECC to check if its Data Zone is locked.
    /// If true, a chip can be used for cryptographic operations
    fn is_data_zone_locked(&self) -> bool;
    /// Returns a structure containing configuration data read from ATECC
    /// during initialization of the AteccDevice object.
    fn get_config(&self, atca_slots: &mut Vec<AtcaSlot>) -> AtcaStatus;
    /// Command accesses some static or dynamic information from the ATECC chip
    fn info_cmd(&self, _command: InfoCmdType) -> Result<Vec<u8>, AtcaStatus>;
    /// A function that adds an encryption key for securely reading or writing data
    /// that is located in a specific slot on the ATECCx08 chip.
    /// Data is not written to the ATECCx08 chip, but to the AteccDevice structure
    fn add_access_key(&self, slot_id: u8, encryption_key: &[u8]) -> AtcaStatus;
    /// A function that deletes all encryption keys for secure read or write operations
    /// performed by the ATECCx08 chip
    fn flush_access_keys(&self) -> AtcaStatus;
    /// Get serial number of the ATECC device
    fn get_serial_number(&self) -> [u8; ATCA_SERIAL_NUM_SIZE];
    /// Checks if the chip supports AES encryption.
    /// (only relevant for the ATECC608x chip)
    fn is_aes_enabled(&self) -> bool;
    /// Checks if the chip supports AES for KDF operations
    /// (only relevant for the ATECC608x chip)
    fn is_kdf_aes_enabled(&self) -> bool;
    /// Checks if the special KDF Initialization Vector function is enabled
    /// (only relevant for the ATECC608x chip)
    fn is_kdf_iv_enabled(&self) -> bool;
    /// Checks whether transmission between chip and host is to be encrypted
    /// (IO encryption is only possible for ATECC608x chip)
    fn is_io_protection_key_enabled(&self) -> bool;
    /// Function that reads the read security settings of the ECDH function from chip
    /// (only relevant for the ATECC608x chip)
    fn get_ecdh_output_protection_state(&self) -> OutputProtectionState;
    /// Function that reads the read security settings of the KDF function from chip
    /// (only relevant for the ATECC608x chip)
    fn get_kdf_output_protection_state(&self) -> OutputProtectionState;
    /// wakeup the CryptoAuth device
    fn wakeup(&self) -> AtcaStatus;
    /// invoke sleep on the CryptoAuth device
    fn sleep(&self) -> AtcaStatus;
    /// ATECC device instance destructor
    fn release(&self) -> AtcaStatus;

    //--------------------------------------------------
    //
    // Functions available only during testing
    //
    //--------------------------------------------------

    /// A generic function that reads data from the chip
    #[cfg(test)]
    fn read_zone(&self, zone: u8, slot: u16, block: u8, offset: u8, data: &mut [u8]) -> AtcaStatus;
    /// Request ATECC to read and return own configuration zone.
    /// Note: this function returns raw data, function get_config(..) implements a more
    /// structured return value.
    #[cfg(test)]
    fn read_config_zone(&self, config_data: &mut Vec<u8>) -> AtcaStatus;
    /// Compare internal config zone contents vs. config_data.
    /// Diagnostic function.
    #[cfg(test)]
    fn cmp_config_zone(&self, config_data: &mut [u8]) -> Result<bool, AtcaStatus>;
    /// A function that takes an encryption key for securely reading or writing data
    /// that is located in a specific slot on an ATECCx08 chip.
    /// Data is not taken directly from the ATECCx08 chip, but from the AteccDevice structure
    #[cfg(test)]
    fn get_access_key(&self, slot_id: u8, key: &mut Vec<u8>) -> AtcaStatus;
    /// Perform an AES-128 encrypt operation with a key in the device
    #[cfg(test)]
    fn aes_encrypt_block(
        &self,
        key_id: u16,
        key_block: u8,
        input: &[u8],
    ) -> Result<[u8; ATCA_AES_DATA_SIZE], AtcaStatus>;
    /// Perform an AES-128 decrypt operation with a key in the device
    #[cfg(test)]
    fn aes_decrypt_block(
        &self,
        key_id: u16,
        key_block: u8,
        input: &[u8],
    ) -> Result<[u8; ATCA_AES_DATA_SIZE], AtcaStatus>;
    /// Initialize context for AES CTR operation with an existing IV, which
    /// is common when start a decrypt operation
    #[cfg(test)]
    fn aes_ctr_init(
        &self,
        slot_id: u8,
        counter_size: u8,
        iv: &[u8],
    ) -> Result<atca_aes_ctr_ctx_t, AtcaStatus>;
    /// Increments AES CTR counter value
    #[cfg(test)]
    fn aes_ctr_increment(&self, ctx: atca_aes_ctr_ctx_t) -> Result<atca_aes_ctr_ctx_t, AtcaStatus>;
    /// Initialize context for AES CBC operation.
    #[cfg(test)]
    fn aes_cbc_init(&self, slot_id: u8, iv: &[u8]) -> Result<atca_aes_cbc_ctx_t, AtcaStatus>;
    /// A helper function that returns number of blocks and bytes of data
    /// available for a given socket
    #[cfg(test)]
    fn get_slot_capacity(&self, slot_id: u8) -> AtcaSlotCapacity;
}

pub type AteccDevice = Box<dyn AteccDeviceTrait + Send + Sync>;

pub fn setup_atecc_device(r_iface_cfg: AtcaIfaceCfg) -> Result<AteccDevice, String> {
    match r_iface_cfg.devtype {
        AtcaDeviceType::AtcaTestDevSuccess
        | AtcaDeviceType::AtcaTestDevFail
        | AtcaDeviceType::AtcaTestDevFailUnimplemented => {
            match sw_impl::AteccDevice::new(r_iface_cfg) {
                Ok(x) => Ok(Box::new(x)),
                Err(err) => Err(err),
            }
        }
        AtcaDeviceType::AtcaDevUnknown => {
            Err(String::from("Attempting to create an unknown device type"))
        }
        _ => match hw_impl::AteccDevice::new(r_iface_cfg) {
            Ok(x) => Ok(Box::new(x)),
            Err(err) => Err(err),
        },
    }
}

impl AtcaSlot {
    pub fn is_valid(self) -> bool {
        // As long as exclusive range is experimental, this should work.
        // self.id is always greater than 0
        self.id < ATCA_ATECC_SLOTS_COUNT
    }
}
