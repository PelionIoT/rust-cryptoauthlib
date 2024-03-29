use std::mem::MaybeUninit;

use cryptoauthlib_sys::atca_aes_ctr_ctx_t;
use cryptoauthlib_sys::atca_aes_cmac_ctx_t;

/// An ATECC/ATSHA device buffer to load
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum NonceTarget {
    TempKey = 0x00,
    MsgDigBuf = 0x40,
    AltKeyBuf = 0x80,
}

/// Designates the source of the data to hash with TempKey for Generate Digest
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum GenDigZone {
    Data = 0x02,
    SharedNonce = 0x03,
}

/// Modes of calling the info_cmd() function
#[allow(dead_code)]
#[repr(u8)]
pub enum InfoCmdType {
    Revision = 0x00,
    KeyValid = 0x01,
    State = 0x02,
    Gpio = 0x03,
    VolKeyPermit = 0x04,
}

/// The mode of calling the ECDSA signature function
pub enum SignMode {
    /// The input parameter is hash to be signed
    External(Vec<u8>),
    Internal(SignEcdsaParam),
}

/// The mode of calling the ECDSA verification function
pub enum VerifyMode {
    /// The input parameter is public key
    External(Vec<u8>),
    ExternalMac(VerifyEcdsaParam),
    /// The input parameter is slot number
    Internal(u8),
    InternalMac(VerifyEcdsaParam),
}

/// Detailed parameters of calling the ECDSA signature function
pub struct SignEcdsaParam {
    /// Set to true if the signature will be used with
    /// the Verify(Invalidate) command. false for all other cases.
    pub is_invalidate: bool,
    /// Set to true if the message should incorporate
    /// the device's full serial number.
    pub is_full_sn: bool,
}

/// Detailed parameters of calling the ECDSA verification function
#[derive(Default)]
pub struct VerifyEcdsaParam {
    /// Public key for ExternalMac mode 
    pub public_key: Option<Vec<u8>>,
    /// Slot number for InternalMac mode
    pub slot_number: Option<u8>,
    /// System nonce (32 byte) used for the verification MAC
    pub num_in: Vec<u8>,
    /// IO protection key for verifying the validation MAC
    pub io_key: u8,
}

/// Cipher operation type
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum CipherOperation {
    Encrypt,
    Decrypt,
}

/// Feedback mode of cipher algorithm
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum FeedbackMode {
    Cfb,
    Ofb,
}
/// Type of Cipher algorithm
#[derive(Clone, Debug, PartialEq)]
pub enum CipherAlgorithm {
    /// Counter
    Ctr(CipherParam),
    /// Cipher Feedback
    Cfb(CipherParam),
    /// Output Feedback
    Ofb(CipherParam),
    /// XEX-based tweaked-codebook mode with ciphertext stealing
    Xts(CipherParam),
    /// Electronic Codebook
    Ecb(CipherParam),
    /// Cipher-Block Chaining
    Cbc(CipherParam),
    /// Cipher-Block Chaining with PKCS#7 padding
    CbcPkcs7(CipherParam),
}

/// Cipher algorithm parameters for compute
#[derive(Clone, Debug, PartialEq, Default)]
pub struct CipherParam {
    /// IV - Initialization Vector.
    /// For CTR mode it is concatenation of nonce and initial counter value.
    pub iv: Option<[u8; ATCA_AES_KEY_SIZE]>,
    /// Size of counter in IV in bytes for CTR mode. 4 bytes is a common size.
    pub counter_size: Option<u8>,
    /// external encryption/decryption key needed
    /// when an AES key stored in the cryptochip is not used
    pub key: Option<Vec<u8>>,
}

/// Type of AEAD algorithm
#[derive(Clone, Debug, PartialEq)]
pub enum AeadAlgorithm {
    Ccm(AeadParam),
    Gcm(AeadParam),
}

/// AEAD algorithm parameters for compute
#[derive(Clone, Debug, PartialEq, Default)]
pub struct AeadParam {
    /// Nonce [number used once aka IV] (default length is 12 bytes)
    pub nonce: Vec<u8>,
    /// external encryption/decryption key needed
    /// when an AES key stored in the cryptochip is not used
    pub key: Option<[u8; ATCA_AES_KEY_SIZE]>,
    /// tag to verify authenticity of decrypted data (16 bytes)
    pub tag: Option<Vec<u8>>,
    /// tag length generated during encryption
    pub tag_length: Option<u8>,
    /// Additional data that will be authenticated but not encrypted
    pub additional_data: Option<Vec<u8>>,
}

/// MAC algorithm to compute
#[derive(Clone, Debug, PartialEq)]
pub enum MacAlgorithm {
    HmacSha256(MacParam),
    Cbcmac(MacParam),
    Cmac(MacParam),
}

/// MAC algorithm parameters for compute
#[derive(Clone, Debug, PartialEq, Default)]
pub struct MacParam {
    /// external encryption/decryption key needed for MAC calculation
    /// when an 'AES' or 'ShaOrText' key stored in the cryptochip is not used
    pub key: Option<Vec<u8>>,
    /// MAC length generated during calculation
    pub mac_length: Option<u8>,
    /// MAC to verify authenticity of the provided data
    pub mac: Option<Vec<u8>>,
}

/// KDF algorithm to derive key
#[derive(Clone, Debug, PartialEq)]
pub enum KdfAlgorithm {
    Prf(PrfDetails),
    Hkdf(HkdfDetails),
    Aes,
}

/// KDF function parameters
#[derive(Clone, Debug, PartialEq)]
pub struct KdfParams {
    pub source: KdfSource,
    pub target: KdfTarget,
    pub source_slot_id: Option<u8>,
    pub target_slot_id: Option<u8>,
}

impl Default for KdfParams {
    fn default() -> KdfParams {
        KdfParams {
            source: KdfSource::TempKey,
            target: KdfTarget::Output,
            source_slot_id: None,
            target_slot_id: None,
        }
    }
}

/// KDF sources
#[derive(Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum KdfSource {
    /// source key in TempKey
    TempKey = 0x00,
    /// source key in upper TempKey
    TempKeyUp = 0x01,
    /// source key in a slot
    Slot = 0x02,
    /// source key in alternate key buffer
    AltKeyBuf = 0x03,
}

/// KDF targets. Possibility of exporting KDF function result outside the chip
/// depends on "chip_options.kdf_output_protection" variable
#[derive(Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum KdfTarget {
    /// target key in TempKey
    TempKey = 0x00,
    /// target key in upper TempKey
    TempKeyUp = 0x04,
    /// target key in slot
    Slot = 0x08,
    /// target key in alternate key buffer
    AltKeyBuf = 0x0C,
    /// target key in output buffer
    Output = 0x10,
    /// target key encrypted in output buffer
    OutputEnc = 0x14,
}

/// KDF details for PRF, source key length
#[derive(Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum KdfPrfKeyLen {
    /// source key length is 16 bytes
    Len16 = 0x00000000,
    /// source key length is 32 bytes
    Len32 = 0x00000001,
    /// source key length is 48 bytes
    Len48 = 0x00000002,
    /// source key length is 64 bytes
    Len64 = 0x00000003,
}

/// KDF details for PRF, target length
#[derive(Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum KdfPrfTargetLen {
    /// target length is 32 bytes
    Len32 = 0x00000000,
    /// target length is 64 bytes
    Len64 = 0x00000100,
}

impl From<KdfPrfTargetLen> for usize {
    fn from(orig: KdfPrfTargetLen) -> Self {
        match orig {
            KdfPrfTargetLen::Len32 => 32,
            KdfPrfTargetLen::Len64 => 64,
        }
    }
}

/// KDF details for PRF
#[derive(Clone, Debug, PartialEq)]
pub struct PrfDetails {
    pub key_length: KdfPrfKeyLen,
    pub target_length: KdfPrfTargetLen,
}

impl Default for PrfDetails {
    fn default() -> PrfDetails {
        PrfDetails {
            key_length: KdfPrfKeyLen::Len32,
            target_length: KdfPrfTargetLen::Len64,
        }
    }
}

/// KDF details for HKDF. [place from which function should retrieve message for calculations]
#[derive(Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum HkdfMsgLoc {
    /// message location in slot
    Slot = 0x00000000,
    /// message location in TempKey
    TempKey = 0x00000001,
    /// message location in input parameter
    Input = 0x00000002,
    /// message location is a special IV function
    Iv = 0x00000003,
}

/// KDF details for HKDF
#[derive(Clone, Debug, PartialEq)]
pub struct HkdfDetails {
    pub msg_loc: HkdfMsgLoc,
    /// if true then a vector of thirty-two zero bytes will be used as the key
    pub zero_key: bool,
    /// if source of message is a slot, its identifier must be entered
    pub msg_slot: Option<u8>,
}

impl Default for HkdfDetails {
    fn default() -> HkdfDetails {
        HkdfDetails {
            msg_loc: HkdfMsgLoc::Input,
            zero_key: false,
            msg_slot: None,
        }
    }
}

/// KDF result structure
#[derive(Clone, Debug, PartialEq)]
pub struct KdfResult {
    /// Data are available only when the target of the KDF function is 'Output' or 'OutputEnc'
    pub out_data: Option<Vec<u8>>,
    /// Data are available only when the target of the KDF function is 'OutputEnc'
    pub out_nonce: Option<Vec<u8>>,
}

/// ECDH function parameters
#[derive(Clone, Debug, PartialEq)]
pub struct EcdhParams {
    /// private key source for ECDH
    pub key_source: EcdhSource,
    /// target where the result of the ECDH operation will be placed
    pub out_target: EcdhTarget,
    /// parameter that specifies whether the output should be encrypted
    /// (only relevant for the ATECC608x chip)
    pub out_encrypt: bool,
    /// slot number where the private key will be retrieved
    /// or where result of the ECDH operation will be placed
    pub slot_id: Option<u8>,
}

impl Default for EcdhParams {
    fn default() -> EcdhParams {
        EcdhParams {
            key_source: EcdhSource::Slot,
            out_target: EcdhTarget::Compatibility,
            out_encrypt: false,
            slot_id: None,
        }
    }
}

/// Private key source for ECDH
#[derive(Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum EcdhSource{
    /// source key in a slot
    Slot = 0x00,
    /// source key in TempKey (only relevant for the ATECC608x chip)
    TempKey = 0x01,
}

/// Target where the result of the ECDH operation will be placed
#[derive(Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum EcdhTarget {
    /// Compatibility mode for ATECC508A. Result goes to either the output buffer
    /// or (slot_id + 1) depending on the state of slots[slot_idx].config.ecc_key_attr.ecdh_secret_out
    Compatibility = 0x00,
    /// Result goes to slot specified by KeyID. slots[slot_idx].write_config must be ALWAYS
    /// (only relevant for the ATECC608x chip)
    Slot  = 0x04,
    /// Result goes to TempKey (only relevant for the ATECC608x chip)
    TempKey = 0x08,
    /// Result goes to the output buffer (only relevant for the ATECC608x chip)
    Output = 0x0C,
}

/// ECDH result structure
#[derive(Clone, Debug, PartialEq)]
pub struct EcdhResult {
    /// Computed ECDH pre-master secret (32 bytes) if returned directly
    pub pms: Option<Vec<u8>>,
    /// Nonce used to encrypt pre-master secret
    pub out_nonce: Option<Vec<u8>>,
}

/// Data context structure for AEAD encryption in CCM mode
#[derive(Copy, Clone, Debug)]//, PartialEq)]
pub struct AtcaAesCcmCtx {
    pub cbc_mac_ctx: atca_aes_cmac_ctx_t,           // CBC_MAC context
    pub ctr_ctx: atca_aes_ctr_ctx_t,                // CTR context
    pub iv_size: u8,                                // iv size
    pub m: u8,                                      // Tag size
    pub counter: [u8; ATCA_AES_DATA_SIZE],          // Initial counter value
    pub partial_aad: [u8; ATCA_AES_DATA_SIZE],      // Partial blocks of data waiting to be processed
    pub partial_aad_size: usize,                    // Amount of data in the partial block buffer
    pub text_size: usize,                           // Size of data to be processed
    pub enc_cb: [u8; ATCA_AES_DATA_SIZE],           // Last encrypted counter block
    pub data_size: u32,                             // Size of the data being encrypted/decrypted in bytes.
    pub ciphertext_block: [u8; ATCA_AES_DATA_SIZE]  // Last ciphertext block
}

impl Default for AtcaAesCcmCtx {
    fn default() -> AtcaAesCcmCtx {
        AtcaAesCcmCtx {
            cbc_mac_ctx: {
                let ctx = MaybeUninit::<atca_aes_cmac_ctx_t>::zeroed();
                unsafe { ctx.assume_init() }
            },
            ctr_ctx: {
                let ctx = MaybeUninit::<atca_aes_ctr_ctx_t>::zeroed();
                unsafe { ctx.assume_init() }
            },
            iv_size: ATCA_AES_DATA_SIZE as u8,
            m: ATCA_AES_DATA_SIZE as u8,
            counter: [0x00; ATCA_AES_DATA_SIZE],
            partial_aad: [0x00; ATCA_AES_DATA_SIZE],
            partial_aad_size: 0,
            text_size: 0,
            enc_cb: [0x00; ATCA_AES_DATA_SIZE],
            data_size: 0,
            ciphertext_block: [0x00; ATCA_AES_DATA_SIZE],
        }
    }
}

/// structure that stores data for options supported by the chip
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct ChipOptions {
    /// If true, then the protection functions are enabled via the secret key
    /// stored in the slot indicated by io_key_in_slot.
    /// If false, the security functions are disabled and fields 'io_key_in_slot',
    /// 'ecdh_output_protection' and 'kdf_output_protection' are irrelevant
    /// (only relevant for the ATECC608x chip)
    pub io_key_enabled: bool,
    /// slot number where the key for encrypting transmission between chip and host is placed
    pub io_key_in_slot: u8,
    /// flag, on-chip availability, AES function
    pub aes_enabled: bool,
    /// flag, on-chip availability, AES functionality for KDF command
    pub kdf_aes_enabled: bool,
    /// restrictions on the way the ECDH command result can be used
    pub ecdh_output_protection: OutputProtectionState,
    /// restrictions on the way the KDF command result can be used
    pub kdf_output_protection: OutputProtectionState,
    /// availability flag of the special function of the IV KDF command 
    pub kdf_iv_enabled: bool,
    /// place in message where special data bytes must be placed
    /// when calling function IV of the KDF command
    pub kdf_iv_location_at: usize,
    /// two bytes of data that must be included in message
    /// when calling function IV of the KDF command
    pub kdf_iv_str: [u8; 0x02],
}

impl Default for ChipOptions {
    fn default() -> ChipOptions {
        ChipOptions {
            io_key_enabled: false,
            io_key_in_slot: 0x00,
            aes_enabled: false,
            kdf_aes_enabled: false,
            ecdh_output_protection: OutputProtectionState::Invalid,
            kdf_output_protection: OutputProtectionState::Invalid,
            kdf_iv_enabled: false,
            kdf_iv_location_at: 0x00,
            kdf_iv_str: [0x00, 0x00],
        }
    }
}

/// Allowed IO transmission states between chip and host MCU
/// for ECDH, KDF, Verify and SecureBoot commands.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum OutputProtectionState {
    /// Output in the clear is OK, though encryption can still be indicated in the mode parameter
    ClearTextAllowed = 0x00,
    /// Output is OK, but the result must be encrypted.
    /// The state of the encryption bit in the mode parameter will be ignored by the ECDH command.
    EncryptedOutputOnly = 0x01,
    /// Result must be stored in TempKey or and key slot, output outside the chip is forbidden
    ForbiddenOutputOutsideChip = 0x02,
    /// Invalid state
    Invalid = 0x03,
}

impl From<u8> for OutputProtectionState {
    fn from(orig: u8) -> Self {
        match orig {
            0x0 => OutputProtectionState::ClearTextAllowed,
            0x1 => OutputProtectionState::EncryptedOutputOnly,
            0x2 => OutputProtectionState::ForbiddenOutputOutsideChip,
            _ => OutputProtectionState::Invalid,
        }
    }
}

/// An ATECC slot
#[derive(Copy, Clone, Debug, Default)]
pub struct AtcaSlot {
    /// ATECC slot id (for diagnostic)
    pub id: u8,
    /// Lock status of slot (locked or not). If is_locked is true,
    /// slot cannot be written
    pub is_locked: bool,
    /// Slot configuration as can be read from configuration zone
    pub config: SlotConfig,
}

/// An ATECC slot capacity
#[derive(Copy, Clone, Debug, Default)]
pub struct AtcaSlotCapacity {
    pub blocks: u8,
    pub last_block_bytes: u8,
    pub bytes: u16,
}

/// Detailed ATECC key slot configuration
#[derive(Copy, Clone, Debug)]
pub struct SlotConfig {
    /// Controls the ability to modify the data in this slot.
    pub write_config: WriteConfig,

    pub key_type: KeyType,

    pub read_key: ReadKey,

    pub ecc_key_attr: EccKeyAttr,

    /// The index into the X509format array within the Configuration zone
    /// which corresponds to this slot.
    /// If the corresponding format byte is zero, then the public key
    /// can be validated by any format signature by the parent.
    /// If the corresponding format byte is non-zero, then the validating
    /// certificate must be of a certain length;
    /// the stored public key must be locateindicates this slot contains
    /// an ECC private key at a certain place within the message and the SHA()
    /// commands must be used to generate the digest of the message.
    /// Must be zero if the slot does not contain a public key.
    /// Valid range from 0 to 3.
    pub x509id: u8,

    /// If 'req_auth' is true, this field points to the key that must be used
    /// for authorization before the key associated with this slot may be used.
    /// Must be zero if 'req_auth' is false.
    /// Valid range from 0 to 15.
    pub auth_key: u8,

    /// Use this key to validate and encrypt data written to the slot
    /// indicated by this variable.
    /// Valid range from 0 to 15.
    pub write_key: u8,

    /// true = The contents of this slot are secret – Clear text reads are prohibited
    /// and both 4-byte reads and writes are prohibited.
    /// This variable must be true if 'encrypt_read' is a true or if 'write_config'
    /// has any value other than 'Always' to ensure proper operation of the device.
    /// false = The contents of this slot should contain neither confidential data nor keys.
    /// The GenKey and Sign commands will fail if 'is_secret'
    /// is set to false for any ECC private key.
    pub is_secret: bool,

    /// true = The key stored in the slot is "Limited Use".
    /// The number of uses of this key is limited by a in chip monotonic counter.
    /// false = There are no usage limitations.
    pub limited_use: bool,

    /// true = The key stored in the slot is intended for verification usage
    /// and cannot be used by the MAC or HMAC commands.
    /// When this key is used to generate or modify TempKey,
    /// then that value may not be used by the MAC and HMAC commands.
    /// Also cannot be used with the SHA command in HMAC mode.
    /// false = The key stored in the slot can be used by all commands.
    pub no_mac: bool,

    /// true = Use of this key is prohibited for all commands other than
    /// GenKey if the PersistentLatch is zero.
    /// GenKey is permitted regardless of the state of the latch.
    /// false = Use of this key is independent of the state of the PersistentLatch.
    pub persistent_disable: bool,

    /// true = Before this key must be used, a prior authorization using
    /// the key pointed to by AuthKey must be completed successfully
    /// prior to cryptographic use of the key.
    /// Applies to all key types, both public, secret, and private.
    /// false = No prior authorization is required.
    pub req_auth: bool,

    /// If true then a random nonce is required for
    /// GenKey, MAC, CheckMac, Verify, DeriveKey, and GenDig commands.
    pub req_random: bool,

    /// If true then this slot can be individually locked using the Lock command.
    pub lockable: bool,

    /// If 'is_private' indicates this slot contains an ECC private key:
    /// false = The public version of this key can never be generated.
    /// Use this mode for the highest security.
    /// true = The public version of this key can always be generated.
    /// If 'is_private' indicates that this slot does not contain an ECC private key,
    /// then this bit may be used to control validity of public keys.
    /// If so configured, the Verify command will only use a stored public key
    /// to verify a signature if it has been validated.
    /// The Sign and Info commands are used to report the validity state.
    /// The public key validity feature is ignored by all other commands
    /// and applies only to Slots 8 - 15.
    /// false = The public key in this slot can be used by the Verify command
    /// without being validated.
    /// true = The public key in this slot can be used by the Verify command
    /// only if the public key in the slot has been validated.
    /// When this slot is written for any reason, the most significant four bits
    /// of byte 0 of block 0 will be set to 0xA to invalidate the slot.
    /// The Verify command can be used to write those bits to 0x05 to validate the slot.
    /// If this slot contains a key of type Data or AES, then the 'pub_info' bit
    /// controls whether or not the KDF command write data into this slot.
    /// If true, then writes by KDF are allowed.
    /// If false, KDF may not write to this slot.
    pub pub_info: bool,
}

impl Default for SlotConfig {
    fn default() -> Self {
        SlotConfig {
            write_config: WriteConfig::Rfu,
            key_type: KeyType::Rfu,
            read_key: ReadKey::default(),
            ecc_key_attr: EccKeyAttr::default(),
            x509id: 0u8,
            auth_key: 0u8,
            write_key: 0u8,
            is_secret: false,
            limited_use: false,
            no_mac: false,
            persistent_disable: false,
            req_auth: false,
            req_random: false,
            lockable: false,
            pub_info: false,
        }
    }
}

/// Detailed ECC key attributes as stored in slot configuration
#[derive(Copy, Clone, Debug, Default)]
pub struct EccKeyAttr {
    /// true = The key slot contains an ECC private key and
    /// can be accessed only with the Sign, GenKey, and PrivWrite commands.
    /// false = The key slot does not contain an ECC private key and
    /// cannot be accessed with the Sign, GenKey, and PrivWrite commands.
    /// It may contain an ECC public key, a SHA key, or data.
    pub is_private: bool,

    /// Slots containing private keys can never be read
    /// so the fields below are only valid if 'is_private' is true.

    /// false = External signatures of arbitrary messages are not enabled.
    /// true = External signatures of arbitrary messages are enabled.
    pub ext_sign: bool,

    /// false = Internal signatures of messages are not enabled.
    /// true = Internal signatures of messages generated by
    /// GenDig or GenKey are enabled.
    pub int_sign: bool,

    /// false = ECDH operation is not permitted for this key.
    /// true = ECDH operation is permitted for this key.
    pub ecdh_operation: bool,

    /// false = ECDH master secret will be output in the clear.
    /// true = Master secret will be written into slot N+1.
    /// (Can only be set to true for even number slots and
    /// should always be false for odd number slots)
    /// This bit is ignored if 'ecdh_operation' is false.
    pub ecdh_secret_out: bool,
}

/// Detailed ATECC key slot read attributes
#[derive(Copy, Clone, Debug, Default)]
pub struct ReadKey {
    /// true = Reads from this slot will be encrypted using the procedure
    /// specified in the Read command using value of 'slot_number'
    /// to generate the encryption key. No input MAC is required.
    /// If this bit is true, then 'is_secret'
    /// from 'SlotConfig' struct must also be set.
    /// false = Clear text reads may be permitted,
    /// and the 'slot_number' field is irrelevant.
    pub encrypt_read: bool,

    /// Valid range from 0 to 15.
    /// If 0 then this slot can be the source for the CheckMac copy operation.
    /// Do not use zero as a default. Do not set this field to zero
    /// unless the CheckMac copy operation is explicitly desired,
    /// regardless of any other read/write restrictions.
    pub slot_number: u8,
}

/// Detailed ATECC key slot write configuration
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum WriteConfig {
    Rfu,    // do not use

    /// Clear text writes are always permitted on this slot.
    /// Slots set to always should never be used as key storage.
    /// Either 4 or 32 bytes may be written to this slot.
    Always,

    /// If a validated public key is stored in the slot, writes are prohibited.
    /// Use Verify(Invalidate) to invalidate prior to writing.
    /// Do not use this mode unless slot contains a public key.
    PubInvalid,

    /// Writes are never permitted on this slot using the Write command.
    /// Slots set to never can still be used as key storage.
    Never,

    /// Writes to this slot require a properly computed MAC,
    /// and the input data must be encrypted by the system with WriteKey
    /// using the encryption algorithm documented in the Write command description.
    /// 4-byte writes to this slot are prohibited.
    Encrypt,
}

/// ATECC key slot types
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum KeyType {
    /// Do not use (Reserved for Future Use)
    Rfu,
    /// Slot may contain ECC key
    P256EccKey,
    /// Slot may contain AES key
    Aes,
    /// Slot may contain hash value or a raw text
    ShaOrText,
}

/// ATECC interface configuration
#[derive(Copy, Clone)]
pub struct AtcaIfaceCfg {
    /// ATECC interface type
    iface_type: AtcaIfaceType,
    /// ATECC device type
    devtype: AtcaDeviceType,
    /// ATECC interface details (contents depend on interface type).
    /// Not needed at all for "test-interface"
    iface: Option<AtcaIface>,
    wake_delay: u16,
    rx_retries: i32,
} // pub struct AtcaIfaceCfg

/// ATECC interface
// Only one can be instantiated at a time
#[derive(Copy, Clone)]
pub union AtcaIface {
    /// ATECC I2C interface settings
    pub atcai2c: AtcaIfaceI2c,
    // pub atcaswi: AtcaIfaceSwi,
    // pub atcauart: AtcaIfaceUart,
    // pub atcahid: AtcaIfaceHid,
} // pub union AtcaIface

/// ATECC I2C interface details
#[derive(Copy, Clone, Default)]
pub struct AtcaIfaceI2c {
    /// ATECC I2C bus address
    slave_address: u8,
    /// ATECC I2C bus number
    bus: u8,
    /// ATECC I2C bus baud rate
    baud: u32,
} // pub struct AtcaIfaceI2c

/// Supported ATECC interfaces
#[derive(PartialEq, Copy, Clone, Display)]
pub enum AtcaIfaceType {
    AtcaI2cIface,
    AtcaSwiIface,
    AtcaUartIface,
    AtcaSpiIface,
    AtcaHidIface,
    AtcaCustomIface,
    AtcaTestIface,
    AtcaUnknownIface,
} // pub enum AtcaIfaceType

/// ATECC/ATSHA device types supported by CryptoAuth library
#[derive(PartialEq, Debug, Display, Copy, Clone)]
pub enum AtcaDeviceType {
    ATSHA204A,
    ATECC108A,
    ATECC508A,
    ATECC608A,
    ATSHA206A,
    AtcaTestDevFail,
    AtcaTestDevSuccess,
    AtcaTestDevNone,
    AtcaTestDevFailUnimplemented,
    AtcaDevUnknown,
} // pub enum AtcaDeviceType

/// Return status for device accessing functions
#[derive(Debug, Copy, Clone, Display, PartialEq)]
pub enum AtcaStatus {
    /// Function succeeded.
    AtcaSuccess,
    AtcaConfigZoneLocked,
    AtcaDataZoneLocked,
    /// response status byte indicates CheckMac failure (status byte = 0x01)
    AtcaWakeFailed,
    /// response status byte indicates CheckMac failure (status byte = 0x01)
    AtcaCheckMacVerifyFailed,
    /// response status byte indicates parsing error (status byte = 0x03)
    AtcaParseError,
    /// response status byte indicates DEVICE did not receive data properly (status byte = 0xFF)
    AtcaStatusCrc,
    /// response status byte is unknown
    AtcaStatusUnknown,
    /// response status byte is ECC fault (status byte = 0x05)
    AtcaStatusEcc,
    /// response status byte is Self Test Error, chip in failure mode (status byte = 0x07)
    AtcaStatusSelftestError,
    /// Function could not execute due to incorrect condition / state.
    AtcaFuncFail,
    /// unspecified error
    AtcaGenFail,
    /// bad argument (out of range, null pointer, etc.)
    AtcaBadParam,
    /// invalid device id, id not set
    AtcaInvalidId,
    /// Count value is out of range or greater than buffer size.
    AtcaInvalidSize,
    /// CRC error in data received from device
    AtcaRxCrcError,
    /// Timed out while waiting for response. Number of bytes received is > 0.
    AtcaRxFail,
    /// Not an error while the Command layer is polling for a command response.
    AtcaRxNoResponse,
    /// Re-synchronization succeeded, but only after generating a Wake-up
    AtcaResyncWithWakeup,
    /// for protocols needing parity
    AtcaParityError,
    /// for Microchip PHY protocol, timeout on transmission waiting for master
    AtcaTxTimeout,
    /// for Microchip PHY protocol, timeout on receipt waiting for master
    AtcaRxTimeout,
    /// Device did not respond too many times during a transmission. Could indicate no device present.
    AtcaTooManyCommRetries,
    /// Supplied buffer is too small for data required
    AtcaSmallBuffer,
    /// Communication with device failed. Same as in hardware dependent modules.
    AtcaCommFail,
    /// Timed out while waiting for response. Number of bytes received is 0.
    AtcaTimeout,
    /// opcode is not supported by the device
    AtcaBadOpcode,
    /// received proper wake token
    AtcaWakeSuccess,
    /// chip was in a state where it could not execute the command, response status byte indicates command execution error (status byte = 0x0F)
    AtcaExecutionError,
    /// Function or some element of it hasn't been implemented yet
    AtcaUnimplemented,
    /// Code failed run-time consistency check
    AtcaAssertFailure,
    /// Failed to write
    AtcaTxFail,
    /// required zone was not locked
    AtcaNotLocked,
    /// For protocols that support device discovery (kit protocol), no devices were found
    AtcaNoDevices,
    /// random number generator health test error
    AtcaHealthTestError,
    /// Couldn't allocate required memory
    AtcaAllocFailure,
    /// Use flags on the device indicates its consumed fully
    AtcaUseFlagsConsumed,
    /// Unknown error occured
    AtcaUnknown,
} // pub enum AtcaStatus

#[derive(Debug)]
struct AtcaIfaceCfgPtrWrapper {
    ptr: *mut cryptoauthlib_sys::ATCAIfaceCfg,
}

unsafe impl Send for AtcaIfaceCfgPtrWrapper {}
unsafe impl Sync for AtcaIfaceCfgPtrWrapper {}
