#[macro_use]
extern crate strum_macros; // 0.10.0

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
enum InfoCmdType {
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

impl Default for VerifyEcdsaParam {
    fn default() -> VerifyEcdsaParam {
        VerifyEcdsaParam {
            public_key: None,
            slot_number: None,
            num_in: Vec::new(),
            io_key: 0x00,
        }
    }
}

/// An ATECC slot
#[derive(Copy, Clone, Debug)]
pub struct AtcaSlot {
    /// ATECC slot id (for diagnostic)
    pub id: u8,
    /// Lock status of slot (locked or not). If is_locked is true,
    /// slot cannot be written
    pub is_locked: bool,
    /// Slot configuration as can be read from configuration zone
    pub config: SlotConfig,
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

/// Detailed ECC key attributes as stored in slot configuration
#[derive(Copy, Clone, Debug)]
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
#[derive(Copy, Clone, Debug)]
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
pub struct AtcaIfaceCfg {
    /// ATECC interface type
    pub iface_type: AtcaIfaceType,
    /// ATECC device type
    pub devtype: AtcaDeviceType,
    /// ATECC interface details (contents depend on interface type)
    pub iface: AtcaIface,
    pub wake_delay: u16,
    pub rx_retries: i32,
} // pub struct AtcaIfaceCfg

/// ATECC interface
pub union AtcaIface {
    /// ATECC I2C interface settings
    pub atcai2c: AtcaIfaceI2c,
    // pub atcaswi: AtcaIfaceSwi,
    // pub atcauart: AtcaIfaceUart,
    // pub atcahid: AtcaIfaceHid,
} // pub union AtcaIface

/// ATECC I2C interface details
#[derive(Copy, Clone)]
pub struct AtcaIfaceI2c {
    /// ATECC I2C bus address
    pub slave_address: u8,
    /// ATECC I2C bus number
    pub bus: u8,
    /// ATECC I2C bus baud rate
    pub baud: u32,
} // pub struct AtcaIfaceI2c

/// Supported ATECC interfaces
#[derive(Copy, Clone, Display)]
pub enum AtcaIfaceType {
    AtcaI2cIface,
    AtcaSwiIface,
    AtcaUartIface,
    AtcaSpiIface,
    AtcaHidIface,
    AtcaCustomIface,
    AtcaUnknownIface,
} // pub enum AtcaIfaceType

/// ATECC/ATSHA device types supported by CryptoAuth library
#[derive(PartialEq, Debug, Display)]
pub enum AtcaDeviceType {
    ATSHA204A,
    ATECC108A,
    ATECC508A,
    ATECC608A,
    ATSHA206A,
    AtcaDevUnknown,
} // pub enum AtcaDeviceType

/// Return status for device accessing functions
#[derive(Debug,Display,PartialEq)]
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

/// The Rust box for C object backing ATCADevice
#[derive(Debug,Clone)]
// supress "warning: field is never read: `dev`"
#[allow(dead_code)]
#[deprecated]
pub struct AtcaDevice {
    dev: cryptoauthlib_sys::ATCADevice,
}

#[allow(deprecated)]
unsafe impl Send for AtcaDevice {}
#[allow(deprecated)]
unsafe impl Sync for AtcaDevice {}

#[derive(Debug)]
struct AtcaIfaceCfgPtrWrapper {
    ptr: *mut cryptoauthlib_sys::ATCAIfaceCfg,
}

unsafe impl Send for AtcaIfaceCfgPtrWrapper {}
unsafe impl Sync for AtcaIfaceCfgPtrWrapper {}