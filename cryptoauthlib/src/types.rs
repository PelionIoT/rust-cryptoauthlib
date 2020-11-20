#[macro_use]
extern crate strum_macros; // 0.10.0

pub struct AtcaIfaceCfg {
    pub iface_type: AtcaIfaceType,
    pub devtype: AtcaDeviceType,
    pub iface: AtcaIface,
    pub wake_delay: u16,
    pub rx_retries: i32,
} // pub struct AtcaIfaceCfg

pub union AtcaIface {
    pub atcai2c: AtcaIfaceI2c,
    // pub atcaswi: AtcaIfaceSwi,
    // pub atcauart: AtcaIfaceUart,
    // pub atcahid: AtcaIfaceHid,
} // pub union AtcaIface

#[derive(Copy, Clone)]
pub struct AtcaIfaceI2c {
    pub slave_address: u8,
    pub bus: u8,
    pub baud: u32,
} // pub struct AtcaIfaceI2c

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

/// The supported Device type in Cryptoauthlib library
#[derive(Display)]
pub enum AtcaDeviceType {
    ATSHA204A,
    ATECC108A,
    ATECC508A,
    ATECC608A,
    ATSHA206A,
    AtcaDevUnknown,
} // pub enum AtcaDeviceType

/// Return status for ATCA functions
#[derive(Debug,Display)]
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

// pub type AtcaDevicePtr = *mut AtcaDevice;
// pub struct AtcaDevice {
//     #[doc = "!< Command set for a given CryptoAuth device"]
//     pub commands: AtcaCommandPtr,
//     #[doc = "!< Physical interface"]
//     pub iface: AtcaIface,
// }

// pub type AtcaCommandPtr = *mut AtcaCommand;
// pub struct AtcaCommand {
//     pub dt: AtcaDeviceType,
//     pub clock_divider: u8,
//     pub execution_time_msec: u16,
// }

/// The C object backing ATCADevice
pub type AtcaDevice = cryptoauthlib_sys::ATCADevice;
