
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


pub enum AtcaIfaceType {
    AtcaI2cIface,
    AtcaSwiIface,
    AtcaUartIface,
    AtcaSpiIface,
    AtcaHidIface,
    AtcaCustomIface,
    AtcaUnknownIface,
} // pub enum AtcaIfaceType

#[doc = " \\brief The supported Device type in Cryptoauthlib library"]
pub enum AtcaDeviceType {
    ATSHA204A,
    ATECC108A,
    ATECC508A,
    ATECC608A,
    ATSHA206A,
    AtcaDevUnknown,
} // pub enum AtcaDeviceType

pub enum AtcaStatus {
    #[doc = "!< Function succeeded."]
    AtcaSuccess,
    AtcaConfigZoneLocked,
    AtcaDataZoneLocked,
    #[doc = "!< response status byte indicates CheckMac failure (status byte = 0x01)"]
    AtcaWakeFailed,
    #[doc = "!< response status byte indicates CheckMac failure (status byte = 0x01)"]
    AtcaCheckMacVerifyFailed,
    #[doc = "!< response status byte indicates parsing error (status byte = 0x03)"]
    AtcaParseError,
    #[doc = "!< response status byte indicates DEVICE did not receive data properly (status byte = 0xFF)"]
    AtcaStatusCrc,
    #[doc = "!< response status byte is unknown"]
    AtcaStatusUnknown,
    #[doc = "!< response status byte is ECC fault (status byte = 0x05)"]
    AtcaStatusEcc,
    #[doc = "!< response status byte is Self Test Error, chip in failure mode (status byte = 0x07)"]
    AtcaStatusSelftestError,
    #[doc = "!< Function could not execute due to incorrect condition / state."]
    AtcaFuncFail,
    #[doc = "!< unspecified error"]
    AtcaGenFail,
    #[doc = "!< bad argument (out of range, null pointer, etc.)"]
    AtcaBadParam,
    #[doc = "!< invalid device id, id not set"]
    AtcaInvalidId,
    #[doc = "!< Count value is out of range or greater than buffer size."]
    AtcaInvalidSize,
    #[doc = "!< CRC error in data received from device"]
    AtcaRxCrcError,
    #[doc = "!< Timed out while waiting for response. Number of bytes received is > 0."]
    AtcaRxFail,
    #[doc = "!< Not an error while the Command layer is polling for a command response."]
    AtcaRxNoResponse,
    #[doc = "!< Re-synchronization succeeded, but only after generating a Wake-up"]
    AtcaResyncWithWakeup,
    #[doc = "!< for protocols needing parity"]
    AtcaParityError,
    #[doc = "!< for Microchip PHY protocol, timeout on transmission waiting for master"]
    AtcaTxTimeout,
    #[doc = "!< for Microchip PHY protocol, timeout on receipt waiting for master"]
    AtcaRxTimeout,
    #[doc = "!< Device did not respond too many times during a transmission. Could indicate no device present."]
    AtcaTooManyCommRetries,
    #[doc = "!< Supplied buffer is too small for data required"]
    AtcaSmallBuffer,
    #[doc = "!< Communication with device failed. Same as in hardware dependent modules."]
    AtcaCommFail,
    #[doc = "!< Timed out while waiting for response. Number of bytes received is 0."]
    AtcaTimeout,
    #[doc = "!< opcode is not supported by the device"]
    AtcaBadOpcode,
    #[doc = "!< received proper wake token"]
    AtcaWakeSuccess,
    #[doc = "!< chip was in a state where it could not execute the command, response status byte indicates command execution error (status byte = 0x0F)"]
    AtcaExecutionError,
    #[doc = "!< Function or some element of it hasn't been implemented yet"]
    AtcaUnimplemented,
    #[doc = "!< Code failed run-time consistency check"]
    AtcaAssertFailure,
    #[doc = "!< Failed to write"]
    AtcaTxFail,
    #[doc = "!< required zone was not locked"]
    AtcaNotLocked,
    #[doc = "!< For protocols that support device discovery (kit protocol), no devices were found"]
    AtcaNoDevices,
    #[doc = "!< random number generator health test error"]
    AtcaHealthTestError,
    #[doc = "!< Couldn't allocate required memory"]
    AtcaAllocFailure,
    #[doc = "!< Use flags on the device indicates its consumed fully"]
    AtcaUseFlagsConsumed,
    #[doc = "!< Unknown error occured"]
    AtcaUnknown,
} // pub enum AtcaStatus
