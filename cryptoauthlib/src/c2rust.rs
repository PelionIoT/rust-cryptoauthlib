use super::AtcaStatus;
use std::convert::From;

impl From<cryptoauthlib_sys::ATCA_STATUS> for AtcaStatus {
    fn from(atca_status: cryptoauthlib_sys::ATCA_STATUS) -> Self {
        match atca_status {
            cryptoauthlib_sys::ATCA_STATUS_ATCA_SUCCESS => AtcaStatus::AtcaSuccess,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_CONFIG_ZONE_LOCKED => {
                AtcaStatus::AtcaConfigZoneLocked
            }
            cryptoauthlib_sys::ATCA_STATUS_ATCA_DATA_ZONE_LOCKED => AtcaStatus::AtcaDataZoneLocked,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_WAKE_FAILED => AtcaStatus::AtcaWakeFailed,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_CHECKMAC_VERIFY_FAILED => {
                AtcaStatus::AtcaCheckMacVerifyFailed
            }
            cryptoauthlib_sys::ATCA_STATUS_ATCA_PARSE_ERROR => AtcaStatus::AtcaParseError,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_STATUS_CRC => AtcaStatus::AtcaStatusCrc,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_STATUS_UNKNOWN => AtcaStatus::AtcaStatusUnknown,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_STATUS_ECC => AtcaStatus::AtcaStatusEcc,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_STATUS_SELFTEST_ERROR => {
                AtcaStatus::AtcaStatusSelftestError
            }
            cryptoauthlib_sys::ATCA_STATUS_ATCA_FUNC_FAIL => AtcaStatus::AtcaFuncFail,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_GEN_FAIL => AtcaStatus::AtcaGenFail,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_BAD_PARAM => AtcaStatus::AtcaBadParam,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_INVALID_ID => AtcaStatus::AtcaInvalidId,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_INVALID_SIZE => AtcaStatus::AtcaInvalidSize,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_RX_CRC_ERROR => AtcaStatus::AtcaRxCrcError,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_RX_FAIL => AtcaStatus::AtcaRxFail,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_RX_NO_RESPONSE => AtcaStatus::AtcaRxNoResponse,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_RESYNC_WITH_WAKEUP => {
                AtcaStatus::AtcaResyncWithWakeup
            }
            cryptoauthlib_sys::ATCA_STATUS_ATCA_PARITY_ERROR => AtcaStatus::AtcaParityError,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_TX_TIMEOUT => AtcaStatus::AtcaTxTimeout,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_RX_TIMEOUT => AtcaStatus::AtcaRxTimeout,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_TOO_MANY_COMM_RETRIES => {
                AtcaStatus::AtcaTooManyCommRetries
            }
            cryptoauthlib_sys::ATCA_STATUS_ATCA_SMALL_BUFFER => AtcaStatus::AtcaSmallBuffer,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_COMM_FAIL => AtcaStatus::AtcaCommFail,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_TIMEOUT => AtcaStatus::AtcaTimeout,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_BAD_OPCODE => AtcaStatus::AtcaBadOpcode,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_WAKE_SUCCESS => AtcaStatus::AtcaWakeSuccess,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_EXECUTION_ERROR => AtcaStatus::AtcaExecutionError,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_UNIMPLEMENTED => AtcaStatus::AtcaUnimplemented,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_ASSERT_FAILURE => AtcaStatus::AtcaAssertFailure,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_TX_FAIL => AtcaStatus::AtcaTxFail,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_NOT_LOCKED => AtcaStatus::AtcaNotLocked,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_NO_DEVICES => AtcaStatus::AtcaNoDevices,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_HEALTH_TEST_ERROR => {
                AtcaStatus::AtcaHealthTestError
            }
            cryptoauthlib_sys::ATCA_STATUS_ATCA_ALLOC_FAILURE => AtcaStatus::AtcaAllocFailure,
            cryptoauthlib_sys::ATCA_STATUS_ATCA_USE_FLAGS_CONSUMED => {
                AtcaStatus::AtcaUseFlagsConsumed
            }
            _ => AtcaStatus::AtcaUnknown,
        }
    }
}

impl From<cryptoauthlib_sys::ATCADeviceType> for super::AtcaDeviceType {
    fn from(device_type: cryptoauthlib_sys::ATCADeviceType) -> Self {
        match device_type {
            cryptoauthlib_sys::ATCADeviceType_ATSHA204A => super::AtcaDeviceType::ATSHA204A,
            cryptoauthlib_sys::ATCADeviceType_ATECC108A => super::AtcaDeviceType::ATECC108A,
            cryptoauthlib_sys::ATCADeviceType_ATECC508A => super::AtcaDeviceType::ATECC508A,
            cryptoauthlib_sys::ATCADeviceType_ATECC608A => super::AtcaDeviceType::ATECC608A,
            cryptoauthlib_sys::ATCADeviceType_ATSHA206A => super::AtcaDeviceType::ATSHA206A,
            _ => super::AtcaDeviceType::AtcaDevUnknown,
        }
    }
}
