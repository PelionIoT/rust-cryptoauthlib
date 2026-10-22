use super::{AtcaDeviceType, AtcaStatus};
use std::convert::From;

// In cryptoauthlib 3.8.0 the status codes are plain macros (`ATCA_SUCCESS`, ...) whose
// integer type chosen by bindgen differs from `ATCA_STATUS` (c_int), so they cannot be
// used directly as match patterns.
macro_rules! map_status {
    ($value:expr, { $($code:ident => $variant:expr),* $(,)? }) => {{
        let value = $value;
        $(
            if value == cryptoauthlib_sys::$code as cryptoauthlib_sys::ATCA_STATUS {
                return $variant;
            }
        )*
        AtcaStatus::AtcaUnknown
    }};
}

impl From<cryptoauthlib_sys::ATCA_STATUS> for AtcaStatus {
    fn from(atca_status: cryptoauthlib_sys::ATCA_STATUS) -> Self {
        map_status!(atca_status, {
            ATCA_SUCCESS => AtcaStatus::AtcaSuccess,
            ATCA_CONFIG_ZONE_LOCKED => AtcaStatus::AtcaConfigZoneLocked,
            ATCA_DATA_ZONE_LOCKED => AtcaStatus::AtcaDataZoneLocked,
            ATCA_WAKE_FAILED => AtcaStatus::AtcaWakeFailed,
            ATCA_CHECKMAC_VERIFY_FAILED => AtcaStatus::AtcaCheckMacVerifyFailed,
            ATCA_PARSE_ERROR => AtcaStatus::AtcaParseError,
            ATCA_STATUS_CRC => AtcaStatus::AtcaStatusCrc,
            ATCA_STATUS_UNKNOWN => AtcaStatus::AtcaStatusUnknown,
            ATCA_STATUS_ECC => AtcaStatus::AtcaStatusEcc,
            ATCA_STATUS_SELFTEST_ERROR => AtcaStatus::AtcaStatusSelftestError,
            ATCA_FUNC_FAIL => AtcaStatus::AtcaFuncFail,
            ATCA_GEN_FAIL => AtcaStatus::AtcaGenFail,
            ATCA_BAD_PARAM => AtcaStatus::AtcaBadParam,
            ATCA_INVALID_ID => AtcaStatus::AtcaInvalidId,
            ATCA_INVALID_SIZE => AtcaStatus::AtcaInvalidSize,
            ATCA_RX_CRC_ERROR => AtcaStatus::AtcaRxCrcError,
            ATCA_RX_FAIL => AtcaStatus::AtcaRxFail,
            ATCA_RX_NO_RESPONSE => AtcaStatus::AtcaRxNoResponse,
            ATCA_RESYNC_WITH_WAKEUP => AtcaStatus::AtcaResyncWithWakeup,
            ATCA_PARITY_ERROR => AtcaStatus::AtcaParityError,
            ATCA_TX_TIMEOUT => AtcaStatus::AtcaTxTimeout,
            ATCA_RX_TIMEOUT => AtcaStatus::AtcaRxTimeout,
            ATCA_TOO_MANY_COMM_RETRIES => AtcaStatus::AtcaTooManyCommRetries,
            ATCA_SMALL_BUFFER => AtcaStatus::AtcaSmallBuffer,
            ATCA_COMM_FAIL => AtcaStatus::AtcaCommFail,
            ATCA_TIMEOUT => AtcaStatus::AtcaTimeout,
            ATCA_BAD_OPCODE => AtcaStatus::AtcaBadOpcode,
            ATCA_WAKE_SUCCESS => AtcaStatus::AtcaWakeSuccess,
            ATCA_EXECUTION_ERROR => AtcaStatus::AtcaExecutionError,
            ATCA_UNIMPLEMENTED => AtcaStatus::AtcaUnimplemented,
            ATCA_ASSERT_FAILURE => AtcaStatus::AtcaAssertFailure,
            ATCA_TX_FAIL => AtcaStatus::AtcaTxFail,
            ATCA_NOT_LOCKED => AtcaStatus::AtcaNotLocked,
            ATCA_NO_DEVICES => AtcaStatus::AtcaNoDevices,
            ATCA_HEALTH_TEST_ERROR => AtcaStatus::AtcaHealthTestError,
            ATCA_ALLOC_FAILURE => AtcaStatus::AtcaAllocFailure,
            ATCA_USE_FLAGS_CONSUMED => AtcaStatus::AtcaUseFlagsConsumed,
        })
    }
}

impl From<cryptoauthlib_sys::ATCADeviceType> for AtcaDeviceType {
    fn from(device_type: cryptoauthlib_sys::ATCADeviceType) -> Self {
        match device_type {
            x if x == cryptoauthlib_sys::ATSHA204A as cryptoauthlib_sys::ATCADeviceType => {
                AtcaDeviceType::ATSHA204A
            }
            x if x == cryptoauthlib_sys::ATECC108A as cryptoauthlib_sys::ATCADeviceType => {
                AtcaDeviceType::ATECC108A
            }
            x if x == cryptoauthlib_sys::ATECC508A as cryptoauthlib_sys::ATCADeviceType => {
                AtcaDeviceType::ATECC508A
            }
            x if x == cryptoauthlib_sys::ATECC608A as cryptoauthlib_sys::ATCADeviceType => {
                AtcaDeviceType::ATECC608A
            }
            x if x == cryptoauthlib_sys::ATSHA206A as cryptoauthlib_sys::ATCADeviceType => {
                AtcaDeviceType::ATSHA206A
            }
            _ => AtcaDeviceType::AtcaDevUnknown,
        }
    }
}
