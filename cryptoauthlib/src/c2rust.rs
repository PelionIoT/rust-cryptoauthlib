use cryptoauthlib_sys;

pub fn c2r_enum_status(atca_status: cryptoauthlib_sys::ATCA_STATUS) -> super::AtcaStatus {
    return match atca_status {
        cryptoauthlib_sys::ATCA_STATUS_ATCA_SUCCESS => super::AtcaStatus::AtcaSuccess,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_CONFIG_ZONE_LOCKED => {
            super::AtcaStatus::AtcaConfigZoneLocked
        }
        cryptoauthlib_sys::ATCA_STATUS_ATCA_DATA_ZONE_LOCKED => {
            super::AtcaStatus::AtcaDataZoneLocked
        }
        cryptoauthlib_sys::ATCA_STATUS_ATCA_WAKE_FAILED => super::AtcaStatus::AtcaWakeFailed,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_CHECKMAC_VERIFY_FAILED => {
            super::AtcaStatus::AtcaCheckMacVerifyFailed
        }
        cryptoauthlib_sys::ATCA_STATUS_ATCA_PARSE_ERROR => super::AtcaStatus::AtcaParseError,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_STATUS_CRC => super::AtcaStatus::AtcaStatusCrc,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_STATUS_UNKNOWN => super::AtcaStatus::AtcaStatusUnknown,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_STATUS_ECC => super::AtcaStatus::AtcaStatusEcc,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_STATUS_SELFTEST_ERROR => {
            super::AtcaStatus::AtcaStatusSelftestError
        }
        cryptoauthlib_sys::ATCA_STATUS_ATCA_FUNC_FAIL => super::AtcaStatus::AtcaFuncFail,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_GEN_FAIL => super::AtcaStatus::AtcaGenFail,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_BAD_PARAM => super::AtcaStatus::AtcaBadParam,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_INVALID_ID => super::AtcaStatus::AtcaInvalidId,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_INVALID_SIZE => super::AtcaStatus::AtcaInvalidSize,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_RX_CRC_ERROR => super::AtcaStatus::AtcaRxCrcError,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_RX_FAIL => super::AtcaStatus::AtcaRxFail,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_RX_NO_RESPONSE => super::AtcaStatus::AtcaRxNoResponse,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_RESYNC_WITH_WAKEUP => {
            super::AtcaStatus::AtcaResyncWithWakeup
        }
        cryptoauthlib_sys::ATCA_STATUS_ATCA_PARITY_ERROR => super::AtcaStatus::AtcaParityError,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_TX_TIMEOUT => super::AtcaStatus::AtcaTxTimeout,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_RX_TIMEOUT => super::AtcaStatus::AtcaRxTimeout,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_TOO_MANY_COMM_RETRIES => {
            super::AtcaStatus::AtcaTooManyCommRetries
        }
        cryptoauthlib_sys::ATCA_STATUS_ATCA_SMALL_BUFFER => super::AtcaStatus::AtcaSmallBuffer,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_COMM_FAIL => super::AtcaStatus::AtcaCommFail,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_TIMEOUT => super::AtcaStatus::AtcaTimeout,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_BAD_OPCODE => super::AtcaStatus::AtcaBadOpcode,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_WAKE_SUCCESS => super::AtcaStatus::AtcaWakeSuccess,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_EXECUTION_ERROR => {
            super::AtcaStatus::AtcaExecutionError
        }
        cryptoauthlib_sys::ATCA_STATUS_ATCA_UNIMPLEMENTED => super::AtcaStatus::AtcaUnimplemented,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_ASSERT_FAILURE => super::AtcaStatus::AtcaAssertFailure,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_TX_FAIL => super::AtcaStatus::AtcaTxFail,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_NOT_LOCKED => super::AtcaStatus::AtcaNotLocked,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_NO_DEVICES => super::AtcaStatus::AtcaNoDevices,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_HEALTH_TEST_ERROR => {
            super::AtcaStatus::AtcaHealthTestError
        }
        cryptoauthlib_sys::ATCA_STATUS_ATCA_ALLOC_FAILURE => super::AtcaStatus::AtcaAllocFailure,
        cryptoauthlib_sys::ATCA_STATUS_ATCA_USE_FLAGS_CONSUMED => {
            super::AtcaStatus::AtcaUseFlagsConsumed
        }
        _ => super::AtcaStatus::AtcaUnknown,
    };
}
