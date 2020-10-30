use cryptoauthlib_sys;

pub fn cal_enum_status(atca_status: cryptoauthlib_sys::ATCA_STATUS) -> super::AtcaStatus {
    return match atca_status {
        cryptoauthlib_sys::ATCA_STATUS_ATCA_SUCCESS => super::AtcaStatus::AtcaSuccess,
        _ => super::AtcaStatus::AtcaUnknown,
    }
}