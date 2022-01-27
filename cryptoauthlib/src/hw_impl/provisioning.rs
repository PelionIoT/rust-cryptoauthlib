// ATTENTION these functions should be called knowing what you are doing !!!
//
// The lack of tests for this module is intentional because, in most cases,
// these functions can only be called once and block the possibility of further changes to the chip.
// --------------------------------------------------------------------------------------------------
//
// Below is the content of the test configuration for the ATECC608A chip, used in testing this crate.
// This configuration was created for testing purposes only,
// DO NOT USE it in target solutions, for security reasons!!!
//
// const TEST_CONFIG_DATA: &[u8] = &[
//     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//     0xC0, 0x00, 0x00, 0x01, 0x8F, 0x20, 0xC6, 0xE6, 0x86, 0x66, 0x85, 0x66, 0xC6, 0x66, 0xC6, 0x46,
//     0x8F, 0x0F, 0x9F, 0x8F, 0x00, 0x0F, 0xC6, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0B, 0x1F,
//     0xC6, 0x76, 0xC6, 0xF6, 0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
//     0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x03, 0xB7, 0x00, 0x69, 0x76, 0x00, 0x00, 0x00, 0x00, 0x00,
//     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 0xFF, 0xFF, 0x0E, 0x60, 0x00, 0x00, 0x00, 0x00,
//     0x33, 0x00, 0x1C, 0x00, 0x73, 0x00, 0x13, 0x00, 0x18, 0x00, 0x38, 0x00, 0x7C, 0x00, 0x1C, 0x00,
//     0x3C, 0x00, 0x1A, 0x00, 0x3C, 0x00, 0x30, 0x00, 0x3C, 0x00, 0x12, 0x00, 0x18, 0x00, 0x1A, 0x00,
// ];
// --------------------------------------------------------------------------------------------------
//
// In addition, for all tests to run correctly, to slot 6 you must upload encryption key,
// the content of which is in constant 'WRITE_KEY' in file 'hw_backend_common.rs'
//
// --------------------------------------------------------------------------------------------------

use super::{AtcaStatus, AteccDevice};

use super::ATCA_ATECC_SLOTS_COUNT;

impl AteccDevice {
    /// Execute this command prevents future modifications of the Configuration zone.
    /// This command fails if the designated area is already locked.
    pub(crate) fn lock_config_zone(&self) -> AtcaStatus {
        AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_lock_config_zone()
        })
    } // AteccDevice::lock_config_zone()

    /// Execute this command prevents future modifications of the Data and OTP zones.
    /// This command fails if the designated area is already locked.
    pub(crate) fn lock_data_zone(&self) -> AtcaStatus {
        if !self.config_zone_locked {
            return AtcaStatus::AtcaNotLocked;
        }

        AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_lock_data_zone()
        })
    } // AteccDevice::lock_data_zone()

    /// Lock an individual slot in the data zone on an ATECC device. Not available for ATSHA devices.
    /// Slot must be configured to be slot lockable slots[slot_idx].config.lockable = true.
    /// This command fails if the designated area is already locked.
    pub(crate) fn lock_slot(&self, slot_id: u8) -> AtcaStatus {
        if !(self.config_zone_locked && self.data_zone_locked) {
            return AtcaStatus::AtcaNotLocked;
        }
        if slot_id >= ATCA_ATECC_SLOTS_COUNT {
            return AtcaStatus::AtcaInvalidId;
        }
        if !self.slots[slot_id as usize].config.lockable {
            return AtcaStatus::AtcaBadParam;
        }

        AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_lock_data_slot(slot_id as u16)
        })
    } // AteccDevice::lock_slot()

    /// Function for uploading configuration to the chip.
    /// First 16 bytes of data are skipped as they are not writable. LockValue and LockConfig
    /// are also skipped and can only be changed via the Lock command.
    /// This command may fail if UserExtra and/or Selector bytes have already been set to non-zero values.
    pub(crate) fn load_config_into_chip(&self, config: &[u8]) -> AtcaStatus {
        if self.config_zone_locked {
            return AtcaStatus::AtcaConfigZoneLocked;
        }
        if config.len() != self.get_config_buffer_size() {
            return AtcaStatus::AtcaInvalidSize;
        }

        AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_write_config_zone(config.as_ptr())
        })
    } // AteccDevice::load_config_into_chip()
}
