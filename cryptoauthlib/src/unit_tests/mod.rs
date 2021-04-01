use serial_test::serial;

// Types
#[allow(unused_imports)]
use super::{
    AtcaDeviceType, AtcaIface, AtcaIfaceCfg, AtcaIfaceI2c, AtcaSlot, AtcaStatus, AteccDevice,
    InfoCmdType, KeyType, NonceTarget, SignEcdsaParam, SignMode, VerifyEcdsaParam, VerifyMode,
};
// Constants
#[allow(unused_imports)]
use super::{
    ATCA_ATECC_CONFIG_BUFFER_SIZE, ATCA_ATECC_PUB_KEY_SIZE, ATCA_ATECC_SLOTS_COUNT,
    ATCA_NONCE_NUMIN_SIZE, ATCA_RANDOM_BUFFER_SIZE, ATCA_SIG_SIZE, ATCA_ZONE_CONFIG,
};
// Functions
#[allow(unused_imports)]
use super::setup_atecc_device;
// Modules
#[allow(unused_imports)]
use super::hw_impl;

#[cfg(not(feature = "software-backend"))]
mod hw_backend;
#[cfg(feature = "software-backend")]
mod sw_backend;

// The placeholder for tests that can be easily switched between the backends.

#[test]
#[serial]
fn random() {
    #[cfg(feature = "software-backend")]
    {
        let device = sw_backend::test_setup("always-success".to_owned());
        let mut rand_out = Vec::new();
        let device_random = device.random(&mut rand_out);

        assert_eq!(rand_out.len(), super::ATCA_RANDOM_BUFFER_SIZE);
        assert_eq!(device.release().to_string(), "AtcaSuccess");
        assert_eq!(device_random.to_string(), "AtcaSuccess");
    }
    #[cfg(feature = "software-backend")]
    {
        let device = sw_backend::test_setup("unimplemented-fail".to_owned());
        let mut rand_out = Vec::new();
        let device_random = device.random(&mut rand_out);

        assert_eq!(rand_out.len(), super::ATCA_RANDOM_BUFFER_SIZE);
        assert_eq!(device.release().to_string(), "AtcaSuccess");
        assert_eq!(device_random.to_string(), "AtcaSuccess");
    }
    #[cfg(feature = "software-backend")]
    {
        let device = sw_backend::test_setup("always-fail".to_owned());
        let mut rand_out = Vec::new();
        let device_random = device.random(&mut rand_out);

        assert_eq!(rand_out.len(), super::ATCA_RANDOM_BUFFER_SIZE);
        assert_ne!(device.release().to_string(), "AtcaSuccess");
        assert_ne!(device_random.to_string(), "AtcaSuccess");
    }
    #[cfg(not(feature = "software-backend"))]
    {
        let device = hw_backend::test_setup();

        let mut rand_out = Vec::new();
        let device_random = device.random(&mut rand_out);

        let mut expected = super::AtcaStatus::AtcaSuccess;
        if !device.configuration_is_locked() {
            println!("\u{001b}[1m\u{001b}[33mConfiguration not Locked!\u{001b}[0m");
            expected = super::AtcaStatus::AtcaNotLocked;
        } else {
            assert_eq!(rand_out.len(), super::ATCA_RANDOM_BUFFER_SIZE);
        }
        assert_eq!(device.release().to_string(), "AtcaSuccess");
        assert_eq!(device_random, expected);
    }
}

#[test]
#[serial]
fn read_config_zone() {
    #[cfg(feature = "software-backend")]
    let device = sw_backend::test_setup("always-success".to_owned());
    #[cfg(not(feature = "software-backend"))]
    let device = hw_backend::test_setup();

    let mut config_data = Vec::new();
    let device_read_config_zone = device.read_config_zone(&mut config_data);
    let device_get_device_type = device.get_device_type();

    assert_eq!(device.release().to_string(), "AtcaSuccess");
    match device_get_device_type {
        #[cfg(not(feature = "software-backend"))]
        super::AtcaDeviceType::ATECC508A
        | super::AtcaDeviceType::ATECC608A
        | super::AtcaDeviceType::ATECC108A => {
            assert_eq!(device_read_config_zone.to_string(), "AtcaSuccess");
            assert_eq!(config_data.len(), super::ATCA_ATECC_CONFIG_BUFFER_SIZE);
            assert_eq!(config_data[0], 0x01);
            assert_eq!(config_data[1], 0x23);
        }
        #[cfg(feature = "software-backend")]
        super::AtcaDeviceType::AtcaTestDevFail => {
            assert_ne!(device_read_config_zone.to_string(), "AtcaSuccess");
        }
        #[cfg(feature = "software-backend")]
        super::AtcaDeviceType::AtcaTestDevSuccess => {
            assert_eq!(device_read_config_zone.to_string(), "AtcaSuccess");
        }
        super::AtcaDeviceType::AtcaDevUnknown => {
            panic!("Unexpected device type: AtcaDevUnknown.");
        }
        _ => panic!("Missing device type."),
    };
}
