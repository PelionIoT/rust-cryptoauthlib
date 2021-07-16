#![allow(unused_imports)]
use serial_test::serial;

// Types
use super::{
    AeadAlgorithm, AeadParam, AtcaDeviceType, AtcaIface, AtcaIfaceCfg, AtcaIfaceI2c, AtcaSlot,
    AtcaStatus, AteccDevice, InfoCmdType, KeyType, NonceTarget, SignEcdsaParam, SignMode,
    VerifyEcdsaParam, VerifyMode,
};
// Constants
use super::{
    ATCA_AES_DATA_SIZE, ATCA_AES_GCM_IV_STD_LENGTH, ATCA_AES_KEY_SIZE,
    ATCA_ATECC_CONFIG_BUFFER_SIZE, ATCA_ATECC_PUB_KEY_SIZE, ATCA_ATECC_SLOTS_COUNT,
    ATCA_NONCE_NUMIN_SIZE, ATCA_RANDOM_BUFFER_SIZE, ATCA_SIG_SIZE, ATCA_ZONE_CONFIG,
};
// Functions
use super::setup_atecc_device;
// Modules
use super::hw_impl;

#[cfg(not(feature = "software-backend"))]
mod hw_backend;
#[cfg(not(feature = "software-backend"))]
mod hw_backend_aes_ccm;
#[cfg(not(feature = "software-backend"))]
mod hw_backend_aes_gcm;
#[cfg(not(feature = "software-backend"))]
mod hw_backend_common;

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

        assert_eq!(rand_out.len(), ATCA_RANDOM_BUFFER_SIZE);
        assert_eq!(device.release().to_string(), "AtcaSuccess");
        assert_eq!(device_random.to_string(), "AtcaSuccess");
    }
    #[cfg(feature = "software-backend")]
    {
        let device = sw_backend::test_setup("unimplemented-fail".to_owned());
        let mut rand_out = Vec::new();
        let device_random = device.random(&mut rand_out);

        assert_eq!(rand_out.len(), ATCA_RANDOM_BUFFER_SIZE);
        assert_eq!(device.release().to_string(), "AtcaSuccess");
        assert_eq!(device_random.to_string(), "AtcaSuccess");
    }
    #[cfg(feature = "software-backend")]
    {
        let device = sw_backend::test_setup("always-fail".to_owned());
        let mut rand_out = Vec::new();
        let device_random = device.random(&mut rand_out);

        assert_eq!(rand_out.len(), ATCA_RANDOM_BUFFER_SIZE);
        assert_ne!(device.release().to_string(), "AtcaSuccess");
        assert_ne!(device_random.to_string(), "AtcaSuccess");
    }
    #[cfg(not(feature = "software-backend"))]
    {
        let device = hw_backend_common::test_setup();

        let mut rand_out = Vec::new();
        let device_random = device.random(&mut rand_out);

        let mut expected = AtcaStatus::AtcaSuccess;
        if !device.is_configuration_locked() {
            println!("\u{001b}[1m\u{001b}[33mConfiguration not Locked!\u{001b}[0m");
            expected = AtcaStatus::AtcaNotLocked;
        } else {
            assert_eq!(rand_out.len(), ATCA_RANDOM_BUFFER_SIZE);
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
    let device = hw_backend_common::test_setup();

    let mut config_data = Vec::new();
    let device_read_config_zone = device.read_config_zone(&mut config_data);
    let device_get_device_type = device.get_device_type();

    assert_eq!(device.release().to_string(), "AtcaSuccess");
    match device_get_device_type {
        #[cfg(not(feature = "software-backend"))]
        AtcaDeviceType::ATECC508A | AtcaDeviceType::ATECC608A | AtcaDeviceType::ATECC108A => {
            assert_eq!(device_read_config_zone.to_string(), "AtcaSuccess");
            assert_eq!(config_data.len(), ATCA_ATECC_CONFIG_BUFFER_SIZE);
            assert_eq!(config_data[0], 0x01);
            assert_eq!(config_data[1], 0x23);
        }
        #[cfg(feature = "software-backend")]
        AtcaDeviceType::AtcaTestDevFail => {
            assert_ne!(device_read_config_zone.to_string(), "AtcaSuccess");
        }
        #[cfg(feature = "software-backend")]
        AtcaDeviceType::AtcaTestDevSuccess => {
            assert_eq!(device_read_config_zone.to_string(), "AtcaSuccess");
        }
        AtcaDeviceType::AtcaDevUnknown => {
            panic!("Unexpected device type: AtcaDevUnknown.");
        }
        _ => panic!("Missing device type."),
    };
}
