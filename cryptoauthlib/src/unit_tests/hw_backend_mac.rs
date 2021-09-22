// Types
use super::{AtcaDeviceType, AtcaStatus, KeyType, MacAlgorithm, MacParam};
// Constants
use super::{
    ATCA_AES_DATA_SIZE, ATCA_AES_KEY_SIZE, ATCA_ATECC_SLOTS_COUNT, ATCA_SHA2_256_DIGEST_SIZE,
};

use super::hw_backend_common::*;
use serial_test::serial;

#[test]
#[serial]
fn compute_mac_cmac_proper_data() {
    const DATA_20_SIZE: usize = 20;
    const DATA_16_SIZE: usize = 16;
    const DATA_0_SIZE: usize = 0;
    const SHORT_MAC_SIZE: usize = 12;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    // Test Vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
    let aes_key = [
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F,
        0x3C,
    ];

    let plain_text = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17,
        0x2A, 0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF,
        0x8E, 0x51, 0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A,
        0x0A, 0x52, 0xEF, 0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B,
        0xE6, 0x6C, 0x37, 0x10,
    ];

    let mac_64 = [
        0x51, 0xF0, 0xBE, 0xBF, 0x7E, 0x3B, 0x9D, 0x92, 0xFC, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3C,
        0xFE,
    ];

    let mac_20 = [
        0x7D, 0x85, 0x44, 0x9E, 0xA6, 0xEA, 0x19, 0xC8, 0x23, 0xA7, 0xBF, 0x78, 0x83, 0x7D, 0xFA,
        0xDE,
    ];

    let mac_16 = [
        0x07, 0x0A, 0x16, 0xB4, 0x6B, 0x4D, 0x41, 0x44, 0xF7, 0x9B, 0xDD, 0x9D, 0xD0, 0x4A, 0x28,
        0x7C,
    ];

    let mac_0 = [
        0xBB, 0x1D, 0x69, 0x29, 0xE9, 0x59, 0x37, 0x28, 0x7F, 0xA3, 0x7D, 0x12, 0x9B, 0x75, 0x67,
        0x46,
    ];

    let param_ok = MacParam {
        key: Some(aes_key.to_vec()),
        ..Default::default()
    };
    let param_ok_short_mac = MacParam {
        key: Some(aes_key.to_vec()),
        mac_length: Some(SHORT_MAC_SIZE as u8),
        ..Default::default()
    };
    let param_ok_internal_key = MacParam {
        ..Default::default()
    };

    let mut result_mac_64 = vec![0x00; ATCA_AES_KEY_SIZE];
    let mut result_mac_64_internal_key = vec![0x00; ATCA_AES_KEY_SIZE];
    let mut result_mac_20 = vec![0x00; ATCA_AES_KEY_SIZE];
    let mut result_mac_16 = vec![0x00; ATCA_AES_KEY_SIZE];
    let mut result_mac_16_short = vec![0x00; SHORT_MAC_SIZE];
    let mut result_mac_0 = vec![0x00; ATCA_AES_KEY_SIZE];

    let mut expected_64 = AtcaStatus::AtcaBadParam;
    let mut expected_64_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_20 = AtcaStatus::AtcaBadParam;
    let mut expected_16 = AtcaStatus::AtcaBadParam;
    let mut expected_16_short = AtcaStatus::AtcaBadParam;
    let mut expected_0 = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;
    let mut result_64 = AtcaStatus::AtcaUnknown;
    let mut result_64_internal_key = AtcaStatus::AtcaUnknown;
    let mut result_20 = AtcaStatus::AtcaUnknown;
    let mut result_16 = AtcaStatus::AtcaUnknown;
    let mut result_16_short = AtcaStatus::AtcaUnknown;
    let mut result_0 = AtcaStatus::AtcaUnknown;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_64 = AtcaStatus::AtcaNotLocked;
        expected_64_internal_key = AtcaStatus::AtcaNotLocked;
        expected_20 = AtcaStatus::AtcaNotLocked;
        expected_16 = AtcaStatus::AtcaNotLocked;
        expected_16_short = AtcaStatus::AtcaNotLocked;
        expected_0 = AtcaStatus::AtcaNotLocked;

        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected_64 = AtcaStatus::AtcaSuccess;
        expected_64_internal_key = AtcaStatus::AtcaSuccess;
        expected_20 = AtcaStatus::AtcaSuccess;
        expected_16 = AtcaStatus::AtcaSuccess;
        expected_16_short = AtcaStatus::AtcaSuccess;
        expected_0 = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;

        result_64 = AtcaStatus::AtcaSuccess;
        result_64_internal_key = AtcaStatus::AtcaSuccess;
        result_20 = AtcaStatus::AtcaSuccess;
        result_16 = AtcaStatus::AtcaSuccess;
        result_16_short = AtcaStatus::AtcaSuccess;
        result_0 = AtcaStatus::AtcaSuccess;
    }

    match device.mac_compute(
        MacAlgorithm::Cmac(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &plain_text.to_vec(),
    ) {
        Ok(mac) => result_mac_64 = mac,
        Err(err) => result_64 = err,
    }

    match device.mac_compute(
        MacAlgorithm::Cmac(param_ok_internal_key),
        AES_KEY_SLOT_IDX,
        &plain_text.to_vec(),
    ) {
        Ok(mac) => result_mac_64_internal_key = mac,
        Err(err) => result_64_internal_key = err,
    }

    match device.mac_compute(
        MacAlgorithm::Cmac(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &plain_text[..DATA_20_SIZE].to_vec(),
    ) {
        Ok(mac) => result_mac_20 = mac,
        Err(err) => result_20 = err,
    }

    match device.mac_compute(
        MacAlgorithm::Cmac(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &plain_text[..DATA_16_SIZE].to_vec(),
    ) {
        Ok(mac) => result_mac_16 = mac,
        Err(err) => result_16 = err,
    }

    match device.mac_compute(
        MacAlgorithm::Cmac(param_ok_short_mac),
        ATCA_ATECC_SLOTS_COUNT,
        &plain_text[..DATA_16_SIZE].to_vec(),
    ) {
        Ok(mac) => result_mac_16_short = mac,
        Err(err) => result_16_short = err,
    }

    match device.mac_compute(
        MacAlgorithm::Cmac(param_ok),
        ATCA_ATECC_SLOTS_COUNT,
        &plain_text[..DATA_0_SIZE].to_vec(),
    ) {
        Ok(mac) => result_mac_0 = mac,
        Err(err) => result_0 = err,
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert_eq!(result_mac_64, mac_64.to_vec());
        assert_eq!(result_mac_64_internal_key, mac_64.to_vec());
        assert_eq!(result_mac_20, mac_20.to_vec());
        assert_eq!(result_mac_16, mac_16.to_vec());
        assert_eq!(result_mac_16_short, mac_16[..SHORT_MAC_SIZE].to_vec());
        assert_eq!(result_mac_0, mac_0.to_vec());
    }
    assert_eq!(result_64, expected_64);
    assert_eq!(result_64_internal_key, expected_64_internal_key);
    assert_eq!(result_20, expected_20);
    assert_eq!(result_16, expected_16);
    assert_eq!(result_16_short, expected_16_short);
    assert_eq!(result_0, expected_0);
}

#[test]
#[serial]
fn compute_mac_cmac_bad_data() {
    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let data: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE];
    let param_ok = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };

    let param_bad_1 = MacParam {
        ..Default::default()
    };

    let param_bad_2 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        mac_length: Some(ATCA_AES_DATA_SIZE as u8),
        mac: Some(data.clone()),
    };

    let param_bad_3 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        mac_length: Some(0x00),
        ..Default::default()
    };

    let param_bad_4 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        mac_length: Some((ATCA_AES_DATA_SIZE + 1) as u8),
        ..Default::default()
    };

    let param_bad_5 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        mac: Some(vec![0x00; 0]),
        ..Default::default()
    };

    let param_bad_6 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        mac: Some(vec![0x00; ATCA_AES_DATA_SIZE + 1]),
        ..Default::default()
    };

    let param_bad_7 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE - 1]),
        ..Default::default()
    };

    let mut expected_bad_1 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_2 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_3 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_4 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_5 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_6 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_7 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_8 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_9 = AtcaStatus::AtcaBadParam;
    let mut result_bad_1 = AtcaStatus::AtcaUnknown;
    let mut result_bad_2 = AtcaStatus::AtcaUnknown;
    let mut result_bad_3 = AtcaStatus::AtcaUnknown;
    let mut result_bad_4 = AtcaStatus::AtcaUnknown;
    let mut result_bad_5 = AtcaStatus::AtcaUnknown;
    let mut result_bad_6 = AtcaStatus::AtcaUnknown;
    let mut result_bad_7 = AtcaStatus::AtcaUnknown;
    let mut result_bad_8 = AtcaStatus::AtcaUnknown;
    let mut result_bad_9 = AtcaStatus::AtcaUnknown;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_bad_1 = AtcaStatus::AtcaNotLocked;
        expected_bad_2 = AtcaStatus::AtcaNotLocked;
        expected_bad_3 = AtcaStatus::AtcaNotLocked;
        expected_bad_4 = AtcaStatus::AtcaNotLocked;
        expected_bad_5 = AtcaStatus::AtcaNotLocked;
        expected_bad_6 = AtcaStatus::AtcaNotLocked;
        expected_bad_7 = AtcaStatus::AtcaNotLocked;
        expected_bad_8 = AtcaStatus::AtcaNotLocked;
        expected_bad_9 = AtcaStatus::AtcaNotLocked;
    }

    if chip_is_locked && device.is_aes_enabled() {
        expected_bad_1 = AtcaStatus::AtcaInvalidId;
        expected_bad_2 = AtcaStatus::AtcaInvalidId;
        expected_bad_3 = AtcaStatus::AtcaBadParam;
        expected_bad_4 = AtcaStatus::AtcaBadParam;
        expected_bad_5 = AtcaStatus::AtcaInvalidSize;
        expected_bad_6 = AtcaStatus::AtcaInvalidSize;
        expected_bad_7 = AtcaStatus::AtcaInvalidSize;
        expected_bad_8 = AtcaStatus::AtcaInvalidSize;
        expected_bad_9 = AtcaStatus::AtcaInvalidSize;
    }

    // slot_id is too big
    match device.mac_compute(
        MacAlgorithm::Cmac(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_1 = err,
    }

    // slot holds a key other than AES
    match device.mac_compute(MacAlgorithm::Cmac(param_ok), 0x00, &data) {
        Ok(_) => (),
        Err(err) => result_bad_2 = err,
    }

    // slot_id points to TEMP_KEY but no key data
    match device.mac_compute(
        MacAlgorithm::Cmac(param_bad_1),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_3 = err,
    }

    // both 'mac_length' and 'mac' parameters were passed - properly there should be only one of them
    match device.mac_compute(
        MacAlgorithm::Cmac(param_bad_2),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_4 = err,
    }

    // 'mac_length' value too low
    match device.mac_compute(
        MacAlgorithm::Cmac(param_bad_3),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_5 = err,
    }

    // 'mac_length' value too high
    match device.mac_compute(
        MacAlgorithm::Cmac(param_bad_4),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_6 = err,
    }

    // 'mac' length too short
    match device.mac_compute(
        MacAlgorithm::Cmac(param_bad_5),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_7 = err,
    }

    // 'mac' length too long
    match device.mac_compute(
        MacAlgorithm::Cmac(param_bad_6),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_8 = err,
    }

    // key length not equal to 'ATCA_AES_KEY_SIZE'
    match device.mac_compute(
        MacAlgorithm::Cmac(param_bad_7),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_9 = err,
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_bad_1, expected_bad_1);
    assert_eq!(result_bad_2, expected_bad_2);
    assert_eq!(result_bad_3, expected_bad_3);
    assert_eq!(result_bad_4, expected_bad_4);
    assert_eq!(result_bad_5, expected_bad_5);
    assert_eq!(result_bad_6, expected_bad_6);
    assert_eq!(result_bad_7, expected_bad_7);
    assert_eq!(result_bad_8, expected_bad_8);
    assert_eq!(result_bad_9, expected_bad_9);
}

#[test]
#[serial]
fn verify_mac_cmac_proper_data() {
    const DATA_20_SIZE: usize = 20;
    const DATA_16_SIZE: usize = 16;
    const DATA_0_SIZE: usize = 0;
    const SHORT_MAC_SIZE: usize = 12;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    // Test Vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
    let aes_key = [
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F,
        0x3C,
    ];

    let plain_text = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17,
        0x2A, 0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF,
        0x8E, 0x51, 0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A,
        0x0A, 0x52, 0xEF, 0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B,
        0xE6, 0x6C, 0x37, 0x10,
    ];

    let mac_64 = [
        0x51, 0xF0, 0xBE, 0xBF, 0x7E, 0x3B, 0x9D, 0x92, 0xFC, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3C,
        0xFE,
    ];

    let mac_20 = [
        0x7D, 0x85, 0x44, 0x9E, 0xA6, 0xEA, 0x19, 0xC8, 0x23, 0xA7, 0xBF, 0x78, 0x83, 0x7D, 0xFA,
        0xDE,
    ];

    let mac_16 = [
        0x07, 0x0A, 0x16, 0xB4, 0x6B, 0x4D, 0x41, 0x44, 0xF7, 0x9B, 0xDD, 0x9D, 0xD0, 0x4A, 0x28,
        0x7C,
    ];

    let mac_0 = [
        0xBB, 0x1D, 0x69, 0x29, 0xE9, 0x59, 0x37, 0x28, 0x7F, 0xA3, 0x7D, 0x12, 0x9B, 0x75, 0x67,
        0x46,
    ];

    let param_ok_64 = MacParam {
        key: Some(aes_key.to_vec()),
        mac: Some(mac_64.to_vec()),
        ..Default::default()
    };
    let param_ok_20 = MacParam {
        key: Some(aes_key.to_vec()),
        mac: Some(mac_20.to_vec()),
        ..Default::default()
    };
    let param_ok_16 = MacParam {
        key: Some(aes_key.to_vec()),
        mac: Some(mac_16.to_vec()),
        ..Default::default()
    };
    let param_ok_16_short_mac = MacParam {
        key: Some(aes_key.to_vec()),
        mac: Some(mac_16[..SHORT_MAC_SIZE].to_vec()),
        ..Default::default()
    };
    let param_ok_0 = MacParam {
        key: Some(aes_key.to_vec()),
        mac: Some(mac_0.to_vec()),
        ..Default::default()
    };
    let param_ok_64_internal_key = MacParam {
        mac: Some(mac_64.to_vec()),
        ..Default::default()
    };

    let mut result_mac_64: bool = false;
    let mut result_mac_64_internal_key: bool = false;
    let mut result_mac_20: bool = false;
    let mut result_mac_16: bool = false;
    let mut result_mac_16_short: bool = false;
    let mut result_mac_0: bool = false;

    let mut expected_64 = AtcaStatus::AtcaBadParam;
    let mut expected_64_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_20 = AtcaStatus::AtcaBadParam;
    let mut expected_16 = AtcaStatus::AtcaBadParam;
    let mut expected_16_short = AtcaStatus::AtcaBadParam;
    let mut expected_0 = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;
    let mut result_64 = AtcaStatus::AtcaUnknown;
    let mut result_64_internal_key = AtcaStatus::AtcaUnknown;
    let mut result_20 = AtcaStatus::AtcaUnknown;
    let mut result_16 = AtcaStatus::AtcaUnknown;
    let mut result_16_short = AtcaStatus::AtcaUnknown;
    let mut result_0 = AtcaStatus::AtcaUnknown;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_64 = AtcaStatus::AtcaNotLocked;
        expected_64_internal_key = AtcaStatus::AtcaNotLocked;
        expected_20 = AtcaStatus::AtcaNotLocked;
        expected_16 = AtcaStatus::AtcaNotLocked;
        expected_16_short = AtcaStatus::AtcaNotLocked;
        expected_0 = AtcaStatus::AtcaNotLocked;

        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected_64 = AtcaStatus::AtcaSuccess;
        expected_64_internal_key = AtcaStatus::AtcaSuccess;
        expected_20 = AtcaStatus::AtcaSuccess;
        expected_16 = AtcaStatus::AtcaSuccess;
        expected_16_short = AtcaStatus::AtcaSuccess;
        expected_0 = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;

        result_64 = AtcaStatus::AtcaSuccess;
        result_64_internal_key = AtcaStatus::AtcaSuccess;
        result_20 = AtcaStatus::AtcaSuccess;
        result_16 = AtcaStatus::AtcaSuccess;
        result_16_short = AtcaStatus::AtcaSuccess;
        result_0 = AtcaStatus::AtcaSuccess;
    }

    match device.mac_verify(
        MacAlgorithm::Cmac(param_ok_64),
        ATCA_ATECC_SLOTS_COUNT,
        &plain_text.to_vec(),
    ) {
        Ok(is_mac_ok) => result_mac_64 = is_mac_ok,
        Err(err) => result_64 = err,
    }

    match device.mac_verify(
        MacAlgorithm::Cmac(param_ok_64_internal_key),
        AES_KEY_SLOT_IDX,
        &plain_text.to_vec(),
    ) {
        Ok(is_mac_ok) => result_mac_64_internal_key = is_mac_ok,
        Err(err) => result_64_internal_key = err,
    }

    match device.mac_verify(
        MacAlgorithm::Cmac(param_ok_20),
        ATCA_ATECC_SLOTS_COUNT,
        &plain_text[..DATA_20_SIZE].to_vec(),
    ) {
        Ok(is_mac_ok) => result_mac_20 = is_mac_ok,
        Err(err) => result_20 = err,
    }

    match device.mac_verify(
        MacAlgorithm::Cmac(param_ok_16),
        ATCA_ATECC_SLOTS_COUNT,
        &plain_text[..DATA_16_SIZE].to_vec(),
    ) {
        Ok(is_mac_ok) => result_mac_16 = is_mac_ok,
        Err(err) => result_16 = err,
    }

    match device.mac_verify(
        MacAlgorithm::Cmac(param_ok_16_short_mac),
        ATCA_ATECC_SLOTS_COUNT,
        &plain_text[..DATA_16_SIZE].to_vec(),
    ) {
        Ok(is_mac_ok) => result_mac_16_short = is_mac_ok,
        Err(err) => result_16_short = err,
    }

    match device.mac_verify(
        MacAlgorithm::Cmac(param_ok_0),
        ATCA_ATECC_SLOTS_COUNT,
        &plain_text[..DATA_0_SIZE].to_vec(),
    ) {
        Ok(is_mac_ok) => result_mac_0 = is_mac_ok,
        Err(err) => result_0 = err,
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert!(result_mac_64);
        assert!(result_mac_64_internal_key);
        assert!(result_mac_20);
        assert!(result_mac_16);
        assert!(result_mac_16_short);
        assert!(result_mac_0);
    }
    assert_eq!(result_64, expected_64);
    assert_eq!(result_64_internal_key, expected_64_internal_key);
    assert_eq!(result_20, expected_20);
    assert_eq!(result_16, expected_16);
    assert_eq!(result_16_short, expected_16_short);
    assert_eq!(result_0, expected_0);
}

#[test]
#[serial]
fn verify_mac_cmac_bad_data() {
    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let data: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE];
    let param_ok = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        mac: Some(data.clone()),
        ..Default::default()
    };

    let param_bad_1 = MacParam {
        mac: Some(data.clone()),
        ..Default::default()
    };

    let param_bad_2 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        mac_length: Some(ATCA_AES_DATA_SIZE as u8),
        mac: Some(data.clone()),
    };

    let param_bad_3 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };

    let param_bad_4 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        mac: Some(vec![0x00; 0]),
        ..Default::default()
    };

    let param_bad_5 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        mac: Some(vec![0x00; ATCA_AES_DATA_SIZE + 1]),
        ..Default::default()
    };

    let param_bad_6 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE - 1]),
        mac: Some(data.clone()),
        ..Default::default()
    };

    let mut expected_bad_1 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_2 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_3 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_4 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_5 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_6 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_7 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_8 = AtcaStatus::AtcaBadParam;
    let mut result_bad_1 = AtcaStatus::AtcaUnknown;
    let mut result_bad_2 = AtcaStatus::AtcaUnknown;
    let mut result_bad_3 = AtcaStatus::AtcaUnknown;
    let mut result_bad_4 = AtcaStatus::AtcaUnknown;
    let mut result_bad_5 = AtcaStatus::AtcaUnknown;
    let mut result_bad_6 = AtcaStatus::AtcaUnknown;
    let mut result_bad_7 = AtcaStatus::AtcaUnknown;
    let mut result_bad_8 = AtcaStatus::AtcaUnknown;
    let mut result_mac: bool = true;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_bad_1 = AtcaStatus::AtcaNotLocked;
        expected_bad_2 = AtcaStatus::AtcaNotLocked;
        expected_bad_3 = AtcaStatus::AtcaNotLocked;
        expected_bad_4 = AtcaStatus::AtcaNotLocked;
        expected_bad_5 = AtcaStatus::AtcaNotLocked;
        expected_bad_6 = AtcaStatus::AtcaNotLocked;
        expected_bad_7 = AtcaStatus::AtcaNotLocked;
        expected_bad_8 = AtcaStatus::AtcaNotLocked;
    }

    if chip_is_locked && device.is_aes_enabled() {
        expected_bad_1 = AtcaStatus::AtcaInvalidId;
        expected_bad_2 = AtcaStatus::AtcaInvalidId;
        expected_bad_3 = AtcaStatus::AtcaBadParam;
        expected_bad_4 = AtcaStatus::AtcaBadParam;
        expected_bad_5 = AtcaStatus::AtcaBadParam;
        expected_bad_6 = AtcaStatus::AtcaInvalidSize;
        expected_bad_7 = AtcaStatus::AtcaInvalidSize;
        expected_bad_8 = AtcaStatus::AtcaInvalidSize;
    }

    // slot_id is too big
    match device.mac_verify(
        MacAlgorithm::Cmac(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_1 = err,
    }

    // slot holds a key other than AES
    match device.mac_verify(MacAlgorithm::Cmac(param_ok.clone()), 0x00, &data) {
        Ok(_) => (),
        Err(err) => result_bad_2 = err,
    }

    // slot_id points to TEMP_KEY but no key data
    match device.mac_verify(
        MacAlgorithm::Cmac(param_bad_1),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_3 = err,
    }

    // both 'mac_length' and 'mac' parameters were passed - properly there should be only one of them
    match device.mac_verify(
        MacAlgorithm::Cmac(param_bad_2),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_4 = err,
    }

    // no 'mac' data to check
    match device.mac_verify(
        MacAlgorithm::Cmac(param_bad_3),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_5 = err,
    }

    // 'mac' length too short
    match device.mac_verify(
        MacAlgorithm::Cmac(param_bad_4),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_6 = err,
    }

    // 'mac' length too long
    match device.mac_verify(
        MacAlgorithm::Cmac(param_bad_5),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_7 = err,
    }

    // key length not equal to 'ATCA_AES_KEY_SIZE'
    match device.mac_verify(
        MacAlgorithm::Cmac(param_bad_6),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_8 = err,
    }

    // value of 'mac' does not match
    if let Ok(is_mac_ok) =
        device.mac_verify(MacAlgorithm::Cmac(param_ok), ATCA_ATECC_SLOTS_COUNT, &data)
    {
        result_mac = is_mac_ok
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    if chip_is_locked && device.is_aes_enabled() {
        assert!(!result_mac);
    }
    assert_eq!(result_bad_1, expected_bad_1);
    assert_eq!(result_bad_2, expected_bad_2);
    assert_eq!(result_bad_3, expected_bad_3);
    assert_eq!(result_bad_4, expected_bad_4);
    assert_eq!(result_bad_5, expected_bad_5);
    assert_eq!(result_bad_6, expected_bad_6);
    assert_eq!(result_bad_7, expected_bad_7);
    assert_eq!(result_bad_8, expected_bad_8);
}

#[test]
#[serial]
fn compute_mac_cbcmac_proper_data() {
    const DATA_16_SIZE: usize = 16;
    const SHORT_MAC_SIZE: usize = 12;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let aes_key = [
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F,
        0x3C,
    ];

    let plain_text = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17,
        0x2A, 0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF,
        0x8E, 0x51, 0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A,
        0x0A, 0x52, 0xEF, 0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B,
        0xE6, 0x6C, 0x37, 0x10,
    ];

    let mac_64 = [
        0xA7, 0x35, 0x6E, 0x12, 0x07, 0xBB, 0x40, 0x66, 0x39, 0xE5, 0xE5, 0xCE, 0xB9, 0xA9, 0xED,
        0x93,
    ];

    let mac_16 = [
        0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF,
        0x97,
    ];

    let param_ok = MacParam {
        key: Some(aes_key.to_vec()),
        ..Default::default()
    };
    let param_ok_short_mac = MacParam {
        key: Some(aes_key.to_vec()),
        mac_length: Some(SHORT_MAC_SIZE as u8),
        ..Default::default()
    };
    let param_ok_internal_key = MacParam {
        ..Default::default()
    };

    let mut result_mac_64 = vec![0x00; ATCA_AES_KEY_SIZE];
    let mut result_mac_64_internal_key = vec![0x00; ATCA_AES_KEY_SIZE];
    let mut result_mac_16_short = vec![0x00; SHORT_MAC_SIZE];

    let mut expected_64 = AtcaStatus::AtcaBadParam;
    let mut expected_64_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_16_short = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;
    let mut result_64 = AtcaStatus::AtcaUnknown;
    let mut result_64_internal_key = AtcaStatus::AtcaUnknown;
    let mut result_16_short = AtcaStatus::AtcaUnknown;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_64 = AtcaStatus::AtcaNotLocked;
        expected_64_internal_key = AtcaStatus::AtcaNotLocked;
        expected_16_short = AtcaStatus::AtcaNotLocked;

        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected_64 = AtcaStatus::AtcaSuccess;
        expected_64_internal_key = AtcaStatus::AtcaSuccess;
        expected_16_short = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;

        result_64 = AtcaStatus::AtcaSuccess;
        result_64_internal_key = AtcaStatus::AtcaSuccess;
        result_16_short = AtcaStatus::AtcaSuccess;
    }

    match device.mac_compute(
        MacAlgorithm::Cbcmac(param_ok),
        ATCA_ATECC_SLOTS_COUNT,
        &plain_text.to_vec(),
    ) {
        Ok(mac) => result_mac_64 = mac,
        Err(err) => result_64 = err,
    }

    match device.mac_compute(
        MacAlgorithm::Cbcmac(param_ok_internal_key),
        AES_KEY_SLOT_IDX,
        &plain_text.to_vec(),
    ) {
        Ok(mac) => result_mac_64_internal_key = mac,
        Err(err) => result_64_internal_key = err,
    }

    match device.mac_compute(
        MacAlgorithm::Cbcmac(param_ok_short_mac),
        ATCA_ATECC_SLOTS_COUNT,
        &plain_text[..DATA_16_SIZE].to_vec(),
    ) {
        Ok(mac) => result_mac_16_short = mac,
        Err(err) => result_16_short = err,
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert_eq!(result_mac_64, mac_64.to_vec());
        assert_eq!(result_mac_64_internal_key, mac_64.to_vec());
        assert_eq!(result_mac_16_short, mac_16[..SHORT_MAC_SIZE].to_vec());
    }
    assert_eq!(result_64, expected_64);
    assert_eq!(result_64_internal_key, expected_64_internal_key);
    assert_eq!(result_16_short, expected_16_short);
}

#[test]
#[serial]
fn compute_mac_cbcmac_bad_data() {
    const BAD_DATA_SIZE: usize = ATCA_AES_DATA_SIZE - 4;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let data: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE];
    let param_ok = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };

    let param_bad_1 = MacParam {
        ..Default::default()
    };

    let param_bad_2 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        mac_length: Some(ATCA_AES_DATA_SIZE as u8),
        mac: Some(data.clone()),
    };

    let param_bad_3 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        mac_length: Some(0x00),
        ..Default::default()
    };

    let param_bad_4 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        mac_length: Some((ATCA_AES_DATA_SIZE + 1) as u8),
        ..Default::default()
    };

    let param_bad_5 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        mac: Some(vec![0x00; 0]),
        ..Default::default()
    };

    let param_bad_6 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        mac: Some(vec![0x00; ATCA_AES_DATA_SIZE + 1]),
        ..Default::default()
    };

    let param_bad_7 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE - 1]),
        ..Default::default()
    };

    let mut expected_bad_1 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_2 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_3 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_4 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_5 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_6 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_7 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_8 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_9 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_10 = AtcaStatus::AtcaBadParam;
    let mut result_bad_1 = AtcaStatus::AtcaUnknown;
    let mut result_bad_2 = AtcaStatus::AtcaUnknown;
    let mut result_bad_3 = AtcaStatus::AtcaUnknown;
    let mut result_bad_4 = AtcaStatus::AtcaUnknown;
    let mut result_bad_5 = AtcaStatus::AtcaUnknown;
    let mut result_bad_6 = AtcaStatus::AtcaUnknown;
    let mut result_bad_7 = AtcaStatus::AtcaUnknown;
    let mut result_bad_8 = AtcaStatus::AtcaUnknown;
    let mut result_bad_9 = AtcaStatus::AtcaUnknown;
    let mut result_bad_10 = AtcaStatus::AtcaUnknown;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_bad_1 = AtcaStatus::AtcaNotLocked;
        expected_bad_2 = AtcaStatus::AtcaNotLocked;
        expected_bad_3 = AtcaStatus::AtcaNotLocked;
        expected_bad_4 = AtcaStatus::AtcaNotLocked;
        expected_bad_5 = AtcaStatus::AtcaNotLocked;
        expected_bad_6 = AtcaStatus::AtcaNotLocked;
        expected_bad_7 = AtcaStatus::AtcaNotLocked;
        expected_bad_8 = AtcaStatus::AtcaNotLocked;
        expected_bad_9 = AtcaStatus::AtcaNotLocked;
        expected_bad_10 = AtcaStatus::AtcaNotLocked;
    }

    if chip_is_locked && device.is_aes_enabled() {
        expected_bad_1 = AtcaStatus::AtcaInvalidId;
        expected_bad_2 = AtcaStatus::AtcaInvalidId;
        expected_bad_3 = AtcaStatus::AtcaBadParam;
        expected_bad_4 = AtcaStatus::AtcaBadParam;
        expected_bad_5 = AtcaStatus::AtcaInvalidSize;
        expected_bad_6 = AtcaStatus::AtcaInvalidSize;
        expected_bad_7 = AtcaStatus::AtcaInvalidSize;
        expected_bad_8 = AtcaStatus::AtcaInvalidSize;
        expected_bad_9 = AtcaStatus::AtcaInvalidSize;
        expected_bad_10 = AtcaStatus::AtcaInvalidSize;
    }

    // slot_id is too big
    match device.mac_compute(
        MacAlgorithm::Cbcmac(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_1 = err,
    }

    // slot holds a key other than AES
    match device.mac_compute(MacAlgorithm::Cbcmac(param_ok.clone()), 0x00, &data) {
        Ok(_) => (),
        Err(err) => result_bad_2 = err,
    }

    // slot_id points to TEMP_KEY but no key data
    match device.mac_compute(
        MacAlgorithm::Cbcmac(param_bad_1),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_3 = err,
    }

    // both 'mac_length' and 'mac' parameters were passed - properly there should be only one of them
    match device.mac_compute(
        MacAlgorithm::Cbcmac(param_bad_2),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_4 = err,
    }

    // 'mac_length' value too low
    match device.mac_compute(
        MacAlgorithm::Cbcmac(param_bad_3),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_5 = err,
    }

    // 'mac_length' value too high
    match device.mac_compute(
        MacAlgorithm::Cbcmac(param_bad_4),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_6 = err,
    }

    // 'mac' length too short
    match device.mac_compute(
        MacAlgorithm::Cbcmac(param_bad_5),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_7 = err,
    }

    // 'mac' length too long
    match device.mac_compute(
        MacAlgorithm::Cbcmac(param_bad_6),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_8 = err,
    }

    // key length not equal to 'ATCA_AES_KEY_SIZE'
    match device.mac_compute(
        MacAlgorithm::Cbcmac(param_bad_7),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_9 = err,
    }

    // data size indivisible by block size
    match device.mac_compute(
        MacAlgorithm::Cbcmac(param_ok),
        ATCA_ATECC_SLOTS_COUNT,
        &data[..BAD_DATA_SIZE],
    ) {
        Ok(_) => (),
        Err(err) => result_bad_10 = err,
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_bad_1, expected_bad_1);
    assert_eq!(result_bad_2, expected_bad_2);
    assert_eq!(result_bad_3, expected_bad_3);
    assert_eq!(result_bad_4, expected_bad_4);
    assert_eq!(result_bad_5, expected_bad_5);
    assert_eq!(result_bad_6, expected_bad_6);
    assert_eq!(result_bad_7, expected_bad_7);
    assert_eq!(result_bad_8, expected_bad_8);
    assert_eq!(result_bad_9, expected_bad_9);
    assert_eq!(result_bad_10, expected_bad_10);
}

#[test]
#[serial]
fn verify_mac_cbcmac_proper_data() {
    const DATA_16_SIZE: usize = 16;
    const SHORT_MAC_SIZE: usize = 12;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let aes_key = [
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F,
        0x3C,
    ];

    let plain_text = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17,
        0x2A, 0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF,
        0x8E, 0x51, 0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A,
        0x0A, 0x52, 0xEF, 0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B,
        0xE6, 0x6C, 0x37, 0x10,
    ];

    let mac_64 = [
        0xA7, 0x35, 0x6E, 0x12, 0x07, 0xBB, 0x40, 0x66, 0x39, 0xE5, 0xE5, 0xCE, 0xB9, 0xA9, 0xED,
        0x93,
    ];

    let mac_16 = [
        0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF,
        0x97,
    ];

    let param_ok_64 = MacParam {
        key: Some(aes_key.to_vec()),
        mac: Some(mac_64.to_vec()),
        ..Default::default()
    };
    let param_ok_16_short_mac = MacParam {
        key: Some(aes_key.to_vec()),
        mac: Some(mac_16[..SHORT_MAC_SIZE].to_vec()),
        ..Default::default()
    };
    let param_ok_64_internal_key = MacParam {
        mac: Some(mac_64.to_vec()),
        ..Default::default()
    };

    let mut result_mac_64: bool = false;
    let mut result_mac_64_internal_key: bool = false;
    let mut result_mac_16_short: bool = false;

    let mut expected_64 = AtcaStatus::AtcaBadParam;
    let mut expected_64_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_16_short = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;
    let mut result_64 = AtcaStatus::AtcaUnknown;
    let mut result_64_internal_key = AtcaStatus::AtcaUnknown;
    let mut result_16_short = AtcaStatus::AtcaUnknown;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_64 = AtcaStatus::AtcaNotLocked;
        expected_64_internal_key = AtcaStatus::AtcaNotLocked;
        expected_16_short = AtcaStatus::AtcaNotLocked;

        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected_64 = AtcaStatus::AtcaSuccess;
        expected_64_internal_key = AtcaStatus::AtcaSuccess;
        expected_16_short = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;

        result_64 = AtcaStatus::AtcaSuccess;
        result_64_internal_key = AtcaStatus::AtcaSuccess;
        result_16_short = AtcaStatus::AtcaSuccess;
    }

    match device.mac_verify(
        MacAlgorithm::Cbcmac(param_ok_64),
        ATCA_ATECC_SLOTS_COUNT,
        &plain_text.to_vec(),
    ) {
        Ok(is_mac_ok) => result_mac_64 = is_mac_ok,
        Err(err) => result_64 = err,
    }

    match device.mac_verify(
        MacAlgorithm::Cbcmac(param_ok_64_internal_key),
        AES_KEY_SLOT_IDX,
        &plain_text.to_vec(),
    ) {
        Ok(is_mac_ok) => result_mac_64_internal_key = is_mac_ok,
        Err(err) => result_64_internal_key = err,
    }

    match device.mac_verify(
        MacAlgorithm::Cbcmac(param_ok_16_short_mac),
        ATCA_ATECC_SLOTS_COUNT,
        &plain_text[..DATA_16_SIZE].to_vec(),
    ) {
        Ok(is_mac_ok) => result_mac_16_short = is_mac_ok,
        Err(err) => result_16_short = err,
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert!(result_mac_64);
        assert!(result_mac_64_internal_key);
        assert!(result_mac_16_short);
    }
    assert_eq!(result_64, expected_64);
    assert_eq!(result_64_internal_key, expected_64_internal_key);
    assert_eq!(result_16_short, expected_16_short);
}

#[test]
#[serial]
fn verify_mac_cbcmac_bad_data() {
    const BAD_DATA_SIZE: usize = ATCA_AES_DATA_SIZE - 4;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let data: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE];
    let param_ok = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        mac: Some(data.clone()),
        ..Default::default()
    };

    let param_bad_1 = MacParam {
        mac: Some(data.clone()),
        ..Default::default()
    };

    let param_bad_2 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        mac_length: Some(ATCA_AES_DATA_SIZE as u8),
        mac: Some(data.clone()),
    };

    let param_bad_3 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };

    let param_bad_4 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        mac: Some(vec![0x00; 0]),
        ..Default::default()
    };

    let param_bad_5 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        mac: Some(vec![0x00; ATCA_AES_DATA_SIZE + 1]),
        ..Default::default()
    };

    let param_bad_6 = MacParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE - 1]),
        mac: Some(data.clone()),
        ..Default::default()
    };

    let mut expected_bad_1 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_2 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_3 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_4 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_5 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_6 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_7 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_8 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_9 = AtcaStatus::AtcaBadParam;
    let mut result_bad_1 = AtcaStatus::AtcaUnknown;
    let mut result_bad_2 = AtcaStatus::AtcaUnknown;
    let mut result_bad_3 = AtcaStatus::AtcaUnknown;
    let mut result_bad_4 = AtcaStatus::AtcaUnknown;
    let mut result_bad_5 = AtcaStatus::AtcaUnknown;
    let mut result_bad_6 = AtcaStatus::AtcaUnknown;
    let mut result_bad_7 = AtcaStatus::AtcaUnknown;
    let mut result_bad_8 = AtcaStatus::AtcaUnknown;
    let mut result_bad_9 = AtcaStatus::AtcaUnknown;
    let mut result_mac: bool = true;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_bad_1 = AtcaStatus::AtcaNotLocked;
        expected_bad_2 = AtcaStatus::AtcaNotLocked;
        expected_bad_3 = AtcaStatus::AtcaNotLocked;
        expected_bad_4 = AtcaStatus::AtcaNotLocked;
        expected_bad_5 = AtcaStatus::AtcaNotLocked;
        expected_bad_6 = AtcaStatus::AtcaNotLocked;
        expected_bad_7 = AtcaStatus::AtcaNotLocked;
        expected_bad_8 = AtcaStatus::AtcaNotLocked;
        expected_bad_9 = AtcaStatus::AtcaNotLocked;
    }

    if chip_is_locked && device.is_aes_enabled() {
        expected_bad_1 = AtcaStatus::AtcaInvalidId;
        expected_bad_2 = AtcaStatus::AtcaInvalidId;
        expected_bad_3 = AtcaStatus::AtcaBadParam;
        expected_bad_4 = AtcaStatus::AtcaBadParam;
        expected_bad_5 = AtcaStatus::AtcaBadParam;
        expected_bad_6 = AtcaStatus::AtcaInvalidSize;
        expected_bad_7 = AtcaStatus::AtcaInvalidSize;
        expected_bad_8 = AtcaStatus::AtcaInvalidSize;
        expected_bad_9 = AtcaStatus::AtcaInvalidSize;
    }

    // slot_id is too big
    match device.mac_verify(
        MacAlgorithm::Cbcmac(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_1 = err,
    }

    // slot holds a key other than AES
    match device.mac_verify(MacAlgorithm::Cbcmac(param_ok.clone()), 0x00, &data) {
        Ok(_) => (),
        Err(err) => result_bad_2 = err,
    }

    // slot_id points to TEMP_KEY but no key data
    match device.mac_verify(
        MacAlgorithm::Cbcmac(param_bad_1),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_3 = err,
    }

    // both 'mac_length' and 'mac' parameters were passed - properly there should be only one of them
    match device.mac_verify(
        MacAlgorithm::Cbcmac(param_bad_2),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_4 = err,
    }

    // no 'mac' data to check
    match device.mac_verify(
        MacAlgorithm::Cbcmac(param_bad_3),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_5 = err,
    }

    // 'mac' length too short
    match device.mac_verify(
        MacAlgorithm::Cbcmac(param_bad_4),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_6 = err,
    }

    // 'mac' length too long
    match device.mac_verify(
        MacAlgorithm::Cbcmac(param_bad_5),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_7 = err,
    }

    // data size indivisible by block size
    match device.mac_verify(
        MacAlgorithm::Cbcmac(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &data[..BAD_DATA_SIZE],
    ) {
        Ok(_) => (),
        Err(err) => result_bad_8 = err,
    }

    // key length not equal to 'ATCA_AES_KEY_SIZE'
    match device.mac_verify(
        MacAlgorithm::Cbcmac(param_bad_6),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_9 = err,
    }

    // value of 'mac' does not match
    if let Ok(is_mac_ok) = device.mac_verify(
        MacAlgorithm::Cbcmac(param_ok),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        result_mac = is_mac_ok
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    if chip_is_locked && device.is_aes_enabled() {
        assert!(!result_mac);
    }
    assert_eq!(result_bad_1, expected_bad_1);
    assert_eq!(result_bad_2, expected_bad_2);
    assert_eq!(result_bad_3, expected_bad_3);
    assert_eq!(result_bad_4, expected_bad_4);
    assert_eq!(result_bad_5, expected_bad_5);
    assert_eq!(result_bad_6, expected_bad_6);
    assert_eq!(result_bad_7, expected_bad_7);
    assert_eq!(result_bad_8, expected_bad_8);
    assert_eq!(result_bad_9, expected_bad_9);
}

#[test]
#[serial]
fn compute_mac_hmac_sha256_proper_data() {
    const SHORT_TEXT_SIZE: usize = 15;
    const SHORT_MAC_SIZE: usize = 12;
    const SHA_KEY_SLOT_IDX: u8 = 0x0A;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let key = [
        0x19, 0x1A, 0x70, 0x0F, 0x3D, 0xC5, 0x60, 0xA5, 0x89, 0xF9, 0xC2, 0xCA, 0x78, 0x4E, 0x97,
        0x0C, 0xB1, 0xE5, 0x52, 0xA0, 0xE6, 0xB3, 0xDF, 0x54, 0xFC, 0x1C, 0xE3, 0xC5, 0x6C, 0xC4,
        0x46, 0xD2,
    ];

    let plain_text = [
        0x19, 0x48, 0xC7, 0x12, 0x0A, 0x06, 0x18, 0xC5, 0x44, 0xA3, 0x9E, 0x59, 0x57, 0x40, 0x8B,
        0x89, 0x22, 0x0A, 0xE3, 0x98, 0xEC, 0x05, 0x30, 0x39, 0xB0, 0x09, 0x78, 0xAD, 0xB7, 0x0A,
        0x6C, 0x2B, 0x6C, 0x9C, 0xE2, 0x84, 0x6D, 0xB5, 0x85, 0x07, 0xDE, 0xB5, 0xCB, 0xA2, 0x02,
        0xA5, 0x28, 0x4B, 0x0C, 0xBC, 0x82, 0x9E, 0x32, 0x28, 0xE4, 0xC8, 0x04, 0x0B, 0x76, 0xA3,
        0xFC, 0xC3, 0xAD, 0x22, 0x56, 0x6E, 0xBF, 0xF0, 0x21, 0xAD, 0x5A, 0x54, 0x97, 0xA9, 0x95,
        0x58, 0xAA, 0x54, 0x27, 0x2A, 0xDF, 0xF2, 0xD6, 0xC2, 0x5F, 0xD7, 0x33, 0xC5, 0x4C, 0x72,
        0x85, 0xAA, 0x51, 0x8A, 0x03, 0x1B, 0x7D, 0xC8, 0x46, 0x9E, 0x51, 0x76, 0xFD, 0x74, 0x17,
        0x86, 0xE3, 0xC1, 0x76, 0xD6, 0xEE, 0xEE, 0x44, 0xB2, 0xC9, 0x4C, 0x9B, 0x9B, 0x85, 0xFA,
        0x2F, 0x46, 0x8C, 0x08, 0xDE, 0xE8, 0xD6, 0xDC,
    ];

    let mac = [
        0xBB, 0xAE, 0x34, 0x43, 0x90, 0x57, 0x81, 0xE5, 0x35, 0x47, 0xD5, 0xE5, 0xD5, 0x66, 0xB5,
        0x5D, 0x1B, 0x95, 0xA9, 0x9C, 0xDB, 0x85, 0xB3, 0x61, 0x79, 0x2E, 0x1E, 0xA6, 0xB5, 0x17,
        0x43, 0xE2,
    ];

    let mac_short_text = [
        0x67, 0x38, 0x7D, 0x9A, 0x4E, 0x80, 0x6D, 0xAF, 0xAF, 0xEF, 0x72, 0xB8, 0xD6, 0x20, 0x8F,
        0xDE, 0xE4, 0x31, 0xBA, 0xBD, 0xF8, 0x7E, 0x73, 0x7B, 0x0E, 0xBF, 0x54, 0xDF, 0x8C, 0x4A,
        0xAB, 0x0A,
    ];

    let param_ok = MacParam {
        key: Some(key.to_vec()),
        ..Default::default()
    };

    let param_ok_internal_key = MacParam {
        ..Default::default()
    };

    let param_ok_internal_key_short_mac = MacParam {
        mac_length: Some(SHORT_MAC_SIZE as u8),
        ..Default::default()
    };

    let mut result_mac = vec![0x00; ATCA_SHA2_256_DIGEST_SIZE];
    let mut result_mac_internal_key = vec![0x00; ATCA_SHA2_256_DIGEST_SIZE];
    let mut result_mac_internal_key_short_text = vec![0x00; ATCA_SHA2_256_DIGEST_SIZE];
    let mut result_mac_internal_key_short_mac = vec![0x00; SHORT_MAC_SIZE];

    let mut expected = AtcaStatus::AtcaBadParam;
    let mut expected_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_internal_key_short_text = AtcaStatus::AtcaBadParam;
    let mut expected_internal_key_short_mac = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;
    let mut result = AtcaStatus::AtcaUnknown;
    let mut result_internal_key = AtcaStatus::AtcaUnknown;
    let mut result_internal_key_short_text = AtcaStatus::AtcaUnknown;
    let mut result_internal_key_short_mac = AtcaStatus::AtcaUnknown;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected = AtcaStatus::AtcaNotLocked;
        expected_internal_key = AtcaStatus::AtcaNotLocked;
        expected_internal_key_short_text = AtcaStatus::AtcaNotLocked;
        expected_internal_key_short_mac = AtcaStatus::AtcaNotLocked;

        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::ShaOrText, &key, SHA_KEY_SLOT_IDX);

    if chip_is_locked {
        expected = AtcaStatus::AtcaSuccess;
        expected_internal_key = AtcaStatus::AtcaSuccess;
        expected_internal_key_short_mac = AtcaStatus::AtcaSuccess;
        expected_internal_key_short_text = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;

        result = AtcaStatus::AtcaSuccess;
        result_internal_key = AtcaStatus::AtcaSuccess;
        result_internal_key_short_text = AtcaStatus::AtcaSuccess;
        result_internal_key_short_mac = AtcaStatus::AtcaSuccess;

        if device.get_device_type() != AtcaDeviceType::ATECC608A {
            expected = AtcaStatus::AtcaBadParam;
        }
    }

    match device.mac_compute(
        MacAlgorithm::HmacSha256(param_ok),
        ATCA_ATECC_SLOTS_COUNT,
        &plain_text.to_vec(),
    ) {
        Ok(mac) => result_mac = mac,
        Err(err) => result = err,
    }

    match device.mac_compute(
        MacAlgorithm::HmacSha256(param_ok_internal_key.clone()),
        SHA_KEY_SLOT_IDX,
        &plain_text.to_vec(),
    ) {
        Ok(mac) => result_mac_internal_key = mac,
        Err(err) => result_internal_key = err,
    }

    match device.mac_compute(
        MacAlgorithm::HmacSha256(param_ok_internal_key),
        SHA_KEY_SLOT_IDX,
        &plain_text[..SHORT_TEXT_SIZE].to_vec(),
    ) {
        Ok(mac) => result_mac_internal_key_short_text = mac,
        Err(err) => result_internal_key_short_text = err,
    }

    match device.mac_compute(
        MacAlgorithm::HmacSha256(param_ok_internal_key_short_mac),
        SHA_KEY_SLOT_IDX,
        &plain_text.to_vec(),
    ) {
        Ok(mac) => result_mac_internal_key_short_mac = mac,
        Err(err) => result_internal_key_short_mac = err,
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked {
        assert_eq!(result_mac_internal_key, mac.to_vec());
        assert_eq!(result_mac_internal_key_short_text, mac_short_text.to_vec());
        assert_eq!(
            result_mac_internal_key_short_mac,
            mac[..SHORT_MAC_SIZE].to_vec()
        );

        if device.get_device_type() == AtcaDeviceType::ATECC608A {
            assert_eq!(result_mac, mac.to_vec());
        }
    }
    assert_eq!(result, expected);
    assert_eq!(result_internal_key, expected_internal_key);
    assert_eq!(
        result_internal_key_short_text,
        expected_internal_key_short_text
    );
    assert_eq!(
        result_internal_key_short_mac,
        expected_internal_key_short_mac
    );
}

#[test]
#[serial]
fn compute_mac_hmac_sha256_bad_data() {
    const SHA_KEY_SLOT_IDX: u8 = 0x0A;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let data: Vec<u8> = vec![0x00; ATCA_SHA2_256_DIGEST_SIZE];
    let param_ok = MacParam {
        key: Some(vec![0x00; ATCA_SHA2_256_DIGEST_SIZE]),
        ..Default::default()
    };

    let param_bad_1 = MacParam {
        ..Default::default()
    };

    let param_bad_2 = MacParam {
        key: Some(vec![0x00; ATCA_SHA2_256_DIGEST_SIZE]),
        mac_length: Some(ATCA_SHA2_256_DIGEST_SIZE as u8),
        mac: Some(data.clone()),
    };

    let param_bad_3 = MacParam {
        key: Some(vec![0x00; ATCA_SHA2_256_DIGEST_SIZE]),
        mac_length: Some(0x00),
        ..Default::default()
    };

    let param_bad_4 = MacParam {
        key: Some(vec![0x00; ATCA_SHA2_256_DIGEST_SIZE]),
        mac_length: Some((ATCA_SHA2_256_DIGEST_SIZE + 1) as u8),
        ..Default::default()
    };

    let param_bad_5 = MacParam {
        key: Some(vec![0x00; ATCA_SHA2_256_DIGEST_SIZE]),
        mac: Some(vec![0x00; 0]),
        ..Default::default()
    };

    let param_bad_6 = MacParam {
        key: Some(vec![0x00; ATCA_SHA2_256_DIGEST_SIZE]),
        mac: Some(vec![0x00; ATCA_SHA2_256_DIGEST_SIZE + 1]),
        ..Default::default()
    };

    let param_bad_7 = MacParam {
        key: Some(vec![0x00; ATCA_SHA2_256_DIGEST_SIZE + 1]),
        ..Default::default()
    };

    let mut expected_bad_1 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_2 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_3 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_4 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_5 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_6 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_7 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_8 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_9 = AtcaStatus::AtcaBadParam;
    let mut result_bad_1 = AtcaStatus::AtcaUnknown;
    let mut result_bad_2 = AtcaStatus::AtcaUnknown;
    let mut result_bad_3 = AtcaStatus::AtcaUnknown;
    let mut result_bad_4 = AtcaStatus::AtcaUnknown;
    let mut result_bad_5 = AtcaStatus::AtcaUnknown;
    let mut result_bad_6 = AtcaStatus::AtcaUnknown;
    let mut result_bad_7 = AtcaStatus::AtcaUnknown;
    let mut result_bad_8 = AtcaStatus::AtcaUnknown;
    let mut result_bad_9 = AtcaStatus::AtcaUnknown;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_bad_1 = AtcaStatus::AtcaNotLocked;
        expected_bad_2 = AtcaStatus::AtcaNotLocked;
        expected_bad_3 = AtcaStatus::AtcaNotLocked;
        expected_bad_4 = AtcaStatus::AtcaNotLocked;
        expected_bad_5 = AtcaStatus::AtcaNotLocked;
        expected_bad_6 = AtcaStatus::AtcaNotLocked;
        expected_bad_7 = AtcaStatus::AtcaNotLocked;
        expected_bad_8 = AtcaStatus::AtcaNotLocked;
        expected_bad_9 = AtcaStatus::AtcaNotLocked;
    }

    if chip_is_locked {
        expected_bad_1 = AtcaStatus::AtcaInvalidId;
        expected_bad_2 = AtcaStatus::AtcaInvalidId;
        expected_bad_3 = AtcaStatus::AtcaBadParam;
        expected_bad_4 = AtcaStatus::AtcaBadParam;
        expected_bad_5 = AtcaStatus::AtcaInvalidSize;
        expected_bad_6 = AtcaStatus::AtcaInvalidSize;
        expected_bad_7 = AtcaStatus::AtcaInvalidSize;
        expected_bad_8 = AtcaStatus::AtcaInvalidSize;
        expected_bad_9 = AtcaStatus::AtcaInvalidSize;
    }

    // slot_id is too big
    match device.mac_compute(
        MacAlgorithm::HmacSha256(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_1 = err,
    }

    // slot holds a key other than ShaOrText
    match device.mac_compute(MacAlgorithm::HmacSha256(param_ok), 0x00, &data) {
        Ok(_) => (),
        Err(err) => result_bad_2 = err,
    }

    // slot_id points to TEMP_KEY but no key data
    match device.mac_compute(
        MacAlgorithm::HmacSha256(param_bad_1),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_3 = err,
    }

    // both 'mac_length' and 'mac' parameters were passed - properly there should be only one of them
    match device.mac_compute(
        MacAlgorithm::HmacSha256(param_bad_2),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_4 = err,
    }

    // 'mac_length' value too low
    match device.mac_compute(
        MacAlgorithm::HmacSha256(param_bad_3),
        SHA_KEY_SLOT_IDX,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_5 = err,
    }

    // 'mac_length' value too high
    match device.mac_compute(
        MacAlgorithm::HmacSha256(param_bad_4),
        SHA_KEY_SLOT_IDX,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_6 = err,
    }

    // 'mac' length too short
    match device.mac_compute(
        MacAlgorithm::HmacSha256(param_bad_5),
        SHA_KEY_SLOT_IDX,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_7 = err,
    }

    // 'mac' length too long
    match device.mac_compute(
        MacAlgorithm::HmacSha256(param_bad_6),
        SHA_KEY_SLOT_IDX,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_8 = err,
    }

    // key length is larger than 'ATCA_SHA2_256_DIGEST_SIZE'
    match device.mac_compute(
        MacAlgorithm::HmacSha256(param_bad_7),
        SHA_KEY_SLOT_IDX,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_9 = err,
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_bad_1, expected_bad_1);
    assert_eq!(result_bad_2, expected_bad_2);
    assert_eq!(result_bad_3, expected_bad_3);
    assert_eq!(result_bad_4, expected_bad_4);
    assert_eq!(result_bad_5, expected_bad_5);
    assert_eq!(result_bad_6, expected_bad_6);
    assert_eq!(result_bad_7, expected_bad_7);
    assert_eq!(result_bad_8, expected_bad_8);
    assert_eq!(result_bad_9, expected_bad_9);
}

#[test]
#[serial]
fn verify_mac_hmac_sha256_proper_data() {
    const SHORT_TEXT_SIZE: usize = 15;
    const SHORT_MAC_SIZE: usize = 12;
    const SHA_KEY_SLOT_IDX: u8 = 0x0A;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let key = [
        0x19, 0x1A, 0x70, 0x0F, 0x3D, 0xC5, 0x60, 0xA5, 0x89, 0xF9, 0xC2, 0xCA, 0x78, 0x4E, 0x97,
        0x0C, 0xB1, 0xE5, 0x52, 0xA0, 0xE6, 0xB3, 0xDF, 0x54, 0xFC, 0x1C, 0xE3, 0xC5, 0x6C, 0xC4,
        0x46, 0xD2,
    ];

    let plain_text = [
        0x19, 0x48, 0xC7, 0x12, 0x0A, 0x06, 0x18, 0xC5, 0x44, 0xA3, 0x9E, 0x59, 0x57, 0x40, 0x8B,
        0x89, 0x22, 0x0A, 0xE3, 0x98, 0xEC, 0x05, 0x30, 0x39, 0xB0, 0x09, 0x78, 0xAD, 0xB7, 0x0A,
        0x6C, 0x2B, 0x6C, 0x9C, 0xE2, 0x84, 0x6D, 0xB5, 0x85, 0x07, 0xDE, 0xB5, 0xCB, 0xA2, 0x02,
        0xA5, 0x28, 0x4B, 0x0C, 0xBC, 0x82, 0x9E, 0x32, 0x28, 0xE4, 0xC8, 0x04, 0x0B, 0x76, 0xA3,
        0xFC, 0xC3, 0xAD, 0x22, 0x56, 0x6E, 0xBF, 0xF0, 0x21, 0xAD, 0x5A, 0x54, 0x97, 0xA9, 0x95,
        0x58, 0xAA, 0x54, 0x27, 0x2A, 0xDF, 0xF2, 0xD6, 0xC2, 0x5F, 0xD7, 0x33, 0xC5, 0x4C, 0x72,
        0x85, 0xAA, 0x51, 0x8A, 0x03, 0x1B, 0x7D, 0xC8, 0x46, 0x9E, 0x51, 0x76, 0xFD, 0x74, 0x17,
        0x86, 0xE3, 0xC1, 0x76, 0xD6, 0xEE, 0xEE, 0x44, 0xB2, 0xC9, 0x4C, 0x9B, 0x9B, 0x85, 0xFA,
        0x2F, 0x46, 0x8C, 0x08, 0xDE, 0xE8, 0xD6, 0xDC,
    ];

    let mac = [
        0xBB, 0xAE, 0x34, 0x43, 0x90, 0x57, 0x81, 0xE5, 0x35, 0x47, 0xD5, 0xE5, 0xD5, 0x66, 0xB5,
        0x5D, 0x1B, 0x95, 0xA9, 0x9C, 0xDB, 0x85, 0xB3, 0x61, 0x79, 0x2E, 0x1E, 0xA6, 0xB5, 0x17,
        0x43, 0xE2,
    ];

    let mac_short_text = [
        0x67, 0x38, 0x7D, 0x9A, 0x4E, 0x80, 0x6D, 0xAF, 0xAF, 0xEF, 0x72, 0xB8, 0xD6, 0x20, 0x8F,
        0xDE, 0xE4, 0x31, 0xBA, 0xBD, 0xF8, 0x7E, 0x73, 0x7B, 0x0E, 0xBF, 0x54, 0xDF, 0x8C, 0x4A,
        0xAB, 0x0A,
    ];

    let param_ok = MacParam {
        key: Some(key.to_vec()),
        mac: Some(mac.to_vec()),
        ..Default::default()
    };

    let param_ok_internal_key = MacParam {
        mac: Some(mac.to_vec()),
        ..Default::default()
    };

    let param_ok_internal_key_short_text = MacParam {
        mac: Some(mac_short_text.to_vec()),
        ..Default::default()
    };

    let param_ok_internal_key_short_mac = MacParam {
        mac: Some(mac[..SHORT_MAC_SIZE].to_vec()),
        ..Default::default()
    };

    let mut result_mac: bool = false;
    let mut result_mac_internal_key: bool = false;
    let mut result_mac_internal_key_short_text: bool = false;
    let mut result_mac_internal_key_short_mac: bool = false;

    let mut expected = AtcaStatus::AtcaBadParam;
    let mut expected_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_internal_key_short_text = AtcaStatus::AtcaBadParam;
    let mut expected_internal_key_short_mac = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;
    let mut result = AtcaStatus::AtcaUnknown;
    let mut result_internal_key = AtcaStatus::AtcaUnknown;
    let mut result_internal_key_short_text = AtcaStatus::AtcaUnknown;
    let mut result_internal_key_short_mac = AtcaStatus::AtcaUnknown;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected = AtcaStatus::AtcaNotLocked;
        expected_internal_key = AtcaStatus::AtcaNotLocked;
        expected_internal_key_short_text = AtcaStatus::AtcaNotLocked;
        expected_internal_key_short_mac = AtcaStatus::AtcaNotLocked;

        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::ShaOrText, &key, SHA_KEY_SLOT_IDX);

    if chip_is_locked {
        expected = AtcaStatus::AtcaSuccess;
        expected_internal_key = AtcaStatus::AtcaSuccess;
        expected_internal_key_short_text = AtcaStatus::AtcaSuccess;
        expected_internal_key_short_mac = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;

        if device.get_device_type() != AtcaDeviceType::ATECC608A {
            expected = AtcaStatus::AtcaBadParam;
        }

        result = AtcaStatus::AtcaSuccess;
        result_internal_key = AtcaStatus::AtcaSuccess;
        result_internal_key_short_text = AtcaStatus::AtcaSuccess;
        result_internal_key_short_mac = AtcaStatus::AtcaSuccess;
    }

    match device.mac_verify(
        MacAlgorithm::HmacSha256(param_ok),
        ATCA_ATECC_SLOTS_COUNT,
        &plain_text.to_vec(),
    ) {
        Ok(is_mac_ok) => result_mac = is_mac_ok,
        Err(err) => result = err,
    }

    match device.mac_verify(
        MacAlgorithm::HmacSha256(param_ok_internal_key),
        SHA_KEY_SLOT_IDX,
        &plain_text.to_vec(),
    ) {
        Ok(is_mac_ok) => result_mac_internal_key = is_mac_ok,
        Err(err) => result_internal_key = err,
    }

    match device.mac_verify(
        MacAlgorithm::HmacSha256(param_ok_internal_key_short_text),
        SHA_KEY_SLOT_IDX,
        &plain_text[..SHORT_TEXT_SIZE].to_vec(),
    ) {
        Ok(is_mac_ok) => result_mac_internal_key_short_text = is_mac_ok,
        Err(err) => result_internal_key_short_text = err,
    }

    match device.mac_verify(
        MacAlgorithm::HmacSha256(param_ok_internal_key_short_mac),
        SHA_KEY_SLOT_IDX,
        &plain_text.to_vec(),
    ) {
        Ok(is_mac_ok) => result_mac_internal_key_short_mac = is_mac_ok,
        Err(err) => result_internal_key_short_mac = err,
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked {
        assert!(result_mac_internal_key);
        assert!(result_mac_internal_key_short_text);
        assert!(result_mac_internal_key_short_mac);

        if device.get_device_type() == AtcaDeviceType::ATECC608A {
            assert!(result_mac);
        }
    }
    assert_eq!(result, expected);
    assert_eq!(result_internal_key, expected_internal_key);
    assert_eq!(
        result_internal_key_short_text,
        expected_internal_key_short_text
    );
    assert_eq!(
        result_internal_key_short_mac,
        expected_internal_key_short_mac
    );
}

#[test]
#[serial]
fn verify_mac_hmac_sha256_bad_data() {
    const SHA_KEY_SLOT_IDX: u8 = 0x0A;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let data: Vec<u8> = vec![0x00; ATCA_SHA2_256_DIGEST_SIZE];
    let param_ok = MacParam {
        key: Some(data.clone()),
        mac: Some(data.clone()),
        ..Default::default()
    };

    let param_bad_1 = MacParam {
        mac: Some(data.clone()),
        ..Default::default()
    };

    let param_bad_2 = MacParam {
        key: Some(data.clone()),
        mac_length: Some(ATCA_SHA2_256_DIGEST_SIZE as u8),
        mac: Some(data.clone()),
    };

    let param_bad_3 = MacParam {
        key: Some(data.clone()),
        ..Default::default()
    };

    let param_bad_4 = MacParam {
        key: Some(data.clone()),
        mac: Some(vec![0x00; 0]),
        ..Default::default()
    };

    let param_bad_5 = MacParam {
        key: Some(data.clone()),
        mac: Some(vec![0x00; ATCA_SHA2_256_DIGEST_SIZE + 1]),
        ..Default::default()
    };

    let param_bad_6 = MacParam {
        key: Some(vec![0x00; ATCA_SHA2_256_DIGEST_SIZE + 1]),
        mac: Some(data.clone()),
        ..Default::default()
    };

    let mut expected_bad_1 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_2 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_3 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_4 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_5 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_6 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_7 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_8 = AtcaStatus::AtcaBadParam;
    let mut result_bad_1 = AtcaStatus::AtcaUnknown;
    let mut result_bad_2 = AtcaStatus::AtcaUnknown;
    let mut result_bad_3 = AtcaStatus::AtcaUnknown;
    let mut result_bad_4 = AtcaStatus::AtcaUnknown;
    let mut result_bad_5 = AtcaStatus::AtcaUnknown;
    let mut result_bad_6 = AtcaStatus::AtcaUnknown;
    let mut result_bad_7 = AtcaStatus::AtcaUnknown;
    let mut result_bad_8 = AtcaStatus::AtcaUnknown;
    let mut result_mac: bool = true;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_bad_1 = AtcaStatus::AtcaNotLocked;
        expected_bad_2 = AtcaStatus::AtcaNotLocked;
        expected_bad_3 = AtcaStatus::AtcaNotLocked;
        expected_bad_4 = AtcaStatus::AtcaNotLocked;
        expected_bad_5 = AtcaStatus::AtcaNotLocked;
        expected_bad_6 = AtcaStatus::AtcaNotLocked;
        expected_bad_7 = AtcaStatus::AtcaNotLocked;
        expected_bad_8 = AtcaStatus::AtcaNotLocked;
    }

    if chip_is_locked {
        expected_bad_1 = AtcaStatus::AtcaInvalidId;
        expected_bad_2 = AtcaStatus::AtcaInvalidId;
        expected_bad_3 = AtcaStatus::AtcaBadParam;
        expected_bad_4 = AtcaStatus::AtcaBadParam;
        expected_bad_5 = AtcaStatus::AtcaBadParam;
        expected_bad_6 = AtcaStatus::AtcaInvalidSize;
        expected_bad_7 = AtcaStatus::AtcaInvalidSize;
        expected_bad_8 = AtcaStatus::AtcaInvalidSize;
    }

    // slot_id is too big
    match device.mac_verify(
        MacAlgorithm::HmacSha256(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_1 = err,
    }

    // slot holds a key other than ShaOrText
    match device.mac_verify(MacAlgorithm::HmacSha256(param_ok.clone()), 0x00, &data) {
        Ok(_) => (),
        Err(err) => result_bad_2 = err,
    }

    // slot_id points to TEMP_KEY but no key data
    match device.mac_verify(
        MacAlgorithm::HmacSha256(param_bad_1),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_3 = err,
    }

    // both 'mac_length' and 'mac' parameters were passed - properly there should be only one of them
    match device.mac_verify(
        MacAlgorithm::HmacSha256(param_bad_2),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_4 = err,
    }

    // no 'mac' data to check
    match device.mac_verify(
        MacAlgorithm::HmacSha256(param_bad_3),
        ATCA_ATECC_SLOTS_COUNT,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_5 = err,
    }

    // 'mac' length too short
    match device.mac_verify(
        MacAlgorithm::HmacSha256(param_bad_4),
        SHA_KEY_SLOT_IDX,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_6 = err,
    }

    // 'mac' length too long
    match device.mac_verify(
        MacAlgorithm::HmacSha256(param_bad_5),
        SHA_KEY_SLOT_IDX,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_7 = err,
    }

    // key length is larger than 'ATCA_SHA2_256_DIGEST_SIZE'
    match device.mac_verify(
        MacAlgorithm::HmacSha256(param_bad_6),
        SHA_KEY_SLOT_IDX,
        &data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_8 = err,
    }

    // value of 'mac' does not match
    if let Ok(is_mac_ok) =
        device.mac_verify(MacAlgorithm::HmacSha256(param_ok), SHA_KEY_SLOT_IDX, &data)
    {
        result_mac = is_mac_ok
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    if chip_is_locked {
        assert!(!result_mac);
    }
    assert_eq!(result_bad_1, expected_bad_1);
    assert_eq!(result_bad_2, expected_bad_2);
    assert_eq!(result_bad_3, expected_bad_3);
    assert_eq!(result_bad_4, expected_bad_4);
    assert_eq!(result_bad_5, expected_bad_5);
    assert_eq!(result_bad_6, expected_bad_6);
    assert_eq!(result_bad_7, expected_bad_7);
    assert_eq!(result_bad_8, expected_bad_8);
}
