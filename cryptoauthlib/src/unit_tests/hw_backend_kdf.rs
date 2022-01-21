// Types
use super::{
    AtcaDeviceType, AtcaStatus, AteccDevice, HkdfDetails, HkdfMsgLoc, KdfAlgorithm, KdfParams,
    KdfPrfKeyLen, KdfPrfTargetLen, KdfSource, KdfTarget, KeyType, NonceTarget, PrfDetails,
};
// Constants
use super::{
    ATCA_AES_DATA_SIZE, ATCA_ATECC_SLOTS_COUNT, ATCA_BLOCK_SIZE, ATCA_KDF_MAX_MSG_SIZE,
    ATCA_NONCE_SIZE, ATCA_SHA2_256_DIGEST_SIZE,
};

use super::hw_backend_common::*;
use serial_test::serial;

#[test]
#[serial]
fn kdf_aes_proper_data() {
    const TEST_KEY_SLOT_IDX: u8 = 0x09;

    let message = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E,
        0x4F,
    ];

    let test_key = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
        0x2F,
    ];

    // kdf key = 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, => kdf out =
    // kdf key = 0x85, 0x94, 0x69, 0xC0, 0x77, 0x43, 0xC7, 0xE4, 0x5B, 0x31, 0x8D, 0x15, 0x1D, 0x3D, 0x87, 0xE9, => kdf out =
    // kdf key = 0x18, 0xDC, 0xC8, 0xAE, 0xCD, 0x21, 0x5E, 0x2F, 0x81, 0x41, 0xC2, 0xA0, 0xBD, 0x97, 0x96, 0xBC, => kdf out =
    // kdf key = 0xCD, 0xDB, 0x1D, 0xD5, 0xB0, 0xF9, 0xF6, 0x89, 0xFD, 0xF3, 0x6D, 0x28, 0x9C, 0x16, 0x69, 0xBF, => kdf out =
    //           0x0D, 0x66, 0x58, 0xBE, 0x6E, 0x97, 0x2F, 0x4F, 0x03, 0x32, 0x35, 0xCA, 0x9B, 0x72, 0x2A, 0x20,

    let expected_kdf_aes_1 = [
        0x18, 0xDC, 0xC8, 0xAE, 0xCD, 0x21, 0x5E, 0x2F, 0x81, 0x41, 0xC2, 0xA0, 0xBD, 0x97, 0x96,
        0xBC,
    ];
    let expected_kdf_aes_2 = [
        0x85, 0x94, 0x69, 0xC0, 0x77, 0x43, 0xC7, 0xE4, 0x5B, 0x31, 0x8D, 0x15, 0x1D, 0x3D, 0x87,
        0xE9,
    ];

    let expected_kdf_aes_3 = [
        0x0D, 0x66, 0x58, 0xBE, 0x6E, 0x97, 0x2F, 0x4F, 0x03, 0x32, 0x35, 0xCA, 0x9B, 0x72, 0x2A,
        0x20,
    ];

    let device = test_setup();

    let is_proper_dev_type: bool = !(device.get_device_type() != AtcaDeviceType::ATECC608A);
    let mut chip_is_locked: bool = true;

    let mut expected_bad_result = AtcaStatus::AtcaBadParam;
    let mut decrypt_result = AtcaStatus::AtcaUnknown;
    let mut kdf_message: Vec<u8> = Vec::new();

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_bad_result = AtcaStatus::AtcaNotLocked;
    }

    let algorithm: KdfAlgorithm = KdfAlgorithm::Aes;

    let parameters_1 = KdfParams {
        source: KdfSource::TempKey,
        target: KdfTarget::TempKey,
        ..Default::default()
    };
    let parameters_2 = KdfParams {
        source: KdfSource::TempKey,
        target: KdfTarget::Output,
        ..Default::default()
    };
    let parameters_3 = KdfParams {
        source: KdfSource::TempKey,
        target: KdfTarget::Slot,
        target_slot_id: Some(TEST_KEY_SLOT_IDX),
        ..Default::default()
    };
    let parameters_4 = KdfParams {
        source: KdfSource::Slot,
        target: KdfTarget::TempKeyUp,
        source_slot_id: Some(TEST_KEY_SLOT_IDX),
        ..Default::default()
    };
    let parameters_5 = KdfParams {
        source: KdfSource::TempKeyUp,
        target: KdfTarget::AltKeyBuf,
        ..Default::default()
    };
    let parameters_6 = KdfParams {
        source: KdfSource::AltKeyBuf,
        target: KdfTarget::OutputEnc,
        ..Default::default()
    };

    let mut nonce = test_key.to_vec();
    nonce.resize(ATCA_NONCE_SIZE, 0x00);
    let nonce_result_1 = device.nonce(NonceTarget::TempKey, &nonce);

    let result_1 = device.kdf(
        algorithm.clone(),
        parameters_1,
        Some(&message),
        message.len(),
    );
    let result_2 = device.kdf(
        algorithm.clone(),
        parameters_2.clone(),
        Some(&message),
        message.len(),
    );

    let nonce_result_2 = device.nonce(NonceTarget::TempKey, &nonce);
    let result_3 = device.kdf(
        algorithm.clone(),
        parameters_2,
        Some(&message),
        message.len(),
    );
    let result_4 = device.kdf(
        algorithm.clone(),
        parameters_3,
        Some(&message),
        message.len(),
    );
    let result_5 = device.kdf(
        algorithm.clone(),
        parameters_4,
        Some(&message),
        message.len(),
    );
    let result_6 = device.kdf(
        algorithm.clone(),
        parameters_5,
        Some(&message),
        message.len(),
    );
    let result_7 = device.kdf(algorithm, parameters_6, Some(&message), message.len());

    if result_7.is_ok() {
        kdf_message = result_7.clone().unwrap().out_data.unwrap();
        let nonce: Vec<u8> = result_7.clone().unwrap().out_nonce.unwrap();
        decrypt_result = io_decrypt(&device, &mut kdf_message, &nonce);
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(nonce_result_1, AtcaStatus::AtcaSuccess);
    assert_eq!(nonce_result_2, AtcaStatus::AtcaSuccess);
    if is_proper_dev_type && chip_is_locked {
        assert!(result_1.is_ok());
        assert!(result_2.is_ok());
        assert_eq!(
            result_2.unwrap().out_data.unwrap(),
            expected_kdf_aes_1.to_vec()
        );
        assert!(result_3.is_ok());
        assert_eq!(
            result_3.unwrap().out_data.unwrap(),
            expected_kdf_aes_2.to_vec()
        );
        assert!(result_4.is_ok());
        assert!(result_5.is_ok());
        assert!(result_6.is_ok());
        assert!(result_7.is_ok());
        assert_eq!(decrypt_result, AtcaStatus::AtcaSuccess);
        assert_eq!(kdf_message, expected_kdf_aes_3.to_vec());
    } else {
        assert_eq!(result_1.err().unwrap(), expected_bad_result);
        assert_eq!(result_2.err().unwrap(), expected_bad_result);
        assert_eq!(result_3.err().unwrap(), expected_bad_result);
        assert_eq!(result_4.err().unwrap(), expected_bad_result);
        assert_eq!(result_5.err().unwrap(), expected_bad_result);
        assert_eq!(result_6.err().unwrap(), expected_bad_result);
        assert_eq!(result_7.err().unwrap(), expected_bad_result);
    }
}

#[test]
#[serial]
fn kdf_aes_bad_data() {
    const BAD_AES_MESSAGE_LEN: usize = ATCA_AES_DATA_SIZE - 1;

    let device = test_setup();

    let is_proper_dev_type: bool = !(device.get_device_type() != AtcaDeviceType::ATECC608A);
    let mut chip_is_locked: bool = true;

    let mut expected_bad_result = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_bad_result = AtcaStatus::AtcaNotLocked;
    }

    let algorithm_1: KdfAlgorithm = KdfAlgorithm::Aes;

    let parameters_1 = KdfParams {
        ..Default::default()
    };

    // algorithm AES, TempKey not valid
    let sleep_result = {
        let result = device.wakeup();
        match result {
            AtcaStatus::AtcaSuccess => device.sleep(),
            _ => result,
        }
    };
    let bad_result_1 = device.kdf(
        algorithm_1.clone(),
        parameters_1.clone(),
        Some(&[0x00; ATCA_AES_DATA_SIZE]),
        ATCA_AES_DATA_SIZE,
    );

    // algorithm AES, message length != ATCA_AES_DATA_SIZE
    let nonce_result = device.nonce(NonceTarget::TempKey, &[0x00; ATCA_BLOCK_SIZE]);
    let bad_result_2 = device.kdf(
        algorithm_1.clone(),
        parameters_1.clone(),
        Some(&[0x00; BAD_AES_MESSAGE_LEN]),
        BAD_AES_MESSAGE_LEN,
    );

    // algorithm AES, no message
    let bad_result_3 = device.kdf(algorithm_1, parameters_1, None, ATCA_AES_DATA_SIZE);

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(sleep_result, AtcaStatus::AtcaSuccess);
    assert_eq!(nonce_result, AtcaStatus::AtcaSuccess);
    if is_proper_dev_type && chip_is_locked {
        assert!(bad_result_1.is_err());
        assert_eq!(bad_result_1.err().unwrap(), AtcaStatus::AtcaBadParam);
        assert!(bad_result_2.is_err());
        assert_eq!(bad_result_2.err().unwrap(), AtcaStatus::AtcaInvalidSize);
        assert!(bad_result_3.is_err());
        assert_eq!(bad_result_3.err().unwrap(), AtcaStatus::AtcaBadParam);
    } else {
        assert_eq!(bad_result_1.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_2.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_3.err().unwrap(), expected_bad_result);
    }
}

#[test]
#[serial]
fn kdf_prf_proper_data() {
    const TEST_KEY_SLOT_IDX: u8 = 0x09;
    const SHORT_MESSAGE_LEN: usize = 0x10;

    let message = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E,
        0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D,
        0x5E, 0x5F,
    ];

    let test_key = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
        0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
        0x3E, 0x3F,
    ];

    // kdf key = 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    //           0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, => kdf out =
    // kdf key = 0xC9, 0x22, 0xF5, 0x6E, 0xEA, 0x75, 0x9C, 0x25, 0x15, 0x4A, 0x73, 0x3A, 0xB7, 0x89, 0x82, 0x86,
    //           0xC1, 0xA1, 0xFF, 0x91, 0x97, 0xE2, 0xAD, 0x31, 0xEF, 0x10, 0x14, 0x4F, 0xA0, 0xCE, 0x9D, 0x2F, => kdf out =
    // kdf key = 0xBB, 0x24, 0x9F, 0x67, 0xC5, 0xEE, 0x5E, 0xD1, 0x53, 0x50, 0x4E, 0x8E, 0x81, 0x69, 0xD8, 0xC6,
    //           0x51, 0x5B, 0x97, 0xE3, 0xC9, 0xA2, 0xF0, 0x2E, 0x4E, 0x35, 0x25, 0xC5, 0xF3, 0x67, 0x49, 0xE2, => kdf out =
    // kdf key = 0x3D, 0x52, 0xBF, 0x3F, 0xD2, 0xC9, 0x17, 0x9E, 0x73, 0xF9, 0xB2, 0x0F, 0x92, 0xB4, 0x9B, 0xFD,
    //           0x03, 0xC8, 0xB4, 0xA4, 0x68, 0xEA, 0x12, 0xBF, 0x4B, 0x89, 0x8B, 0xBD, 0xEA, 0xC3, 0x90, 0xD5, => kdf out =
    //           0xF7, 0x4F, 0x68, 0xA1, 0x11, 0x66, 0x07, 0x86, 0xC1, 0xD0, 0x7F, 0xC0, 0xFF, 0x81, 0x3A, 0x3F,
    //           0x2C, 0x7B, 0x28, 0xC7, 0x44, 0x79, 0x12, 0xEE, 0x4C, 0xCC, 0x91, 0xB4, 0x72, 0x7C, 0x87, 0x6D,
    //           0xB2, 0x7C, 0xA4, 0x31, 0xFE, 0x7D, 0xEC, 0x3B, 0x5D, 0xD2, 0xD4, 0x15, 0x6C, 0x86, 0xA5, 0x6C,
    //           0xDE, 0x93, 0x99, 0xDD, 0x9E, 0x60, 0x4E, 0x9E, 0x5B, 0x1F, 0x26, 0x03, 0x0A, 0x76, 0x31, 0xEC,

    let expected_kdf_prf_1 = [
        0xBB, 0x24, 0x9F, 0x67, 0xC5, 0xEE, 0x5E, 0xD1, 0x53, 0x50, 0x4E, 0x8E, 0x81, 0x69, 0xD8,
        0xC6, 0x51, 0x5B, 0x97, 0xE3, 0xC9, 0xA2, 0xF0, 0x2E, 0x4E, 0x35, 0x25, 0xC5, 0xF3, 0x67,
        0x49, 0xE2,
    ];

    let expected_kdf_prf_2 = [
        0xC9, 0x22, 0xF5, 0x6E, 0xEA, 0x75, 0x9C, 0x25, 0x15, 0x4A, 0x73, 0x3A, 0xB7, 0x89, 0x82,
        0x86, 0xC1, 0xA1, 0xFF, 0x91, 0x97, 0xE2, 0xAD, 0x31, 0xEF, 0x10, 0x14, 0x4F, 0xA0, 0xCE,
        0x9D, 0x2F,
    ];

    let expected_kdf_prf_3 = [
        0xF7, 0x4F, 0x68, 0xA1, 0x11, 0x66, 0x07, 0x86, 0xC1, 0xD0, 0x7F, 0xC0, 0xFF, 0x81, 0x3A,
        0x3F, 0x2C, 0x7B, 0x28, 0xC7, 0x44, 0x79, 0x12, 0xEE, 0x4C, 0xCC, 0x91, 0xB4, 0x72, 0x7C,
        0x87, 0x6D, 0xB2, 0x7C, 0xA4, 0x31, 0xFE, 0x7D, 0xEC, 0x3B, 0x5D, 0xD2, 0xD4, 0x15, 0x6C,
        0x86, 0xA5, 0x6C, 0xDE, 0x93, 0x99, 0xDD, 0x9E, 0x60, 0x4E, 0x9E, 0x5B, 0x1F, 0x26, 0x03,
        0x0A, 0x76, 0x31, 0xEC,
    ];

    let device = test_setup();

    let is_proper_dev_type: bool = !(device.get_device_type() != AtcaDeviceType::ATECC608A);
    let mut chip_is_locked: bool = true;

    let mut expected_bad_result = AtcaStatus::AtcaBadParam;
    let mut decrypt_result = AtcaStatus::AtcaUnknown;
    let mut kdf_message: Vec<u8> = Vec::new();

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_bad_result = AtcaStatus::AtcaNotLocked;
    }

    let prf_details_1 = PrfDetails {
        key_length: KdfPrfKeyLen::Len32,
        target_length: KdfPrfTargetLen::Len32,
    };
    let prf_details_2 = PrfDetails {
        key_length: KdfPrfKeyLen::Len32,
        ..Default::default()
    };

    let algorithm_1: KdfAlgorithm = KdfAlgorithm::Prf(prf_details_1);
    let algorithm_2: KdfAlgorithm = KdfAlgorithm::Prf(prf_details_2);

    let parameters_1 = KdfParams {
        source: KdfSource::TempKey,
        target: KdfTarget::TempKey,
        ..Default::default()
    };
    let parameters_2 = KdfParams {
        source: KdfSource::TempKey,
        target: KdfTarget::Output,
        ..Default::default()
    };
    let parameters_3 = KdfParams {
        source: KdfSource::TempKey,
        target: KdfTarget::Slot,
        target_slot_id: Some(TEST_KEY_SLOT_IDX),
        ..Default::default()
    };
    let parameters_4 = KdfParams {
        source: KdfSource::Slot,
        target: KdfTarget::TempKeyUp,
        source_slot_id: Some(TEST_KEY_SLOT_IDX),
        ..Default::default()
    };
    let parameters_5 = KdfParams {
        source: KdfSource::TempKeyUp,
        target: KdfTarget::AltKeyBuf,
        ..Default::default()
    };
    let parameters_6 = KdfParams {
        source: KdfSource::AltKeyBuf,
        target: KdfTarget::OutputEnc,
        ..Default::default()
    };

    let nonce_result_1 = device.nonce(NonceTarget::TempKey, &test_key);
    let result_1 = device.kdf(
        algorithm_1.clone(),
        parameters_1,
        Some(&message[..SHORT_MESSAGE_LEN]),
        SHORT_MESSAGE_LEN,
    );
    let result_2 = device.kdf(
        algorithm_1.clone(),
        parameters_2.clone(),
        Some(&message[..SHORT_MESSAGE_LEN]),
        SHORT_MESSAGE_LEN,
    );

    let nonce_result_2 = device.nonce(NonceTarget::TempKey, &test_key);
    let result_3 = device.kdf(
        algorithm_1.clone(),
        parameters_2,
        Some(&message[..SHORT_MESSAGE_LEN]),
        SHORT_MESSAGE_LEN,
    );
    let result_4 = device.kdf(
        algorithm_1.clone(),
        parameters_3,
        Some(&message[..SHORT_MESSAGE_LEN]),
        SHORT_MESSAGE_LEN,
    );
    let result_5 = device.kdf(
        algorithm_1.clone(),
        parameters_4,
        Some(&message[..SHORT_MESSAGE_LEN]),
        SHORT_MESSAGE_LEN,
    );
    let result_6 = device.kdf(
        algorithm_1,
        parameters_5,
        Some(&message[..SHORT_MESSAGE_LEN]),
        SHORT_MESSAGE_LEN,
    );
    let result_7 = device.kdf(algorithm_2, parameters_6, Some(&message), message.len());

    if result_7.is_ok() {
        kdf_message = result_7.clone().unwrap().out_data.unwrap();
        let nonce: Vec<u8> = result_7.clone().unwrap().out_nonce.unwrap();
        decrypt_result = io_decrypt(&device, &mut kdf_message, &nonce);
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(nonce_result_1, AtcaStatus::AtcaSuccess);
    assert_eq!(nonce_result_2, AtcaStatus::AtcaSuccess);
    if is_proper_dev_type && chip_is_locked {
        assert!(result_1.is_ok());
        assert!(result_2.is_ok());
        assert_eq!(result_2.unwrap().out_data.unwrap(), expected_kdf_prf_1);
        assert!(result_3.is_ok());
        assert_eq!(result_3.unwrap().out_data.unwrap(), expected_kdf_prf_2);
        assert!(result_4.is_ok());
        assert!(result_5.is_ok());
        assert!(result_6.is_ok());
        assert!(result_7.is_ok());
        assert_eq!(decrypt_result, AtcaStatus::AtcaSuccess);
        assert_eq!(kdf_message, expected_kdf_prf_3.to_vec());
    } else {
        assert_eq!(result_1.err().unwrap(), expected_bad_result);
        assert_eq!(result_2.err().unwrap(), expected_bad_result);
        assert_eq!(result_3.err().unwrap(), expected_bad_result);
        assert_eq!(result_4.err().unwrap(), expected_bad_result);
        assert_eq!(result_5.err().unwrap(), expected_bad_result);
        assert_eq!(result_6.err().unwrap(), expected_bad_result);
        assert_eq!(result_7.err().unwrap(), expected_bad_result);
    }
}

#[test]
#[serial]
fn kdf_prf_bad_data() {
    const MESSAGE_TOO_LONG: usize = ATCA_KDF_MAX_MSG_SIZE + 1;
    const SLOT_ID_TOO_LOW: u8 = 0x01;
    const SLOT_ID_OK: u8 = 0x09;
    const SLOT_ID_INVALID: u8 = 0x0D;

    let device = test_setup();

    let is_proper_dev_type: bool = !(device.get_device_type() != AtcaDeviceType::ATECC608A);
    let mut chip_is_locked: bool = true;

    let mut expected_bad_result = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_bad_result = AtcaStatus::AtcaNotLocked;
    }

    let prf_details_1 = PrfDetails {
        ..Default::default()
    };
    let prf_details_2 = PrfDetails {
        key_length: KdfPrfKeyLen::Len48,
        ..Default::default()
    };

    let algorithm_1: KdfAlgorithm = KdfAlgorithm::Prf(prf_details_1);
    let algorithm_2: KdfAlgorithm = KdfAlgorithm::Prf(prf_details_2);

    let parameters_1 = KdfParams {
        ..Default::default()
    };
    let parameters_2 = KdfParams {
        source: KdfSource::Slot,
        source_slot_id: Some(SLOT_ID_TOO_LOW),
        ..Default::default()
    };
    let parameters_3 = KdfParams {
        source: KdfSource::Slot,
        source_slot_id: Some(ATCA_ATECC_SLOTS_COUNT),
        ..Default::default()
    };
    let parameters_4 = KdfParams {
        source_slot_id: Some(SLOT_ID_OK),
        ..Default::default()
    };
    let parameters_5 = KdfParams {
        source: KdfSource::Slot,
        ..Default::default()
    };
    let parameters_6 = KdfParams {
        target: KdfTarget::Slot,
        target_slot_id: Some(SLOT_ID_TOO_LOW),
        ..Default::default()
    };
    let parameters_7 = KdfParams {
        target: KdfTarget::Slot,
        target_slot_id: Some(ATCA_ATECC_SLOTS_COUNT),
        ..Default::default()
    };
    let parameters_8 = KdfParams {
        target: KdfTarget::Slot,
        target_slot_id: Some(SLOT_ID_INVALID),
        ..Default::default()
    };
    let parameters_9 = KdfParams {
        target_slot_id: Some(SLOT_ID_OK),
        ..Default::default()
    };
    let parameters_10 = KdfParams {
        target: KdfTarget::Slot,
        ..Default::default()
    };
    let parameters_11 = KdfParams {
        source: KdfSource::TempKeyUp,
        ..Default::default()
    };
    let parameters_12 = KdfParams {
        source: KdfSource::AltKeyBuf,
        ..Default::default()
    };
    let parameters_13 = KdfParams {
        target: KdfTarget::TempKeyUp,
        ..Default::default()
    };
    let parameters_14 = KdfParams {
        target: KdfTarget::AltKeyBuf,
        ..Default::default()
    };

    let nonce_result = device.nonce(NonceTarget::TempKey, &[0x00; ATCA_BLOCK_SIZE]);

    // algorithm PRF, message length > ATCA_KDF_MAX_MSG_SIZE
    let bad_result_1 = device.kdf(
        algorithm_1.clone(),
        parameters_1.clone(),
        Some(&[0x00; MESSAGE_TOO_LONG]),
        MESSAGE_TOO_LONG,
    );

    // algorithm PRF, no message
    let bad_result_2 = device.kdf(algorithm_1.clone(), parameters_1, None, ATCA_BLOCK_SIZE);

    // algorithm PRF, source slot will not hold required amount of data
    let bad_result_3 = device.kdf(
        algorithm_2.clone(),
        parameters_2,
        Some(&[0x00; ATCA_BLOCK_SIZE]),
        ATCA_BLOCK_SIZE,
    );

    // algorithm PRF, source slot ID too high
    let bad_result_4 = device.kdf(
        algorithm_1.clone(),
        parameters_3,
        Some(&[0x00; ATCA_BLOCK_SIZE]),
        ATCA_BLOCK_SIZE,
    );

    // algorithm PRF, source not in slot, but slot ID was passed
    let bad_result_5 = device.kdf(
        algorithm_1.clone(),
        parameters_4,
        Some(&[0x00; ATCA_BLOCK_SIZE]),
        ATCA_BLOCK_SIZE,
    );

    // algorithm PRF, source slot ID was not passed
    let bad_result_6 = device.kdf(
        algorithm_1.clone(),
        parameters_5,
        Some(&[0x00; ATCA_BLOCK_SIZE]),
        ATCA_BLOCK_SIZE,
    );

    // algorithm PRF, target slot will not hold required amount of data
    let bad_result_7 = device.kdf(
        algorithm_2.clone(),
        parameters_6,
        Some(&[0x00; ATCA_BLOCK_SIZE]),
        ATCA_BLOCK_SIZE,
    );

    // algorithm PRF, target slot ID too high
    let bad_result_8 = device.kdf(
        algorithm_1.clone(),
        parameters_7,
        Some(&[0x00; ATCA_BLOCK_SIZE]),
        ATCA_BLOCK_SIZE,
    );

    // algorithm PRF, invalid target slot ID
    let bad_result_9 = device.kdf(
        algorithm_1.clone(),
        parameters_8,
        Some(&[0x00; ATCA_BLOCK_SIZE]),
        ATCA_BLOCK_SIZE,
    );

    // algorithm PRF, target not in slot, but slot ID was passed
    let bad_result_10 = device.kdf(
        algorithm_1.clone(),
        parameters_9,
        Some(&[0x00; ATCA_BLOCK_SIZE]),
        ATCA_BLOCK_SIZE,
    );

    // algorithm PRF, target slot ID was not passed
    let bad_result_11 = device.kdf(
        algorithm_1.clone(),
        parameters_10,
        Some(&[0x00; ATCA_BLOCK_SIZE]),
        ATCA_BLOCK_SIZE,
    );

    // algorithm PRF, source is TempKeyUp and keyLen = 48
    let bad_result_12 = device.kdf(
        algorithm_2.clone(),
        parameters_11,
        Some(&[0x00; ATCA_BLOCK_SIZE]),
        ATCA_BLOCK_SIZE,
    );

    // algorithm PRF, source is AltKeyBuf and keyLen = 48
    let bad_result_13 = device.kdf(
        algorithm_2,
        parameters_12,
        Some(&[0x00; ATCA_BLOCK_SIZE]),
        ATCA_BLOCK_SIZE,
    );

    // algorithm PRF, target is TempKeyUp (capacity 32B) and targetLen = 64
    let bad_result_14 = device.kdf(
        algorithm_1.clone(),
        parameters_13,
        Some(&[0x00; ATCA_BLOCK_SIZE]),
        ATCA_BLOCK_SIZE,
    );

    // algorithm PRF, target is AltKeyBuf (capacity 32B) and targetLen = 64
    let bad_result_15 = device.kdf(
        algorithm_1,
        parameters_14,
        Some(&[0x00; ATCA_BLOCK_SIZE]),
        ATCA_BLOCK_SIZE,
    );

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(nonce_result, AtcaStatus::AtcaSuccess);
    if is_proper_dev_type && chip_is_locked {
        assert!(bad_result_1.is_err());
        assert_eq!(bad_result_1.err().unwrap(), AtcaStatus::AtcaInvalidSize);
        assert!(bad_result_2.is_err());
        assert_eq!(bad_result_2.err().unwrap(), AtcaStatus::AtcaBadParam);
        assert!(bad_result_3.is_err());
        assert_eq!(bad_result_3.err().unwrap(), AtcaStatus::AtcaBadParam);
        assert!(bad_result_4.is_err());
        assert_eq!(bad_result_4.err().unwrap(), AtcaStatus::AtcaInvalidId);
        assert!(bad_result_5.is_err());
        assert_eq!(bad_result_5.err().unwrap(), AtcaStatus::AtcaBadParam);
        assert!(bad_result_6.is_err());
        assert_eq!(bad_result_6.err().unwrap(), AtcaStatus::AtcaInvalidId);
        assert!(bad_result_7.is_err());
        assert_eq!(bad_result_7.err().unwrap(), AtcaStatus::AtcaBadParam);
        assert!(bad_result_8.is_err());
        assert_eq!(bad_result_8.err().unwrap(), AtcaStatus::AtcaInvalidId);
        assert!(bad_result_9.is_err());
        assert_eq!(bad_result_9.err().unwrap(), AtcaStatus::AtcaBadParam);
        assert!(bad_result_10.is_err());
        assert_eq!(bad_result_10.err().unwrap(), AtcaStatus::AtcaBadParam);
        assert!(bad_result_11.is_err());
        assert_eq!(bad_result_11.err().unwrap(), AtcaStatus::AtcaInvalidId);
        assert!(bad_result_12.is_err());
        assert_eq!(bad_result_12.err().unwrap(), AtcaStatus::AtcaBadParam);
        assert!(bad_result_13.is_err());
        assert_eq!(bad_result_13.err().unwrap(), AtcaStatus::AtcaBadParam);
        assert!(bad_result_14.is_err());
        assert_eq!(bad_result_14.err().unwrap(), AtcaStatus::AtcaBadParam);
        assert!(bad_result_15.is_err());
        assert_eq!(bad_result_15.err().unwrap(), AtcaStatus::AtcaBadParam);
    } else {
        assert_eq!(bad_result_1.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_2.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_3.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_4.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_5.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_6.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_7.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_8.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_9.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_10.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_11.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_12.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_13.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_14.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_15.err().unwrap(), expected_bad_result);
    }
}

#[test]
#[serial]
fn kdf_hkdf_proper_data() {
    const TEST_KEY_SLOT_IDX: u8 = 0x09;
    const TEST_MESSAGE_SLOT_IDX: u8 = 0x0A;
    const SHORT_MESSAGE_LEN: usize = 0x10;

    // message => IKM in RFC 5869
    let message = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E,
        0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D,
        0x5E, 0x5F,
    ];

    let message_alt = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];

    let message_with_special_iv = [
        0x69, 0x76, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E,
        0x4F,
    ];

    // test_key => salt in RFC 5869
    let test_key = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
        0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
        0x3E, 0x3F,
    ];

    // expected values can be calculated using the hmac module from Python => hmac.digest(key, message, "sha256")

    let expected_kdf_hkdf_1 = [
        0xFC, 0x70, 0xF7, 0xE8, 0x5F, 0x89, 0xEC, 0xCB, 0xCC, 0x95, 0x8D, 0x2D, 0x3C, 0xCF, 0x94,
        0xF5, 0xBD, 0xD3, 0x3C, 0x64, 0xCB, 0x20, 0xA9, 0xC7, 0x86, 0x8D, 0xFE, 0xFD, 0x5A, 0xFB,
        0x7E, 0xC5,
    ];

    let expected_kdf_hkdf_2 = [
        0x39, 0x91, 0x6A, 0x9A, 0xF1, 0xF0, 0x82, 0x07, 0xF8, 0xE0, 0xA7, 0x87, 0xDA, 0x9C, 0x8B,
        0xB7, 0x43, 0x77, 0xD3, 0x5A, 0xF4, 0xD7, 0x61, 0x9F, 0x13, 0xE8, 0x10, 0x1D, 0x08, 0xC9,
        0x8C, 0x9C,
    ];

    let expected_kdf_hkdf_3 = [
        0x14, 0x65, 0xD1, 0xDF, 0xA1, 0xA9, 0x2A, 0x78, 0xAF, 0xC2, 0xA1, 0x66, 0x2A, 0x3B, 0x30,
        0x24, 0x5F, 0x58, 0x4D, 0x00, 0x68, 0xE4, 0x75, 0x06, 0xC5, 0x22, 0x3F, 0xB6, 0xEF, 0x96,
        0x20, 0x22,
    ];

    let expected_kdf_hkdf_4 = [
        0x46, 0xBD, 0x32, 0x06, 0x05, 0xC5, 0xA6, 0xB6, 0x16, 0x3A, 0xB7, 0x0B, 0xC6, 0x34, 0x5B,
        0x92, 0xA5, 0xF9, 0x08, 0xE7, 0x9F, 0xE5, 0x89, 0x79, 0xC2, 0x3E, 0xBB, 0x47, 0xD1, 0xA5,
        0xE3, 0x07,
    ];

    let expected_kdf_hkdf_5 = [
        0xA2, 0x7B, 0x86, 0xE7, 0xA7, 0x0A, 0x02, 0x9C, 0xBA, 0x77, 0x8D, 0x6F, 0x73, 0x8D, 0x95,
        0x26, 0x96, 0xD6, 0xD8, 0x36, 0x1B, 0x95, 0x10, 0x3D, 0xD8, 0x4A, 0xE9, 0xDF, 0x6A, 0xF0,
        0x63, 0xAF,
    ];

    let expected_kdf_hkdf_6 = [
        0x77, 0xF1, 0x99, 0x3F, 0x03, 0x1E, 0x84, 0x84, 0x1F, 0x1C, 0x18, 0xFA, 0x16, 0x0A, 0x44,
        0x0D, 0x25, 0x7E, 0xCA, 0xF9, 0x0A, 0xF8, 0xEB, 0x08, 0x76, 0xF0, 0xE8, 0xFE, 0xB4, 0x88,
        0x8D, 0x94,
    ];

    let device = test_setup();

    let is_proper_dev_type: bool = !(device.get_device_type() != AtcaDeviceType::ATECC608A);
    let mut chip_is_locked: bool = true;

    let mut expected_bad_result = AtcaStatus::AtcaBadParam;
    let mut decrypt_result = AtcaStatus::AtcaUnknown;
    let mut kdf_message: Vec<u8> = Vec::new();

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_bad_result = AtcaStatus::AtcaNotLocked;
    }

    let hkdf_details_1 = HkdfDetails {
        msg_loc: HkdfMsgLoc::Iv,
        ..Default::default()
    };
    let hkdf_details_2 = HkdfDetails {
        zero_key: true,
        ..Default::default()
    };
    let hkdf_details_3 = HkdfDetails {
        msg_loc: HkdfMsgLoc::TempKey,
        zero_key: true,
        ..Default::default()
    };
    let hkdf_details_4 = HkdfDetails {
        msg_loc: HkdfMsgLoc::Slot,
        msg_slot: Some(TEST_MESSAGE_SLOT_IDX),
        ..Default::default()
    };
    let hkdf_details_5 = HkdfDetails {
        ..Default::default()
    };

    let algorithm_1: KdfAlgorithm = KdfAlgorithm::Hkdf(hkdf_details_1);
    let algorithm_2: KdfAlgorithm = KdfAlgorithm::Hkdf(hkdf_details_2);
    let algorithm_3: KdfAlgorithm = KdfAlgorithm::Hkdf(hkdf_details_3);
    let algorithm_4: KdfAlgorithm = KdfAlgorithm::Hkdf(hkdf_details_4);
    let algorithm_5: KdfAlgorithm = KdfAlgorithm::Hkdf(hkdf_details_5);

    let parameters_1 = KdfParams {
        source: KdfSource::TempKey,
        target: KdfTarget::TempKey,
        ..Default::default()
    };
    let parameters_2 = KdfParams {
        source: KdfSource::TempKey,
        target: KdfTarget::Output,
        ..Default::default()
    };
    let parameters_3 = KdfParams {
        source: KdfSource::TempKey,
        target: KdfTarget::Slot,
        target_slot_id: Some(TEST_KEY_SLOT_IDX),
        ..Default::default()
    };
    let parameters_4 = KdfParams {
        source: KdfSource::Slot,
        target: KdfTarget::TempKeyUp,
        source_slot_id: Some(TEST_KEY_SLOT_IDX),
        ..Default::default()
    };
    let parameters_5 = KdfParams {
        source: KdfSource::TempKeyUp,
        target: KdfTarget::AltKeyBuf,
        ..Default::default()
    };
    let parameters_6 = KdfParams {
        source: KdfSource::AltKeyBuf,
        target: KdfTarget::OutputEnc,
        ..Default::default()
    };

    let nonce_result_1 = device.nonce(NonceTarget::TempKey, &test_key);
    let result_1 = device.kdf(
        algorithm_5.clone(),
        parameters_1,
        Some(&message[..SHORT_MESSAGE_LEN]),
        SHORT_MESSAGE_LEN,
    );
    let result_2 = device.kdf(
        algorithm_5.clone(),
        parameters_2.clone(),
        Some(&message[..SHORT_MESSAGE_LEN]),
        SHORT_MESSAGE_LEN,
    );

    let nonce_result_2 = device.nonce(NonceTarget::TempKey, &test_key);
    let result_3 = device.kdf(
        algorithm_1,
        parameters_2.clone(),
        Some(&message_with_special_iv),
        message_with_special_iv.len(),
    );
    let result_4 = device.kdf(
        algorithm_2,
        parameters_2.clone(),
        Some(&message),
        message.len(),
    );
    let nonce_result_3 = device.nonce(NonceTarget::TempKey, &message_alt);
    let result_5 = device.kdf(algorithm_3, parameters_2.clone(), None, message_alt.len());
    let nonce_result_4 = device.nonce(NonceTarget::TempKey, &test_key);
    let msg_to_slot_result =
        device.import_key(KeyType::ShaOrText, &message_alt, TEST_MESSAGE_SLOT_IDX);
    let result_6 = device.kdf(algorithm_4, parameters_2, None, message_alt.len());
    let result_7 = device.kdf(
        algorithm_5.clone(),
        parameters_3,
        Some(&message[..SHORT_MESSAGE_LEN]),
        SHORT_MESSAGE_LEN,
    );
    let result_8 = device.kdf(
        algorithm_5.clone(),
        parameters_4,
        Some(&message[..SHORT_MESSAGE_LEN]),
        SHORT_MESSAGE_LEN,
    );
    let result_9 = device.kdf(
        algorithm_5.clone(),
        parameters_5,
        Some(&message[..SHORT_MESSAGE_LEN]),
        SHORT_MESSAGE_LEN,
    );
    let result_10 = device.kdf(algorithm_5, parameters_6, Some(&message), message.len());

    if result_10.is_ok() {
        kdf_message = result_10.clone().unwrap().out_data.unwrap();
        let nonce: Vec<u8> = result_10.clone().unwrap().out_nonce.unwrap();
        decrypt_result = io_decrypt(&device, &mut kdf_message, &nonce);
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(nonce_result_1, AtcaStatus::AtcaSuccess);
    assert_eq!(nonce_result_2, AtcaStatus::AtcaSuccess);
    assert_eq!(nonce_result_3, AtcaStatus::AtcaSuccess);
    assert_eq!(nonce_result_4, AtcaStatus::AtcaSuccess);
    if is_proper_dev_type && chip_is_locked {
        assert!(result_1.is_ok());
        assert!(result_2.is_ok());
        assert_eq!(
            result_2.unwrap().out_data.unwrap(),
            expected_kdf_hkdf_1.to_vec()
        );
        assert!(result_3.is_ok());
        assert_eq!(
            result_3.unwrap().out_data.unwrap(),
            expected_kdf_hkdf_2.to_vec()
        );
        assert!(result_4.is_ok());
        assert_eq!(
            result_4.unwrap().out_data.unwrap(),
            expected_kdf_hkdf_3.to_vec()
        );
        assert!(result_5.is_ok());
        assert_eq!(
            result_5.unwrap().out_data.unwrap(),
            expected_kdf_hkdf_4.to_vec()
        );
        assert_eq!(msg_to_slot_result, AtcaStatus::AtcaSuccess);
        assert!(result_6.is_ok());
        assert_eq!(
            result_6.unwrap().out_data.unwrap(),
            expected_kdf_hkdf_5.to_vec()
        );
        assert!(result_7.is_ok());
        assert!(result_8.is_ok());
        assert!(result_9.is_ok());
        assert!(result_10.is_ok());
        assert_eq!(decrypt_result, AtcaStatus::AtcaSuccess);
        assert_eq!(kdf_message, expected_kdf_hkdf_6.to_vec());
    } else {
        assert_eq!(result_1.err().unwrap(), expected_bad_result);
        assert_eq!(result_2.err().unwrap(), expected_bad_result);
        assert_eq!(result_3.err().unwrap(), expected_bad_result);
        assert_eq!(result_4.err().unwrap(), expected_bad_result);
        assert_eq!(result_5.err().unwrap(), expected_bad_result);
        assert_eq!(result_6.err().unwrap(), expected_bad_result);
        assert_eq!(result_7.err().unwrap(), expected_bad_result);
        assert_eq!(result_8.err().unwrap(), expected_bad_result);
        assert_eq!(result_9.err().unwrap(), expected_bad_result);
        assert_eq!(result_10.err().unwrap(), expected_bad_result);
    }
}

#[test]
#[serial]
fn kdf_hkdf_bad_data() {
    const MESSAGE_SLOT_ID: u8 = 0x01;

    let message_with_special_iv_bad_value = [
        0x69, 0x75, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    let message_with_special_iv_bad_size = [0x69];

    let device = test_setup();

    let is_proper_dev_type: bool = !(device.get_device_type() != AtcaDeviceType::ATECC608A);
    let mut chip_is_locked: bool = true;

    let mut expected_bad_result = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_bad_result = AtcaStatus::AtcaNotLocked;
    }

    let hkdf_details_1 = HkdfDetails {
        ..Default::default()
    };
    let hkdf_details_2 = HkdfDetails {
        msg_loc: HkdfMsgLoc::Iv,
        ..Default::default()
    };
    let hkdf_details_3 = HkdfDetails {
        msg_loc: HkdfMsgLoc::TempKey,
        ..Default::default()
    };
    let hkdf_details_4 = HkdfDetails {
        msg_loc: HkdfMsgLoc::Slot,
        msg_slot: Some(MESSAGE_SLOT_ID),
        ..Default::default()
    };
    let hkdf_details_5 = HkdfDetails {
        msg_loc: HkdfMsgLoc::Slot,
        msg_slot: Some(ATCA_ATECC_SLOTS_COUNT),
        ..Default::default()
    };
    let hkdf_details_6 = HkdfDetails {
        msg_loc: HkdfMsgLoc::Slot,
        ..Default::default()
    };

    let algorithm_1: KdfAlgorithm = KdfAlgorithm::Hkdf(hkdf_details_1);
    let algorithm_2: KdfAlgorithm = KdfAlgorithm::Hkdf(hkdf_details_2);
    let algorithm_3: KdfAlgorithm = KdfAlgorithm::Hkdf(hkdf_details_3);
    let algorithm_4: KdfAlgorithm = KdfAlgorithm::Hkdf(hkdf_details_4);
    let algorithm_5: KdfAlgorithm = KdfAlgorithm::Hkdf(hkdf_details_5);
    let algorithm_6: KdfAlgorithm = KdfAlgorithm::Hkdf(hkdf_details_6);

    let parameters_1 = KdfParams {
        source: KdfSource::TempKey,
        target: KdfTarget::Output,
        ..Default::default()
    };

    let parameters_2 = KdfParams {
        source: KdfSource::TempKey,
        target: KdfTarget::TempKey,
        ..Default::default()
    };

    let nonce_result = device.nonce(NonceTarget::TempKey, &[0x00; ATCA_BLOCK_SIZE]);

    // algorithm HKDF, message source is "Input" and no message was passed
    let bad_result_1 = device.kdf(algorithm_1, parameters_1.clone(), None, ATCA_BLOCK_SIZE);

    // algorithm HKDF, message source is "IV" and no message was passed
    let bad_result_2 = device.kdf(
        algorithm_2.clone(),
        parameters_1.clone(),
        None,
        ATCA_BLOCK_SIZE,
    );

    // algorithm HKDF, message source is "IV" and message with bad IV value was passed
    let bad_result_3 = device.kdf(
        algorithm_2.clone(),
        parameters_1.clone(),
        Some(&message_with_special_iv_bad_value),
        message_with_special_iv_bad_value.len(),
    );

    // algorithm HKDF, message source is "IV" and message with bad IV value was passed
    let bad_result_4 = device.kdf(
        algorithm_2,
        parameters_1.clone(),
        Some(&message_with_special_iv_bad_size),
        message_with_special_iv_bad_size.len(),
    );

    // algorithm HKDF, KdfSource, KdfTarget and message source are "TempKey"
    let bad_result_5 = device.kdf(
        algorithm_3.clone(),
        parameters_2,
        Some(&[0x00; ATCA_BLOCK_SIZE]),
        ATCA_BLOCK_SIZE,
    );

    // algorithm HKDF, message source is a "Slot" but indicated message length is greater than slot capacity
    let bad_result_6 = device.kdf(
        algorithm_4,
        parameters_1.clone(),
        None,
        (device.get_slot_capacity(MESSAGE_SLOT_ID).bytes + 1) as usize,
    );

    // algorithm HKDF, message source is a "Slot" but slot ID is too high
    let bad_result_7 = device.kdf(algorithm_5, parameters_1.clone(), None, ATCA_BLOCK_SIZE);

    // algorithm HKDF, message source is a "Slot" but slot ID was not passed
    let bad_result_8 = device.kdf(algorithm_6, parameters_1.clone(), None, ATCA_BLOCK_SIZE);

    // algorithm HKDF, message source is a "TempKey" but indicated message length is greater than TempKey capacity
    let bad_result_9 = device.kdf(algorithm_3, parameters_1, None, 65);

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(nonce_result, AtcaStatus::AtcaSuccess);
    if is_proper_dev_type && chip_is_locked {
        assert!(bad_result_1.is_err());
        assert_eq!(bad_result_1.err().unwrap(), AtcaStatus::AtcaBadParam);
        assert!(bad_result_2.is_err());
        assert_eq!(bad_result_2.err().unwrap(), AtcaStatus::AtcaBadParam);
        assert!(bad_result_3.is_err());
        assert_eq!(bad_result_3.err().unwrap(), AtcaStatus::AtcaBadParam);
        assert!(bad_result_4.is_err());
        assert_eq!(bad_result_4.err().unwrap(), AtcaStatus::AtcaBadParam);
        assert!(bad_result_5.is_err());
        assert_eq!(bad_result_5.err().unwrap(), AtcaStatus::AtcaBadParam);
        assert!(bad_result_6.is_err());
        assert_eq!(bad_result_6.err().unwrap(), AtcaStatus::AtcaInvalidSize);
        assert!(bad_result_7.is_err());
        assert_eq!(bad_result_7.err().unwrap(), AtcaStatus::AtcaInvalidSize);
        assert!(bad_result_8.is_err());
        assert_eq!(bad_result_8.err().unwrap(), AtcaStatus::AtcaBadParam);
        assert!(bad_result_9.is_err());
        assert_eq!(bad_result_9.err().unwrap(), AtcaStatus::AtcaInvalidSize);
    } else {
        assert_eq!(bad_result_1.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_2.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_3.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_4.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_5.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_6.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_7.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_8.err().unwrap(), expected_bad_result);
        assert_eq!(bad_result_9.err().unwrap(), expected_bad_result);
    }
}
