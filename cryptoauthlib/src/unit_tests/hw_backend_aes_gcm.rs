// Types
use super::{AeadAlgorithm, AeadParam, AtcaStatus, KeyType};
// Constants
use super::{
    ATCA_AES_DATA_SIZE, ATCA_AES_GCM_IV_STD_LENGTH, ATCA_AES_KEY_SIZE, ATCA_ATECC_SLOTS_COUNT,
};

use super::hw_backend_common::*;
use serial_test::serial;

#[test]
#[serial]
fn aead_gcm_encrypt_proper_data() {
    const DATA_64_SIZE: usize = 64;
    const DATA_60_SIZE: usize = 60;
    const AAD_20_SIZE: usize = 20;
    const SHORT_TAG_SIZE: usize = 12;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    // Test Vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf
    let aes_key = [
        0xFE, 0xFF, 0xE9, 0x92, 0x86, 0x65, 0x73, 0x1C, 0x6D, 0x6A, 0x8F, 0x94, 0x67, 0x30, 0x83,
        0x08,
    ];
    let iv = [
        0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88,
    ];
    let plain_text = [
        0xD9, 0x31, 0x32, 0x25, 0xF8, 0x84, 0x06, 0xE5, 0xA5, 0x59, 0x09, 0xC5, 0xAF, 0xF5, 0x26,
        0x9A, 0x86, 0xA7, 0xA9, 0x53, 0x15, 0x34, 0xF7, 0xDA, 0x2E, 0x4C, 0x30, 0x3D, 0x8A, 0x31,
        0x8A, 0x72, 0x1C, 0x3C, 0x0C, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2F, 0xCF, 0x0E, 0x24, 0x49,
        0xA6, 0xB5, 0x25, 0xB1, 0x6A, 0xED, 0xF5, 0xAA, 0x0D, 0xE6, 0x57, 0xBA, 0x63, 0x7B, 0x39,
        0x1A, 0xAF, 0xD2, 0x55,
    ];
    let cipher_text = [
        0x42, 0x83, 0x1E, 0xC2, 0x21, 0x77, 0x74, 0x24, 0x4B, 0x72, 0x21, 0xB7, 0x84, 0xD0, 0xD4,
        0x9C, 0xE3, 0xAA, 0x21, 0x2F, 0x2C, 0x02, 0xA4, 0xE0, 0x35, 0xC1, 0x7E, 0x23, 0x29, 0xAC,
        0xA1, 0x2E, 0x21, 0xD5, 0x14, 0xB2, 0x54, 0x66, 0x93, 0x1C, 0x7D, 0x8F, 0x6A, 0x5A, 0xAC,
        0x84, 0xAA, 0x05, 0x1B, 0xA3, 0x0B, 0x39, 0x6A, 0x0A, 0xAC, 0x97, 0x3D, 0x58, 0xE0, 0x91,
        0x47, 0x3F, 0x59, 0x85,
    ];
    let aad = [
        0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF,
        0x97, 0xF5, 0xD3, 0xD5, 0x85, 0x03, 0xB9, 0x69, 0x9D, 0xE7, 0x85, 0x89, 0x5A, 0x96, 0xFD,
        0xBA, 0xAF, 0x43, 0xB1, 0xCD, 0x7F, 0x59, 0x8E, 0xCE, 0x23, 0x88, 0x1B, 0x00, 0xE3, 0xED,
        0x03, 0x06, 0x88, 0x7B, 0x0C, 0x78, 0x5E, 0x27, 0xE8, 0xAD, 0x3F, 0x82, 0x23, 0x20, 0x71,
        0x04, 0x72, 0x5D, 0xD4,
    ];

    let tag_64_no_aad = [
        0x4D, 0x5C, 0x2A, 0xF3, 0x27, 0xCD, 0x64, 0xA6, 0x2C, 0xF3, 0x5A, 0xBD, 0x2B, 0xA6, 0xFA,
        0xB4,
    ];

    let tag_64_no_text = [
        0x5F, 0x91, 0xD7, 0x71, 0x23, 0xEF, 0x5E, 0xB9, 0x99, 0x79, 0x13, 0x84, 0x9B, 0x8D, 0xC1,
        0xE9,
    ];

    let tag_64 = [
        0x64, 0xC0, 0x23, 0x29, 0x04, 0xAF, 0x39, 0x8A, 0x5B, 0x67, 0xC1, 0x0B, 0x53, 0xA5, 0x02,
        0x4D,
    ];

    let tag_60 = [
        0xF0, 0x7C, 0x25, 0x28, 0xEE, 0xA2, 0xFC, 0xA1, 0x21, 0x1F, 0x90, 0x5E, 0x1B, 0x6A, 0x88,
        0x1B,
    ];

    let param_64_no_aad = AeadParam {
        key: Some(aes_key),
        nonce: iv.to_vec(),
        ..Default::default()
    };
    let param_64 = AeadParam {
        key: Some(aes_key),
        nonce: iv.to_vec(),
        additional_data: Some(aad.to_vec()),
        ..Default::default()
    };
    let param_64_internal_key = AeadParam {
        nonce: iv.to_vec(),
        additional_data: Some(aad.to_vec()),
        ..Default::default()
    };
    let param_60 = AeadParam {
        key: Some(aes_key),
        nonce: iv.to_vec(),
        additional_data: Some(aad[..AAD_20_SIZE].to_vec()),
        ..Default::default()
    };
    let param_60_short_tag = AeadParam {
        key: Some(aes_key),
        nonce: iv.to_vec(),
        additional_data: Some(aad[..AAD_20_SIZE].to_vec()),
        tag_length: Some(SHORT_TAG_SIZE as u8),
        ..Default::default()
    };
    let param_60_internal_key = AeadParam {
        nonce: iv.to_vec(),
        additional_data: Some(aad[..AAD_20_SIZE].to_vec()),
        ..Default::default()
    };

    let mut data_64_no_text: [u8; 0x00] = [0x00; 0x00];
    let mut data_64_no_aad: [u8; DATA_64_SIZE] = [0x00; DATA_64_SIZE];
    data_64_no_aad.clone_from_slice(&plain_text[..DATA_64_SIZE]);
    let mut data_64: [u8; DATA_64_SIZE] = [0x00; DATA_64_SIZE];
    data_64.clone_from_slice(&plain_text[..DATA_64_SIZE]);
    let mut data_60: [u8; DATA_60_SIZE] = [0x00; DATA_60_SIZE];
    data_60.clone_from_slice(&plain_text[..DATA_60_SIZE]);
    let mut data_60_short_tag: [u8; DATA_60_SIZE] = [0x00; DATA_60_SIZE];
    data_60_short_tag.clone_from_slice(&plain_text[..DATA_60_SIZE]);
    let mut data_64_internal_key: [u8; DATA_64_SIZE] = [0x00; DATA_64_SIZE];
    data_64_internal_key.clone_from_slice(&plain_text[..DATA_64_SIZE]);
    let mut data_60_internal_key: [u8; DATA_60_SIZE] = [0x00; DATA_60_SIZE];
    data_60_internal_key.clone_from_slice(&plain_text[..DATA_60_SIZE]);

    let mut result_tag_64_no_aad = vec![0x00; ATCA_AES_KEY_SIZE];
    let mut result_tag_64_no_text = vec![0x00; ATCA_AES_KEY_SIZE];
    let mut result_tag_64 = vec![0x00; ATCA_AES_KEY_SIZE];
    let mut result_tag_60 = vec![0x00; ATCA_AES_KEY_SIZE];
    let mut result_tag_60_short = vec![0x00; SHORT_TAG_SIZE];
    let mut result_tag_64_internal_key = vec![0x00; ATCA_AES_KEY_SIZE];
    let mut result_tag_60_internal_key = vec![0x00; ATCA_AES_KEY_SIZE];

    let mut expected_64_no_aad = AtcaStatus::AtcaBadParam;
    let mut expected_64_no_text = AtcaStatus::AtcaBadParam;
    let mut expected_64 = AtcaStatus::AtcaBadParam;
    let mut expected_60 = AtcaStatus::AtcaBadParam;
    let mut expected_60_short_tag = AtcaStatus::AtcaBadParam;
    let mut expected_64_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_60_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;
    let mut result_64_no_aad = AtcaStatus::AtcaUnknown;
    let mut result_64_no_text = AtcaStatus::AtcaUnknown;
    let mut result_64 = AtcaStatus::AtcaUnknown;
    let mut result_60 = AtcaStatus::AtcaUnknown;
    let mut result_60_short_tag = AtcaStatus::AtcaUnknown;
    let mut result_64_internal_key = AtcaStatus::AtcaUnknown;
    let mut result_60_internal_key = AtcaStatus::AtcaUnknown;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_64_no_aad = AtcaStatus::AtcaNotLocked;
        expected_64_no_text = AtcaStatus::AtcaNotLocked;
        expected_64 = AtcaStatus::AtcaNotLocked;
        expected_60 = AtcaStatus::AtcaNotLocked;
        expected_60_short_tag = AtcaStatus::AtcaNotLocked;
        expected_64_internal_key = AtcaStatus::AtcaNotLocked;
        expected_60_internal_key = AtcaStatus::AtcaNotLocked;
        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected_64_no_aad = AtcaStatus::AtcaSuccess;
        expected_64_no_text = AtcaStatus::AtcaSuccess;
        expected_64 = AtcaStatus::AtcaSuccess;
        expected_60 = AtcaStatus::AtcaSuccess;
        expected_60_short_tag = AtcaStatus::AtcaSuccess;
        expected_64_internal_key = AtcaStatus::AtcaSuccess;
        expected_60_internal_key = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;
        result_64_no_aad = AtcaStatus::AtcaSuccess;
        result_64_no_text = AtcaStatus::AtcaSuccess;
        result_64 = AtcaStatus::AtcaSuccess;
        result_60 = AtcaStatus::AtcaSuccess;
        result_60_short_tag = AtcaStatus::AtcaSuccess;
        result_64_internal_key = AtcaStatus::AtcaSuccess;
        result_60_internal_key = AtcaStatus::AtcaSuccess;
    }

    match device.aead_encrypt(
        AeadAlgorithm::Gcm(param_64_no_aad),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_64_no_aad,
    ) {
        Ok(tag) => result_tag_64_no_aad = tag,
        Err(err) => result_64_no_aad = err,
    }

    match device.aead_encrypt(
        AeadAlgorithm::Gcm(param_64.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_64_no_text,
    ) {
        Ok(tag) => result_tag_64_no_text = tag,
        Err(err) => result_64_no_text = err,
    }

    match device.aead_encrypt(
        AeadAlgorithm::Gcm(param_64),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_64,
    ) {
        Ok(tag) => result_tag_64 = tag,
        Err(err) => result_64 = err,
    }

    match device.aead_encrypt(
        AeadAlgorithm::Gcm(param_60),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_60,
    ) {
        Ok(tag) => result_tag_60 = tag,
        Err(err) => result_60 = err,
    }

    match device.aead_encrypt(
        AeadAlgorithm::Gcm(param_60_short_tag),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_60_short_tag,
    ) {
        Ok(tag) => result_tag_60_short = tag,
        Err(err) => result_60_short_tag = err,
    }

    match device.aead_encrypt(
        AeadAlgorithm::Gcm(param_64_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_64_internal_key,
    ) {
        Ok(tag) => result_tag_64_internal_key = tag,
        Err(err) => result_64_internal_key = err,
    }

    match device.aead_encrypt(
        AeadAlgorithm::Gcm(param_60_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_60_internal_key,
    ) {
        Ok(tag) => result_tag_60_internal_key = tag,
        Err(err) => result_60_internal_key = err,
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert_eq!(result_tag_64_no_aad, tag_64_no_aad);
        assert_eq!(data_64_no_aad.to_vec(), cipher_text.to_vec());
        assert_eq!(result_tag_64_no_text, tag_64_no_text);
        assert_eq!(data_64_no_text.is_empty(), true);
        assert_eq!(result_tag_64, tag_64);
        assert_eq!(data_64.to_vec(), cipher_text.to_vec());
        assert_eq!(result_tag_60, tag_60);
        assert_eq!(data_60.to_vec(), cipher_text[..DATA_60_SIZE].to_vec());
        assert_eq!(
            result_tag_60_short.to_vec(),
            tag_60[..SHORT_TAG_SIZE].to_vec()
        );
        assert_eq!(
            data_60_short_tag.to_vec(),
            cipher_text[..DATA_60_SIZE].to_vec()
        );
        assert_eq!(result_tag_64_internal_key, tag_64);
        assert_eq!(data_64_internal_key.to_vec(), cipher_text.to_vec());
        assert_eq!(result_tag_60_internal_key, tag_60);
        assert_eq!(
            data_60_internal_key.to_vec(),
            cipher_text[..DATA_60_SIZE].to_vec()
        );
    }
    assert_eq!(result_64_no_aad, expected_64_no_aad);
    assert_eq!(result_64_no_text, expected_64_no_text);
    assert_eq!(result_64, expected_64);
    assert_eq!(result_60, expected_60);
    assert_eq!(result_60_short_tag, expected_60_short_tag);
    assert_eq!(result_64_internal_key, expected_64_internal_key);
    assert_eq!(result_60_internal_key, expected_60_internal_key);
}

#[test]
#[serial]
fn aead_gcm_encrypt_bad_data() {
    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let mut data: [u8; ATCA_AES_DATA_SIZE] = [0x00; ATCA_AES_DATA_SIZE];
    let param_ok = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; ATCA_AES_GCM_IV_STD_LENGTH],
        additional_data: Some(vec![0x00; ATCA_AES_DATA_SIZE]),
        ..Default::default()
    };
    let param_bad_1 = AeadParam {
        nonce: vec![0x00; ATCA_AES_GCM_IV_STD_LENGTH],
        ..Default::default()
    };
    let param_bad_2 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; ATCA_AES_GCM_IV_STD_LENGTH - 1],
        ..Default::default()
    };
    let param_bad_3 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; ATCA_AES_KEY_SIZE],
        ..Default::default()
    };
    let param_bad_4 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; ATCA_AES_GCM_IV_STD_LENGTH],
        ..Default::default()
    };
    let param_bad_5 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; ATCA_AES_GCM_IV_STD_LENGTH],
        additional_data: Some(vec![0x00; ATCA_AES_DATA_SIZE]),
        tag_length: Some((ATCA_AES_DATA_SIZE + 1) as u8),
        ..Default::default()
    };
    let param_bad_6 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; ATCA_AES_GCM_IV_STD_LENGTH],
        additional_data: Some(vec![0x00; ATCA_AES_DATA_SIZE]),
        tag_length: Some(11),
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
        expected_bad_4 = AtcaStatus::AtcaInvalidSize;
        expected_bad_5 = AtcaStatus::AtcaInvalidSize;
        expected_bad_6 = AtcaStatus::AtcaInvalidSize;
        expected_bad_7 = AtcaStatus::AtcaInvalidSize;
        expected_bad_8 = AtcaStatus::AtcaInvalidSize;
    }

    // slot_id is too big
    match device.aead_encrypt(
        AeadAlgorithm::Gcm(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_1 = err,
    }

    // slot holds a key other than AES
    match device.aead_encrypt(AeadAlgorithm::Gcm(param_ok), 0x00, &mut data) {
        Ok(_) => (),
        Err(err) => result_bad_2 = err,
    }

    // slot_id points to TEMP_KEY but no key data
    match device.aead_encrypt(
        AeadAlgorithm::Gcm(param_bad_1),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_3 = err,
    }

    // nonce length is too short
    match device.aead_encrypt(
        AeadAlgorithm::Gcm(param_bad_2),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_4 = err,
    }

    // nonce length is too long
    match device.aead_encrypt(
        AeadAlgorithm::Gcm(param_bad_3),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_5 = err,
    }

    // no data to sign and encrypt
    let mut empty_data: [u8; 0] = [];
    match device.aead_encrypt(
        AeadAlgorithm::Gcm(param_bad_4),
        ATCA_ATECC_SLOTS_COUNT,
        &mut empty_data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_6 = err,
    }

    // expected tag length is too long
    match device.aead_encrypt(
        AeadAlgorithm::Gcm(param_bad_5),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_7 = err,
    }

    // expected tag length is too short
    match device.aead_encrypt(
        AeadAlgorithm::Gcm(param_bad_6),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_8 = err,
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
}

#[test]
#[serial]
fn aead_gcm_decrypt_proper_data() {
    const DATA_64_SIZE: usize = 64;
    const DATA_60_SIZE: usize = 60;
    const AAD_20_SIZE: usize = 20;
    const SHORT_TAG_SIZE: usize = 12;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    // Test Vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf
    let aes_key = [
        0xFE, 0xFF, 0xE9, 0x92, 0x86, 0x65, 0x73, 0x1C, 0x6D, 0x6A, 0x8F, 0x94, 0x67, 0x30, 0x83,
        0x08,
    ];
    let iv = [
        0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE, 0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88,
    ];
    let plain_text = [
        0xD9, 0x31, 0x32, 0x25, 0xF8, 0x84, 0x06, 0xE5, 0xA5, 0x59, 0x09, 0xC5, 0xAF, 0xF5, 0x26,
        0x9A, 0x86, 0xA7, 0xA9, 0x53, 0x15, 0x34, 0xF7, 0xDA, 0x2E, 0x4C, 0x30, 0x3D, 0x8A, 0x31,
        0x8A, 0x72, 0x1C, 0x3C, 0x0C, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2F, 0xCF, 0x0E, 0x24, 0x49,
        0xA6, 0xB5, 0x25, 0xB1, 0x6A, 0xED, 0xF5, 0xAA, 0x0D, 0xE6, 0x57, 0xBA, 0x63, 0x7B, 0x39,
        0x1A, 0xAF, 0xD2, 0x55,
    ];
    let cipher_text = [
        0x42, 0x83, 0x1E, 0xC2, 0x21, 0x77, 0x74, 0x24, 0x4B, 0x72, 0x21, 0xB7, 0x84, 0xD0, 0xD4,
        0x9C, 0xE3, 0xAA, 0x21, 0x2F, 0x2C, 0x02, 0xA4, 0xE0, 0x35, 0xC1, 0x7E, 0x23, 0x29, 0xAC,
        0xA1, 0x2E, 0x21, 0xD5, 0x14, 0xB2, 0x54, 0x66, 0x93, 0x1C, 0x7D, 0x8F, 0x6A, 0x5A, 0xAC,
        0x84, 0xAA, 0x05, 0x1B, 0xA3, 0x0B, 0x39, 0x6A, 0x0A, 0xAC, 0x97, 0x3D, 0x58, 0xE0, 0x91,
        0x47, 0x3F, 0x59, 0x85,
    ];
    let aad = [
        0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF,
        0x97, 0xF5, 0xD3, 0xD5, 0x85, 0x03, 0xB9, 0x69, 0x9D, 0xE7, 0x85, 0x89, 0x5A, 0x96, 0xFD,
        0xBA, 0xAF, 0x43, 0xB1, 0xCD, 0x7F, 0x59, 0x8E, 0xCE, 0x23, 0x88, 0x1B, 0x00, 0xE3, 0xED,
        0x03, 0x06, 0x88, 0x7B, 0x0C, 0x78, 0x5E, 0x27, 0xE8, 0xAD, 0x3F, 0x82, 0x23, 0x20, 0x71,
        0x04, 0x72, 0x5D, 0xD4,
    ];

    let tag_64_no_aad = [
        0x4D, 0x5C, 0x2A, 0xF3, 0x27, 0xCD, 0x64, 0xA6, 0x2C, 0xF3, 0x5A, 0xBD, 0x2B, 0xA6, 0xFA,
        0xB4,
    ];

    let tag_64_no_text = [
        0x5F, 0x91, 0xD7, 0x71, 0x23, 0xEF, 0x5E, 0xB9, 0x99, 0x79, 0x13, 0x84, 0x9B, 0x8D, 0xC1,
        0xE9,
    ];

    let tag_64 = [
        0x64, 0xC0, 0x23, 0x29, 0x04, 0xAF, 0x39, 0x8A, 0x5B, 0x67, 0xC1, 0x0B, 0x53, 0xA5, 0x02,
        0x4D,
    ];

    let tag_60 = [
        0xF0, 0x7C, 0x25, 0x28, 0xEE, 0xA2, 0xFC, 0xA1, 0x21, 0x1F, 0x90, 0x5E, 0x1B, 0x6A, 0x88,
        0x1B,
    ];

    let param_64_no_aad = AeadParam {
        nonce: iv.to_vec(),
        key: Some(aes_key),
        tag: Some(tag_64_no_aad.to_vec()),
        ..Default::default()
    };
    let param_64_no_text = AeadParam {
        nonce: iv.to_vec(),
        key: Some(aes_key),
        tag: Some(tag_64_no_text.to_vec()),
        additional_data: Some(aad.to_vec()),
        ..Default::default()
    };
    let param_64 = AeadParam {
        nonce: iv.to_vec(),
        key: Some(aes_key),
        tag: Some(tag_64.to_vec()),
        additional_data: Some(aad.to_vec()),
        ..Default::default()
    };
    let param_64_internal_key = AeadParam {
        nonce: iv.to_vec(),
        tag: Some(tag_64.to_vec()),
        additional_data: Some(aad.to_vec()),
        ..Default::default()
    };
    let param_60 = AeadParam {
        nonce: iv.to_vec(),
        key: Some(aes_key),
        tag: Some(tag_60.to_vec()),
        additional_data: Some(aad[..AAD_20_SIZE].to_vec()),
        ..Default::default()
    };
    let param_60_short_tag = AeadParam {
        nonce: iv.to_vec(),
        key: Some(aes_key),
        tag: Some(tag_60[..SHORT_TAG_SIZE].to_vec()),
        additional_data: Some(aad[..AAD_20_SIZE].to_vec()),
        ..Default::default()
    };
    let param_60_internal_key = AeadParam {
        nonce: iv.to_vec(),
        tag: Some(tag_60.to_vec()),
        additional_data: Some(aad[..AAD_20_SIZE].to_vec()),
        ..Default::default()
    };

    let mut data_64_no_text: [u8; 0x00] = [0x00; 0x00];
    let mut data_64_no_aad: [u8; DATA_64_SIZE] = [0x00; DATA_64_SIZE];
    data_64_no_aad.clone_from_slice(&cipher_text[..DATA_64_SIZE]);
    let mut data_64: [u8; DATA_64_SIZE] = [0x00; DATA_64_SIZE];
    data_64.clone_from_slice(&cipher_text[..DATA_64_SIZE]);
    let mut data_60: [u8; DATA_60_SIZE] = [0x00; DATA_60_SIZE];
    data_60.clone_from_slice(&cipher_text[..DATA_60_SIZE]);
    let mut data_60_short_tag: [u8; DATA_60_SIZE] = [0x00; DATA_60_SIZE];
    data_60_short_tag.clone_from_slice(&cipher_text[..DATA_60_SIZE]);
    let mut data_64_internal_key: [u8; DATA_64_SIZE] = [0x00; DATA_64_SIZE];
    data_64_internal_key.clone_from_slice(&cipher_text[..DATA_64_SIZE]);
    let mut data_60_internal_key: [u8; DATA_60_SIZE] = [0x00; DATA_60_SIZE];
    data_60_internal_key.clone_from_slice(&cipher_text[..DATA_60_SIZE]);

    let mut result_tag_64_no_aad: bool = false;
    let mut result_tag_64_no_text: bool = false;
    let mut result_tag_64: bool = false;
    let mut result_tag_60: bool = false;
    let mut result_tag_60_short: bool = false;
    let mut result_tag_64_internal_key: bool = false;
    let mut result_tag_60_internal_key: bool = false;

    let mut expected_64_no_aad = AtcaStatus::AtcaBadParam;
    let mut expected_64_no_text = AtcaStatus::AtcaBadParam;
    let mut expected_64 = AtcaStatus::AtcaBadParam;
    let mut expected_60 = AtcaStatus::AtcaBadParam;
    let mut expected_60_short_tag = AtcaStatus::AtcaBadParam;
    let mut expected_64_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_60_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;
    let mut result_64_no_aad = AtcaStatus::AtcaUnknown;
    let mut result_64_no_text = AtcaStatus::AtcaUnknown;
    let mut result_64 = AtcaStatus::AtcaUnknown;
    let mut result_60 = AtcaStatus::AtcaUnknown;
    let mut result_60_short_tag = AtcaStatus::AtcaUnknown;
    let mut result_64_internal_key = AtcaStatus::AtcaUnknown;
    let mut result_60_internal_key = AtcaStatus::AtcaUnknown;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_64_no_aad = AtcaStatus::AtcaNotLocked;
        expected_64_no_text = AtcaStatus::AtcaNotLocked;
        expected_64 = AtcaStatus::AtcaNotLocked;
        expected_60 = AtcaStatus::AtcaNotLocked;
        expected_60_short_tag = AtcaStatus::AtcaNotLocked;
        expected_64_internal_key = AtcaStatus::AtcaNotLocked;
        expected_60_internal_key = AtcaStatus::AtcaNotLocked;
        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected_64_no_aad = AtcaStatus::AtcaSuccess;
        expected_64_no_text = AtcaStatus::AtcaSuccess;
        expected_64 = AtcaStatus::AtcaSuccess;
        expected_60 = AtcaStatus::AtcaSuccess;
        expected_60_short_tag = AtcaStatus::AtcaSuccess;
        expected_64_internal_key = AtcaStatus::AtcaSuccess;
        expected_60_internal_key = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;
        result_64_no_aad = AtcaStatus::AtcaSuccess;
        result_64_no_text = AtcaStatus::AtcaSuccess;
        result_64 = AtcaStatus::AtcaSuccess;
        result_60 = AtcaStatus::AtcaSuccess;
        result_60_short_tag = AtcaStatus::AtcaSuccess;
        result_64_internal_key = AtcaStatus::AtcaSuccess;
        result_60_internal_key = AtcaStatus::AtcaSuccess;
    }

    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_64_no_aad),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_64_no_aad,
    ) {
        Ok(is_tag_ok) => result_tag_64_no_aad = is_tag_ok,
        Err(err) => result_64_no_aad = err,
    }

    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_64_no_text),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_64_no_text,
    ) {
        Ok(is_tag_ok) => result_tag_64_no_text = is_tag_ok,
        Err(err) => result_64_no_text = err,
    }

    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_64),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_64,
    ) {
        Ok(is_tag_ok) => result_tag_64 = is_tag_ok,
        Err(err) => result_64 = err,
    }

    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_60),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_60,
    ) {
        Ok(is_tag_ok) => result_tag_60 = is_tag_ok,
        Err(err) => result_60 = err,
    }

    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_60_short_tag),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_60_short_tag,
    ) {
        Ok(is_tag_ok) => result_tag_60_short = is_tag_ok,
        Err(err) => result_60_short_tag = err,
    }

    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_64_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_64_internal_key,
    ) {
        Ok(is_tag_ok) => result_tag_64_internal_key = is_tag_ok,
        Err(err) => result_64_internal_key = err,
    }

    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_60_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_60_internal_key,
    ) {
        Ok(is_tag_ok) => result_tag_60_internal_key = is_tag_ok,
        Err(err) => result_60_internal_key = err,
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert_eq!(result_tag_64_no_aad, true);
        assert_eq!(data_64_no_aad, plain_text);
        assert_eq!(result_tag_64_no_text, true);
        assert_eq!(data_64_no_text.is_empty(), true);
        assert_eq!(result_tag_64, true);
        assert_eq!(data_64, plain_text);
        assert_eq!(result_tag_60, true);
        assert_eq!(data_60.to_vec(), plain_text[..DATA_60_SIZE].to_vec());
        assert_eq!(result_tag_60_short, true);
        assert_eq!(
            data_60_short_tag.to_vec(),
            plain_text[..DATA_60_SIZE].to_vec()
        );
        assert_eq!(result_tag_64_internal_key, true);
        assert_eq!(data_64_internal_key, plain_text);
        assert_eq!(result_tag_60_internal_key, true);
        assert_eq!(
            data_60_internal_key.to_vec(),
            plain_text[..DATA_60_SIZE].to_vec()
        );
    }
    assert_eq!(result_64_no_aad, expected_64_no_aad);
    assert_eq!(result_64_no_text, expected_64_no_text);
    assert_eq!(result_64, expected_64);
    assert_eq!(result_60, expected_60);
    assert_eq!(result_60_short_tag, expected_60_short_tag);
    assert_eq!(result_64_internal_key, expected_64_internal_key);
    assert_eq!(result_60_internal_key, expected_60_internal_key);
}

#[test]
#[serial]
fn aead_gcm_decrypt_bad_data() {
    const TAG_TOO_SHORT: usize = 11;
    const AES_KEY_SLOT_IDX: u8 = 0x09;
    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let mut data: [u8; ATCA_AES_DATA_SIZE] = [0x00; ATCA_AES_DATA_SIZE];
    let param_ok = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; ATCA_AES_GCM_IV_STD_LENGTH],
        tag: Some([0x00; ATCA_AES_KEY_SIZE].to_vec()),
        additional_data: Some(vec![0x00; ATCA_AES_DATA_SIZE]),
        ..Default::default()
    };
    let param_ok_internal_key = AeadParam {
        nonce: vec![0x00; ATCA_AES_GCM_IV_STD_LENGTH],
        tag: Some([0x00; ATCA_AES_KEY_SIZE].to_vec()),
        additional_data: Some(vec![0x00; ATCA_AES_DATA_SIZE]),
        ..Default::default()
    };
    let param_bad_1 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; ATCA_AES_GCM_IV_STD_LENGTH],
        ..Default::default()
    };
    let param_bad_2 = AeadParam {
        nonce: vec![0x00; ATCA_AES_GCM_IV_STD_LENGTH],
        tag: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_3 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; ATCA_AES_GCM_IV_STD_LENGTH - 1],
        tag: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_4 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; ATCA_AES_KEY_SIZE],
        tag: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_5 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; ATCA_AES_GCM_IV_STD_LENGTH],
        tag: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_6 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; ATCA_AES_GCM_IV_STD_LENGTH],
        tag: Some([0x00; ATCA_AES_KEY_SIZE + 1].to_vec()),
        additional_data: Some(vec![0x00; ATCA_AES_DATA_SIZE]),
        ..Default::default()
    };
    let param_bad_7 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; ATCA_AES_GCM_IV_STD_LENGTH],
        tag: Some([0x00; TAG_TOO_SHORT].to_vec()),
        additional_data: Some(vec![0x00; ATCA_AES_DATA_SIZE]),
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
    }

    // slot_id is too big
    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_1 = err,
    }

    // slot holds a key other than AES
    match device.aead_decrypt(AeadAlgorithm::Gcm(param_ok), 0x00, &mut data) {
        Ok(_) => (),
        Err(err) => result_bad_2 = err,
    }

    // no tag data
    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_bad_1),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_3 = err,
    }

    // slot_id points to TEMP_KEY but no key data
    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_bad_2),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_4 = err,
    }

    // nonce length is too short
    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_bad_3),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_5 = err,
    }

    // nonce length is too long
    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_bad_4),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_6 = err,
    }

    // no data to verify sign and decrypt
    let mut empty_data: [u8; 0] = [];
    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_bad_5),
        ATCA_ATECC_SLOTS_COUNT,
        &mut empty_data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_7 = err,
    }

    // tag length is too long
    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_bad_6),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_8 = err,
    }

    // tag length is too short
    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_bad_7),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_9 = err,
    }

    // tags are not equal
    let mut tags_match: bool = true;
    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_ok_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data,
    ) {
        Ok(val) => {
            tags_match = val;
            expected_bad_10 = AtcaStatus::AtcaUnknown;
        }
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
    if AtcaStatus::AtcaUnknown == result_bad_10 {
        assert_eq!(tags_match, false);
    }
}
