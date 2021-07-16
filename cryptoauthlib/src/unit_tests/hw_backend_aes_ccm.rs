// Types
use super::{AeadAlgorithm, AeadParam, AtcaStatus, KeyType};
// Constants
use super::{ATCA_AES_DATA_SIZE, ATCA_AES_KEY_SIZE, ATCA_ATECC_SLOTS_COUNT};

use super::hw_backend_common::*;
use serial_test::serial;

#[test]
#[serial]
fn aead_ccm_encrypt_proper_data() {
    const DATA_4_SIZE: usize = 4;
    const DATA_16_SIZE: usize = 16;
    const DATA_24_SIZE: usize = 24;
    const DATA_64_SIZE: usize = 64;
    const AAD_8_SIZE: usize = 8;
    const AAD_16_SIZE: usize = 16;
    const AAD_20_SIZE: usize = 20;
    const IV_SIZE_7: usize = 7;
    const IV_SIZE_8: usize = 8;
    const IV_SIZE_12: usize = 12;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    // Test Vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CCM.pdf
    let aes_key = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E,
        0x4F,
    ];
    let iv = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
    ];

    let plain_text = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
        0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
        0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
        0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B,
        0x5C, 0x5D, 0x5E, 0x5F,
    ];

    let aad = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
        0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
        0x3C, 0x3D, 0x3E, 0x3F,
    ];

    let tag_64_no_aad = [0xC6, 0x6B, 0x65, 0x5C];
    let cipher_text_64_no_aad = [
        0x71, 0x62, 0x01, 0x5B, 0xC0, 0x51, 0x95, 0x1E, 0x59, 0x18, 0xAE, 0xAF, 0x3C, 0x11, 0xF3,
        0xD4, 0xAC, 0x36, 0x3F, 0x8D, 0x5B, 0x6A, 0xF3, 0xD3, 0x69, 0x60, 0x3B, 0x04, 0xF2, 0x4C,
        0xAE, 0x29, 0x96, 0x4E, 0x2F, 0x2B, 0xF9, 0xD3, 0x11, 0x43, 0xF7, 0x25, 0x27, 0xCE, 0x2D,
        0xB4, 0x02, 0xEA, 0xB7, 0x66, 0x0E, 0x4A, 0x10, 0xB0, 0x8E, 0x82, 0x26, 0x65, 0x17, 0xCD,
        0xF6, 0x02, 0x67, 0xF9,
    ];

    let tag_64_no_text = [0xE8, 0x40, 0x23, 0xF8];

    let tag_24 = [0x48, 0x43, 0x92, 0xFB, 0xC1, 0xB0, 0x99, 0x51];
    let cipher_text_24 = [
        0xE3, 0xB2, 0x01, 0xA9, 0xF5, 0xB7, 0x1A, 0x7A, 0x9B, 0x1C, 0xEA, 0xEC, 0xCD, 0x97, 0xE7,
        0x0B, 0x61, 0x76, 0xAA, 0xD9, 0xA4, 0x42, 0x8A, 0xA5,
    ];

    let tag_16 = [0x1F, 0xC6, 0x4F, 0xBF, 0xAC, 0xCD];
    let cipher_text_16 = [
        0xD2, 0xA1, 0xF0, 0xE0, 0x51, 0xEA, 0x5F, 0x62, 0x08, 0x1A, 0x77, 0x92, 0x07, 0x3D, 0x59,
        0x3D,
    ];

    let tag_4 = [0x4D, 0xAC, 0x25, 0x5D];
    let cipher_text_4 = [0x71, 0x62, 0x01, 0x5B];

    let mut data_64_no_text: [u8; 0x00] = [0x00; 0x00];
    let mut data_64_no_aad: [u8; DATA_64_SIZE] = [0x00; DATA_64_SIZE];
    data_64_no_aad.clone_from_slice(&plain_text[..DATA_64_SIZE]);
    let mut data_24: [u8; DATA_24_SIZE] = [0x00; DATA_24_SIZE];
    data_24.clone_from_slice(&plain_text[..DATA_24_SIZE]);
    let mut data_16: [u8; DATA_16_SIZE] = [0x00; DATA_16_SIZE];
    data_16.clone_from_slice(&plain_text[..DATA_16_SIZE]);
    let mut data_4: [u8; DATA_4_SIZE] = [0x00; DATA_4_SIZE];
    data_4.clone_from_slice(&plain_text[..DATA_4_SIZE]);
    let mut data_24_internal_key: [u8; DATA_24_SIZE] = [0x00; DATA_24_SIZE];
    data_24_internal_key.clone_from_slice(&plain_text[..DATA_24_SIZE]);

    let param_64_no_aad = AeadParam {
        key: Some(aes_key),
        nonce: iv[..IV_SIZE_7].to_vec(),
        tag_length: Some(tag_64_no_aad.len() as u8),
        ..Default::default()
    };
    let param_64_no_text = AeadParam {
        key: Some(aes_key),
        nonce: iv[..IV_SIZE_7].to_vec(),
        tag_length: Some(tag_64_no_text.len() as u8),
        additional_data: Some(aad.to_vec()),
        ..Default::default()
    };
    let param_24 = AeadParam {
        key: Some(aes_key),
        nonce: iv[..IV_SIZE_12].to_vec(),
        tag_length: Some(tag_24.len() as u8),
        additional_data: Some(aad[..AAD_20_SIZE].to_vec()),
        ..Default::default()
    };
    let param_24_internal_key = AeadParam {
        nonce: iv[..IV_SIZE_12].to_vec(),
        tag_length: Some(tag_24.len() as u8),
        additional_data: Some(aad[..AAD_20_SIZE].to_vec()),
        ..Default::default()
    };
    let param_16 = AeadParam {
        key: Some(aes_key),
        nonce: iv[..IV_SIZE_8].to_vec(),
        tag_length: Some(tag_16.len() as u8),
        additional_data: Some(aad[..AAD_16_SIZE].to_vec()),
        ..Default::default()
    };
    let param_4 = AeadParam {
        key: Some(aes_key),
        nonce: iv[..IV_SIZE_7].to_vec(),
        tag_length: Some(tag_4.len() as u8),
        additional_data: Some(aad[..AAD_8_SIZE].to_vec()),
        ..Default::default()
    };

    let mut expected_64_no_text = AtcaStatus::AtcaBadParam;
    let mut expected_64_no_aad = AtcaStatus::AtcaBadParam;
    let mut expected_24 = AtcaStatus::AtcaBadParam;
    let mut expected_16 = AtcaStatus::AtcaBadParam;
    let mut expected_4 = AtcaStatus::AtcaBadParam;
    let mut expected_24_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;

    let mut result_64_no_text: AtcaStatus = AtcaStatus::AtcaUnknown;
    let mut result_64_no_aad: AtcaStatus = AtcaStatus::AtcaUnknown;
    let mut result_24: AtcaStatus = AtcaStatus::AtcaUnknown;
    let mut result_16: AtcaStatus = AtcaStatus::AtcaUnknown;
    let mut result_4: AtcaStatus = AtcaStatus::AtcaUnknown;
    let mut result_24_internal_key: AtcaStatus = AtcaStatus::AtcaUnknown;

    let mut result_tag_64_no_text: Vec<u8> = Vec::new();
    let mut result_tag_64_no_aad: Vec<u8> = Vec::new();
    let mut result_tag_24: Vec<u8> = Vec::new();
    let mut result_tag_16: Vec<u8> = Vec::new();
    let mut result_tag_4: Vec<u8> = Vec::new();
    let mut result_tag_24_internal_key: Vec<u8> = Vec::new();

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_64_no_text = AtcaStatus::AtcaNotLocked;
        expected_64_no_aad = AtcaStatus::AtcaNotLocked;
        expected_24 = AtcaStatus::AtcaNotLocked;
        expected_16 = AtcaStatus::AtcaNotLocked;
        expected_4 = AtcaStatus::AtcaNotLocked;
        expected_24_internal_key = AtcaStatus::AtcaNotLocked;

        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected_64_no_text = AtcaStatus::AtcaSuccess;
        expected_64_no_aad = AtcaStatus::AtcaSuccess;
        expected_24 = AtcaStatus::AtcaSuccess;
        expected_16 = AtcaStatus::AtcaSuccess;
        expected_4 = AtcaStatus::AtcaSuccess;
        expected_24_internal_key = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;

        result_64_no_text = AtcaStatus::AtcaSuccess;
        result_64_no_aad = AtcaStatus::AtcaSuccess;
        result_24 = AtcaStatus::AtcaSuccess;
        result_16 = AtcaStatus::AtcaSuccess;
        result_4 = AtcaStatus::AtcaSuccess;
        result_24_internal_key = AtcaStatus::AtcaSuccess;
    }

    match device.aead_encrypt(
        AeadAlgorithm::Ccm(param_64_no_text),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_64_no_text,
    ) {
        Ok(tag) => result_tag_64_no_text = tag,
        Err(err) => result_64_no_text = err,
    }

    match device.aead_encrypt(
        AeadAlgorithm::Ccm(param_64_no_aad),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_64_no_aad,
    ) {
        Ok(tag) => result_tag_64_no_aad = tag,
        Err(err) => result_64_no_aad = err,
    }

    match device.aead_encrypt(
        AeadAlgorithm::Ccm(param_24),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_24,
    ) {
        Ok(tag) => result_tag_24 = tag,
        Err(err) => result_24 = err,
    }

    match device.aead_encrypt(
        AeadAlgorithm::Ccm(param_16),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_16,
    ) {
        Ok(tag) => result_tag_16 = tag,
        Err(err) => result_16 = err,
    }

    match device.aead_encrypt(
        AeadAlgorithm::Ccm(param_4),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_4,
    ) {
        Ok(tag) => result_tag_4 = tag,
        Err(err) => result_4 = err,
    }

    match device.aead_encrypt(
        AeadAlgorithm::Ccm(param_24_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_24_internal_key,
    ) {
        Ok(tag) => result_tag_24_internal_key = tag,
        Err(err) => result_24_internal_key = err,
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert_eq!(result_tag_64_no_text, tag_64_no_text);
        assert_eq!(data_64_no_text.is_empty(), true);
        assert_eq!(result_tag_64_no_aad, tag_64_no_aad);
        assert_eq!(data_64_no_aad.to_vec(), cipher_text_64_no_aad.to_vec());
        assert_eq!(result_tag_24, tag_24);
        assert_eq!(data_24.to_vec(), cipher_text_24.to_vec());
        assert_eq!(result_tag_16, tag_16);
        assert_eq!(data_16.to_vec(), cipher_text_16.to_vec());
        assert_eq!(result_tag_4, tag_4);
        assert_eq!(data_4.to_vec(), cipher_text_4.to_vec());
        assert_eq!(result_tag_24_internal_key, tag_24);
        assert_eq!(data_24_internal_key.to_vec(), cipher_text_24.to_vec());
    }
    assert_eq!(result_64_no_text, expected_64_no_text);
    assert_eq!(result_64_no_aad, expected_64_no_aad);
    assert_eq!(result_24, expected_24);
    assert_eq!(result_16, expected_16);
    assert_eq!(result_4, expected_4);
    assert_eq!(result_24_internal_key, expected_24_internal_key);
}

#[test]
#[serial]
fn aead_ccm_encrypt_bad_data() {
    const AES_CCM_IV_MIN_LENGTH: usize = 7;
    const AES_CCM_AAD_MAX_LENGTH: usize = 0xFEFF;
    const AES_CCM_TAG_MIN_LENGTH: u8 = 4;
    const AES_CCM_TAG_BAD_LENGTH: u8 = 5;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let mut data: [u8; ATCA_AES_DATA_SIZE] = [0x00; ATCA_AES_DATA_SIZE];
    let param_ok = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; AES_CCM_IV_MIN_LENGTH],
        additional_data: Some(vec![0x00; ATCA_AES_DATA_SIZE]),
        ..Default::default()
    };
    let param_bad_1 = AeadParam {
        nonce: vec![0x00; AES_CCM_IV_MIN_LENGTH],
        ..Default::default()
    };
    let param_bad_2 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; AES_CCM_IV_MIN_LENGTH - 1],
        ..Default::default()
    };
    let param_bad_3 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; ATCA_AES_KEY_SIZE],
        ..Default::default()
    };
    let param_bad_4 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; AES_CCM_IV_MIN_LENGTH],
        ..Default::default()
    };
    let param_bad_5 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; AES_CCM_IV_MIN_LENGTH],
        additional_data: Some(vec![0x00; ATCA_AES_DATA_SIZE]),
        tag_length: Some((ATCA_AES_DATA_SIZE + 1) as u8),
        ..Default::default()
    };
    let param_bad_6 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; AES_CCM_IV_MIN_LENGTH],
        additional_data: Some(vec![0x00; ATCA_AES_DATA_SIZE]),
        tag_length: Some(AES_CCM_TAG_MIN_LENGTH - 1),
        ..Default::default()
    };
    let param_bad_7 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; AES_CCM_IV_MIN_LENGTH],
        additional_data: Some(vec![0x00; ATCA_AES_DATA_SIZE]),
        tag_length: Some(AES_CCM_TAG_BAD_LENGTH),
        ..Default::default()
    };
    let param_bad_8 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; AES_CCM_IV_MIN_LENGTH],
        additional_data: Some(vec![0x00; AES_CCM_AAD_MAX_LENGTH + 1]),
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
        expected_bad_4 = AtcaStatus::AtcaInvalidSize;
        expected_bad_5 = AtcaStatus::AtcaInvalidSize;
        expected_bad_6 = AtcaStatus::AtcaInvalidSize;
        expected_bad_7 = AtcaStatus::AtcaInvalidSize;
        expected_bad_8 = AtcaStatus::AtcaInvalidSize;
        expected_bad_9 = AtcaStatus::AtcaInvalidSize;
        expected_bad_10 = AtcaStatus::AtcaInvalidSize;
    }

    // slot_id is too big
    match device.aead_encrypt(
        AeadAlgorithm::Ccm(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_1 = err,
    }

    // slot holds a key other than AES
    match device.aead_encrypt(AeadAlgorithm::Ccm(param_ok), 0x00, &mut data) {
        Ok(_) => (),
        Err(err) => result_bad_2 = err,
    }

    // slot_id points to TEMP_KEY but no key data
    match device.aead_encrypt(
        AeadAlgorithm::Ccm(param_bad_1),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_3 = err,
    }

    // nonce length is too short
    match device.aead_encrypt(
        AeadAlgorithm::Ccm(param_bad_2),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_4 = err,
    }

    // nonce length is too long
    match device.aead_encrypt(
        AeadAlgorithm::Ccm(param_bad_3),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_5 = err,
    }

    // no data to sign and encrypt
    let mut empty_data: [u8; 0] = [];
    match device.aead_encrypt(
        AeadAlgorithm::Ccm(param_bad_4),
        ATCA_ATECC_SLOTS_COUNT,
        &mut empty_data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_6 = err,
    }

    // expected tag length is too long
    match device.aead_encrypt(
        AeadAlgorithm::Ccm(param_bad_5),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_7 = err,
    }

    // expected tag length is too short
    match device.aead_encrypt(
        AeadAlgorithm::Ccm(param_bad_6),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_8 = err,
    }

    // expected length of tag is odd
    match device.aead_encrypt(
        AeadAlgorithm::Ccm(param_bad_7),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_9 = err,
    }

    // aad length is too long
    match device.aead_encrypt(
        AeadAlgorithm::Ccm(param_bad_8),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
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
fn aead_ccm_decrypt_proper_data() {
    const DATA_4_SIZE: usize = 4;
    const DATA_16_SIZE: usize = 16;
    const DATA_24_SIZE: usize = 24;
    const DATA_64_SIZE: usize = 64;
    const AAD_8_SIZE: usize = 8;
    const AAD_16_SIZE: usize = 16;
    const AAD_20_SIZE: usize = 20;
    const IV_SIZE_7: usize = 7;
    const IV_SIZE_8: usize = 8;
    const IV_SIZE_12: usize = 12;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    // Test Vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CCM.pdf
    let aes_key = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E,
        0x4F,
    ];
    let iv = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
    ];

    let plain_text = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
        0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
        0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
        0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B,
        0x5C, 0x5D, 0x5E, 0x5F,
    ];

    let aad = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
        0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
        0x3C, 0x3D, 0x3E, 0x3F,
    ];

    let tag_64_no_aad = [0xC6, 0x6B, 0x65, 0x5C];
    let cipher_text_64_no_aad = [
        0x71, 0x62, 0x01, 0x5B, 0xC0, 0x51, 0x95, 0x1E, 0x59, 0x18, 0xAE, 0xAF, 0x3C, 0x11, 0xF3,
        0xD4, 0xAC, 0x36, 0x3F, 0x8D, 0x5B, 0x6A, 0xF3, 0xD3, 0x69, 0x60, 0x3B, 0x04, 0xF2, 0x4C,
        0xAE, 0x29, 0x96, 0x4E, 0x2F, 0x2B, 0xF9, 0xD3, 0x11, 0x43, 0xF7, 0x25, 0x27, 0xCE, 0x2D,
        0xB4, 0x02, 0xEA, 0xB7, 0x66, 0x0E, 0x4A, 0x10, 0xB0, 0x8E, 0x82, 0x26, 0x65, 0x17, 0xCD,
        0xF6, 0x02, 0x67, 0xF9,
    ];

    let tag_64_no_text = [0xE8, 0x40, 0x23, 0xF8];

    let tag_24 = [0x48, 0x43, 0x92, 0xFB, 0xC1, 0xB0, 0x99, 0x51];
    let cipher_text_24 = [
        0xE3, 0xB2, 0x01, 0xA9, 0xF5, 0xB7, 0x1A, 0x7A, 0x9B, 0x1C, 0xEA, 0xEC, 0xCD, 0x97, 0xE7,
        0x0B, 0x61, 0x76, 0xAA, 0xD9, 0xA4, 0x42, 0x8A, 0xA5,
    ];

    let tag_16 = [0x1F, 0xC6, 0x4F, 0xBF, 0xAC, 0xCD];
    let cipher_text_16 = [
        0xD2, 0xA1, 0xF0, 0xE0, 0x51, 0xEA, 0x5F, 0x62, 0x08, 0x1A, 0x77, 0x92, 0x07, 0x3D, 0x59,
        0x3D,
    ];

    let tag_4 = [0x4D, 0xAC, 0x25, 0x5D];
    let cipher_text_4 = [0x71, 0x62, 0x01, 0x5B];

    let param_64_no_text = AeadParam {
        nonce: iv[..IV_SIZE_7].to_vec(),
        key: Some(aes_key),
        tag: Some(tag_64_no_text.to_vec()),
        additional_data: Some(aad.to_vec()),
        ..Default::default()
    };
    let param_64_no_aad = AeadParam {
        nonce: iv[..IV_SIZE_7].to_vec(),
        key: Some(aes_key),
        tag: Some(tag_64_no_aad.to_vec()),
        ..Default::default()
    };
    let param_24 = AeadParam {
        nonce: iv[..IV_SIZE_12].to_vec(),
        key: Some(aes_key),
        tag: Some(tag_24.to_vec()),
        additional_data: Some(aad[..AAD_20_SIZE].to_vec()),
        ..Default::default()
    };
    let param_24_internal_key = AeadParam {
        nonce: iv[..IV_SIZE_12].to_vec(),
        tag: Some(tag_24.to_vec()),
        additional_data: Some(aad[..AAD_20_SIZE].to_vec()),
        ..Default::default()
    };
    let param_16 = AeadParam {
        nonce: iv[..IV_SIZE_8].to_vec(),
        key: Some(aes_key),
        tag: Some(tag_16.to_vec()),
        additional_data: Some(aad[..AAD_16_SIZE].to_vec()),
        ..Default::default()
    };
    let param_4 = AeadParam {
        nonce: iv[..IV_SIZE_7].to_vec(),
        key: Some(aes_key),
        tag: Some(tag_4.to_vec()),
        additional_data: Some(aad[..AAD_8_SIZE].to_vec()),
        ..Default::default()
    };

    let mut data_64_no_text: [u8; 0x00] = [0x00; 0x00];
    let mut data_64_no_aad: [u8; DATA_64_SIZE] = [0x00; DATA_64_SIZE];
    data_64_no_aad.clone_from_slice(&cipher_text_64_no_aad);
    let mut data_24: [u8; DATA_24_SIZE] = [0x00; DATA_24_SIZE];
    data_24.clone_from_slice(&cipher_text_24);
    let mut data_16: [u8; DATA_16_SIZE] = [0x00; DATA_16_SIZE];
    data_16.clone_from_slice(&cipher_text_16);
    let mut data_4: [u8; DATA_4_SIZE] = [0x00; DATA_4_SIZE];
    data_4.clone_from_slice(&cipher_text_4);
    let mut data_24_internal_key: [u8; DATA_24_SIZE] = [0x00; DATA_24_SIZE];
    data_24_internal_key.clone_from_slice(&cipher_text_24);

    let mut result_tag_64_no_text: bool = false;
    let mut result_tag_64_no_aad: bool = false;
    let mut result_tag_24: bool = false;
    let mut result_tag_16: bool = false;
    let mut result_tag_4: bool = false;
    let mut result_tag_24_internal_key: bool = false;
    let mut expected_64_no_text = AtcaStatus::AtcaBadParam;
    let mut expected_64_no_aad = AtcaStatus::AtcaBadParam;
    let mut expected_24 = AtcaStatus::AtcaBadParam;
    let mut expected_16 = AtcaStatus::AtcaBadParam;
    let mut expected_4 = AtcaStatus::AtcaBadParam;
    let mut expected_24_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;
    let mut result_64_no_text = AtcaStatus::AtcaUnknown;
    let mut result_64_no_aad = AtcaStatus::AtcaUnknown;
    let mut result_24 = AtcaStatus::AtcaUnknown;
    let mut result_16 = AtcaStatus::AtcaUnknown;
    let mut result_4 = AtcaStatus::AtcaUnknown;
    let mut result_24_internal_key = AtcaStatus::AtcaUnknown;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_64_no_text = AtcaStatus::AtcaNotLocked;
        expected_64_no_aad = AtcaStatus::AtcaNotLocked;
        expected_24 = AtcaStatus::AtcaNotLocked;
        expected_16 = AtcaStatus::AtcaNotLocked;
        expected_4 = AtcaStatus::AtcaNotLocked;
        expected_24_internal_key = AtcaStatus::AtcaNotLocked;
        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected_64_no_text = AtcaStatus::AtcaSuccess;
        expected_64_no_aad = AtcaStatus::AtcaSuccess;
        expected_24 = AtcaStatus::AtcaSuccess;
        expected_16 = AtcaStatus::AtcaSuccess;
        expected_4 = AtcaStatus::AtcaSuccess;
        expected_24_internal_key = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;
        result_64_no_text = AtcaStatus::AtcaSuccess;
        result_64_no_aad = AtcaStatus::AtcaSuccess;
        result_24 = AtcaStatus::AtcaSuccess;
        result_16 = AtcaStatus::AtcaSuccess;
        result_4 = AtcaStatus::AtcaSuccess;
        result_24_internal_key = AtcaStatus::AtcaSuccess;
    }

    match device.aead_decrypt(
        AeadAlgorithm::Ccm(param_64_no_text),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_64_no_text,
    ) {
        Ok(is_tag_ok) => result_tag_64_no_text = is_tag_ok,
        Err(err) => result_64_no_text = err,
    }

    match device.aead_decrypt(
        AeadAlgorithm::Ccm(param_64_no_aad),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_64_no_aad,
    ) {
        Ok(is_tag_ok) => result_tag_64_no_aad = is_tag_ok,
        Err(err) => result_64_no_aad = err,
    }

    match device.aead_decrypt(
        AeadAlgorithm::Ccm(param_24),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_24,
    ) {
        Ok(is_tag_ok) => result_tag_24 = is_tag_ok,
        Err(err) => result_24 = err,
    }

    match device.aead_decrypt(
        AeadAlgorithm::Ccm(param_16),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_16,
    ) {
        Ok(is_tag_ok) => result_tag_16 = is_tag_ok,
        Err(err) => result_16 = err,
    }

    match device.aead_decrypt(
        AeadAlgorithm::Ccm(param_4),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_4,
    ) {
        Ok(is_tag_ok) => result_tag_4 = is_tag_ok,
        Err(err) => result_4 = err,
    }

    match device.aead_decrypt(
        AeadAlgorithm::Ccm(param_24_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_24_internal_key,
    ) {
        Ok(is_tag_ok) => result_tag_24_internal_key = is_tag_ok,
        Err(err) => result_24_internal_key = err,
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert_eq!(result_tag_64_no_text, true);
        assert_eq!(data_64_no_text.is_empty(), true);
        assert_eq!(result_tag_64_no_aad, true);
        assert_eq!(data_64_no_aad.to_vec(), plain_text[..DATA_64_SIZE].to_vec());
        assert_eq!(result_tag_24, true);
        assert_eq!(data_24.to_vec(), plain_text[..DATA_24_SIZE].to_vec());
        assert_eq!(result_tag_16, true);
        assert_eq!(data_16.to_vec(), plain_text[..DATA_16_SIZE].to_vec());
        assert_eq!(result_tag_4, true);
        assert_eq!(data_4.to_vec(), plain_text[..DATA_4_SIZE].to_vec());
        assert_eq!(result_tag_24_internal_key, true);
        assert_eq!(
            data_24_internal_key.to_vec(),
            plain_text[..DATA_24_SIZE].to_vec()
        );
    }
    assert_eq!(result_64_no_text, expected_64_no_text);
    assert_eq!(result_64_no_aad, expected_64_no_aad);
    assert_eq!(result_24, expected_24);
    assert_eq!(result_16, expected_16);
    assert_eq!(result_4, expected_4);
    assert_eq!(result_24_internal_key, expected_24_internal_key);
}

#[test]
#[serial]
fn aead_ccm_decrypt_bad_data() {
    const AES_CCM_IV_MIN_LENGTH: usize = 7;
    const AES_CCM_AAD_MAX_LENGTH: usize = 0xFEFF;
    const AES_CCM_TAG_MIN_LENGTH: usize = 4;
    const AES_CCM_TAG_BAD_LENGTH: usize = 5;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let mut data: [u8; ATCA_AES_DATA_SIZE] = [0x00; ATCA_AES_DATA_SIZE];
    let param_ok = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; AES_CCM_IV_MIN_LENGTH],
        tag: Some([0x00; ATCA_AES_KEY_SIZE].to_vec()),
        additional_data: Some(vec![0x00; ATCA_AES_DATA_SIZE]),
        ..Default::default()
    };
    let param_ok_internal_key = AeadParam {
        nonce: vec![0x00; AES_CCM_IV_MIN_LENGTH],
        tag: Some([0x00; ATCA_AES_KEY_SIZE].to_vec()),
        additional_data: Some(vec![0x00; ATCA_AES_DATA_SIZE]),
        ..Default::default()
    };
    let param_bad_1 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; AES_CCM_IV_MIN_LENGTH],
        ..Default::default()
    };
    let param_bad_2 = AeadParam {
        nonce: vec![0x00; AES_CCM_IV_MIN_LENGTH],
        tag: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_3 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; AES_CCM_IV_MIN_LENGTH - 1],
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
        nonce: vec![0x00; AES_CCM_IV_MIN_LENGTH],
        tag: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_6 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; AES_CCM_IV_MIN_LENGTH],
        tag: Some([0x00; ATCA_AES_KEY_SIZE + 1].to_vec()),
        additional_data: Some(vec![0x00; ATCA_AES_DATA_SIZE]),
        ..Default::default()
    };
    let param_bad_7 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; AES_CCM_IV_MIN_LENGTH],
        tag: Some([0x00; AES_CCM_TAG_MIN_LENGTH - 1].to_vec()),
        additional_data: Some(vec![0x00; ATCA_AES_DATA_SIZE]),
        ..Default::default()
    };
    let param_bad_8 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; AES_CCM_IV_MIN_LENGTH],
        tag: Some([0x00; AES_CCM_TAG_BAD_LENGTH].to_vec()),
        additional_data: Some(vec![0x00; ATCA_AES_DATA_SIZE]),
        ..Default::default()
    };
    let param_bad_9 = AeadParam {
        key: Some([0x00; ATCA_AES_KEY_SIZE]),
        nonce: vec![0x00; AES_CCM_IV_MIN_LENGTH],
        tag: Some([0x00; AES_CCM_TAG_MIN_LENGTH].to_vec()),
        additional_data: Some(vec![0x00; AES_CCM_AAD_MAX_LENGTH + 1]),
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
    let mut expected_bad_11 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_12 = AtcaStatus::AtcaBadParam;
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
    let mut result_bad_11 = AtcaStatus::AtcaUnknown;
    let mut result_bad_12 = AtcaStatus::AtcaUnknown;

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
        expected_bad_11 = AtcaStatus::AtcaNotLocked;
        expected_bad_12 = AtcaStatus::AtcaNotLocked;
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
        expected_bad_11 = AtcaStatus::AtcaInvalidSize;
    }

    // slot_id is too big
    match device.aead_decrypt(
        AeadAlgorithm::Ccm(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_1 = err,
    }

    // slot holds a key other than AES
    match device.aead_decrypt(AeadAlgorithm::Ccm(param_ok), 0x00, &mut data) {
        Ok(_) => (),
        Err(err) => result_bad_2 = err,
    }

    // no tag data
    match device.aead_decrypt(
        AeadAlgorithm::Ccm(param_bad_1),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_3 = err,
    }

    // slot_id points to TEMP_KEY but no key data
    match device.aead_decrypt(
        AeadAlgorithm::Ccm(param_bad_2),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_4 = err,
    }

    // nonce length is too short
    match device.aead_decrypt(
        AeadAlgorithm::Ccm(param_bad_3),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_5 = err,
    }

    // nonce length is too long
    match device.aead_decrypt(
        AeadAlgorithm::Ccm(param_bad_4),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_6 = err,
    }

    // no data to verify sign and decrypt
    let mut empty_data: [u8; 0] = [];
    match device.aead_decrypt(
        AeadAlgorithm::Ccm(param_bad_5),
        ATCA_ATECC_SLOTS_COUNT,
        &mut empty_data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_7 = err,
    }

    // tag length is too long
    match device.aead_decrypt(
        AeadAlgorithm::Ccm(param_bad_6),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_8 = err,
    }

    // tag length is too short
    match device.aead_decrypt(
        AeadAlgorithm::Ccm(param_bad_7),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_9 = err,
    }

    // length of tag is odd
    match device.aead_decrypt(
        AeadAlgorithm::Ccm(param_bad_8),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_10 = err,
    }

    // aad length is too long
    match device.aead_decrypt(
        AeadAlgorithm::Ccm(param_bad_9),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    ) {
        Ok(_) => (),
        Err(err) => result_bad_11 = err,
    }
    // tags are not equal
    let mut tags_match: bool = true;
    match device.aead_decrypt(
        AeadAlgorithm::Ccm(param_ok_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data,
    ) {
        Ok(val) => {
            tags_match = val;
            expected_bad_12 = AtcaStatus::AtcaUnknown;
        }
        Err(err) => result_bad_12 = err,
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
    assert_eq!(result_bad_11, expected_bad_11);
    assert_eq!(result_bad_12, expected_bad_12);
    if AtcaStatus::AtcaUnknown == result_bad_12 {
        assert_eq!(tags_match, false);
    }
}
