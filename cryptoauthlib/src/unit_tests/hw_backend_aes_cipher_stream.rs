// Types
use super::{AtcaStatus, CipherAlgorithm, CipherParam, KeyType};
// Constants
use super::{
    ATCA_AES_DATA_SIZE, ATCA_AES_KEY_SIZE, ATCA_ATECC_SLOTS_COUNT, ATCA_ATECC_TEMPKEY_KEYID,
};

use super::hw_backend_common::*;
use serial_test::serial;
use std::mem::MaybeUninit;

#[test]
#[serial]
fn cipher_cfb_encrypt_proper_data() {
    const DATA_64_SIZE: usize = 64;
    const DATA_24_SIZE: usize = 24;
    const DATA_16_SIZE: usize = 16;
    const DATA_2_SIZE: usize = 2;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    // Test Vector from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CFB.pdf
    let iv = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];

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

    let cipher_text = [
        0x3B, 0x3F, 0xD9, 0x2E, 0xB7, 0x2D, 0xAD, 0x20, 0x33, 0x34, 0x49, 0xF8, 0xE8, 0x3C, 0xFB,
        0x4A, 0xC8, 0xA6, 0x45, 0x37, 0xA0, 0xB3, 0xA9, 0x3F, 0xCD, 0xE3, 0xCD, 0xAD, 0x9F, 0x1C,
        0xE5, 0x8B, 0x26, 0x75, 0x1F, 0x67, 0xA3, 0xCB, 0xB1, 0x40, 0xB1, 0x80, 0x8C, 0xF1, 0x87,
        0xA4, 0xF4, 0xDF, 0xC0, 0x4B, 0x05, 0x35, 0x7C, 0x5D, 0x1C, 0x0E, 0xEA, 0xC4, 0xC6, 0x6F,
        0x9F, 0xF7, 0xF2, 0xE6,
    ];

    let mut data_64: Vec<u8> = Vec::new();
    data_64.extend_from_slice(&plain_text[..DATA_64_SIZE]);
    let mut data_64_internal_key: Vec<u8> = Vec::new();
    data_64_internal_key.extend_from_slice(&plain_text[..DATA_64_SIZE]);
    let mut data_24: Vec<u8> = Vec::new();
    data_24.extend_from_slice(&plain_text[..DATA_24_SIZE]);
    let mut data_16: Vec<u8> = Vec::new();
    data_16.extend_from_slice(&plain_text[..DATA_16_SIZE]);
    let mut data_2: Vec<u8> = Vec::new();
    data_2.extend_from_slice(&plain_text[..DATA_2_SIZE]);

    let param = CipherParam {
        iv: Some(iv),
        key: Some(aes_key.to_vec()),
        ..Default::default()
    };
    let param_internal_key = CipherParam {
        iv: Some(iv),
        ..Default::default()
    };

    let mut expected_64 = AtcaStatus::AtcaBadParam;
    let mut expected_64_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_24 = AtcaStatus::AtcaBadParam;
    let mut expected_16 = AtcaStatus::AtcaBadParam;
    let mut expected_2 = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_64 = AtcaStatus::AtcaNotLocked;
        expected_64_internal_key = AtcaStatus::AtcaNotLocked;
        expected_24 = AtcaStatus::AtcaNotLocked;
        expected_16 = AtcaStatus::AtcaNotLocked;
        expected_2 = AtcaStatus::AtcaNotLocked;
        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected_64 = AtcaStatus::AtcaSuccess;
        expected_64_internal_key = AtcaStatus::AtcaSuccess;
        expected_24 = AtcaStatus::AtcaSuccess;
        expected_16 = AtcaStatus::AtcaSuccess;
        expected_2 = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;
    }

    let result_64 = device.cipher_encrypt(
        CipherAlgorithm::Cfb(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_64,
    );
    let result_64_internal_key = device.cipher_encrypt(
        CipherAlgorithm::Cfb(param_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_64_internal_key,
    );
    let result_24 = device.cipher_encrypt(
        CipherAlgorithm::Cfb(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_24,
    );
    let result_16 = device.cipher_encrypt(
        CipherAlgorithm::Cfb(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_16,
    );
    let result_2 = device.cipher_encrypt(
        CipherAlgorithm::Cfb(param),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_2,
    );

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert_eq!(data_64, cipher_text.to_vec());
        assert_eq!(data_64_internal_key, cipher_text.to_vec());
        assert_eq!(data_24, cipher_text[..DATA_24_SIZE].to_vec());
        assert_eq!(data_16, cipher_text[..DATA_16_SIZE].to_vec());
        assert_eq!(data_2, cipher_text[..DATA_2_SIZE].to_vec());
    }
    assert_eq!(result_64, expected_64);
    assert_eq!(result_64_internal_key, expected_64_internal_key);
    assert_eq!(result_24, expected_24);
    assert_eq!(result_16, expected_16);
    assert_eq!(result_2, expected_2);
}

#[test]
#[serial]
fn cipher_cfb_encrypt_bad_data() {
    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let mut data_ok: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE];
    let mut data_empty: Vec<u8> = Vec::new();

    let param_ok = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_wrong_key_length = CipherParam {
        key: Some(vec![0x00; ATCA_AES_DATA_SIZE + 1]),
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_no_key = CipherParam {
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_no_iv = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };

    let mut expected_bad_1 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_2 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_3 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_4 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_5 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_6 = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_bad_1 = AtcaStatus::AtcaNotLocked;
        expected_bad_2 = AtcaStatus::AtcaNotLocked;
        expected_bad_3 = AtcaStatus::AtcaNotLocked;
        expected_bad_4 = AtcaStatus::AtcaNotLocked;
        expected_bad_5 = AtcaStatus::AtcaNotLocked;
        expected_bad_6 = AtcaStatus::AtcaNotLocked;
    }

    if chip_is_locked && device.is_aes_enabled() {
        expected_bad_1 = AtcaStatus::AtcaInvalidId;
        expected_bad_2 = AtcaStatus::AtcaInvalidId;
        expected_bad_3 = AtcaStatus::AtcaBadParam;
        expected_bad_4 = AtcaStatus::AtcaInvalidSize;
        expected_bad_5 = AtcaStatus::AtcaBadParam;
        expected_bad_6 = AtcaStatus::AtcaBadParam;
    }

    // slot_id is too big
    let result_bad_1 = device.cipher_encrypt(
        CipherAlgorithm::Cfb(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &mut data_ok,
    );

    // slot holds a key other than AES
    let result_bad_2 =
        device.cipher_encrypt(CipherAlgorithm::Cfb(param_ok.clone()), 0x00, &mut data_ok);

    // slot_id points to TEMP_KEY but no key data
    let result_bad_3 = device.cipher_encrypt(
        CipherAlgorithm::Cfb(param_bad_no_key),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // no data to encrypt
    let result_bad_4 = device.cipher_encrypt(
        CipherAlgorithm::Cfb(param_ok),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_empty,
    );

    // no IV in param
    let result_bad_5 = device.cipher_encrypt(
        CipherAlgorithm::Cfb(param_bad_no_iv),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // wrong key length
    let result_bad_6 = device.cipher_encrypt(
        CipherAlgorithm::Cfb(param_bad_wrong_key_length),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_bad_1, expected_bad_1);
    assert_eq!(result_bad_2, expected_bad_2);
    assert_eq!(result_bad_3, expected_bad_3);
    assert_eq!(result_bad_4, expected_bad_4);
    assert_eq!(result_bad_5, expected_bad_5);
    assert_eq!(result_bad_6, expected_bad_6);
}

#[test]
#[serial]
fn cipher_cfb_decrypt_proper_data() {
    const DATA_64_SIZE: usize = 64;
    const DATA_24_SIZE: usize = 24;
    const DATA_16_SIZE: usize = 16;
    const DATA_2_SIZE: usize = 2;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    // Test Vector from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CFB.pdf
    let iv = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];

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

    let cipher_text = [
        0x3B, 0x3F, 0xD9, 0x2E, 0xB7, 0x2D, 0xAD, 0x20, 0x33, 0x34, 0x49, 0xF8, 0xE8, 0x3C, 0xFB,
        0x4A, 0xC8, 0xA6, 0x45, 0x37, 0xA0, 0xB3, 0xA9, 0x3F, 0xCD, 0xE3, 0xCD, 0xAD, 0x9F, 0x1C,
        0xE5, 0x8B, 0x26, 0x75, 0x1F, 0x67, 0xA3, 0xCB, 0xB1, 0x40, 0xB1, 0x80, 0x8C, 0xF1, 0x87,
        0xA4, 0xF4, 0xDF, 0xC0, 0x4B, 0x05, 0x35, 0x7C, 0x5D, 0x1C, 0x0E, 0xEA, 0xC4, 0xC6, 0x6F,
        0x9F, 0xF7, 0xF2, 0xE6,
    ];

    let mut data_64: Vec<u8> = Vec::new();
    data_64.extend_from_slice(&cipher_text[..DATA_64_SIZE]);
    let mut data_64_internal_key: Vec<u8> = Vec::new();
    data_64_internal_key.extend_from_slice(&cipher_text[..DATA_64_SIZE]);
    let mut data_24: Vec<u8> = Vec::new();
    data_24.extend_from_slice(&cipher_text[..DATA_24_SIZE]);
    let mut data_16: Vec<u8> = Vec::new();
    data_16.extend_from_slice(&cipher_text[..DATA_16_SIZE]);
    let mut data_2: Vec<u8> = Vec::new();
    data_2.extend_from_slice(&cipher_text[..DATA_2_SIZE]);

    let param = CipherParam {
        iv: Some(iv),
        key: Some(aes_key.to_vec()),
        ..Default::default()
    };
    let param_internal_key = CipherParam {
        iv: Some(iv),
        ..Default::default()
    };

    let mut expected_64 = AtcaStatus::AtcaBadParam;
    let mut expected_64_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_24 = AtcaStatus::AtcaBadParam;
    let mut expected_16 = AtcaStatus::AtcaBadParam;
    let mut expected_2 = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_64 = AtcaStatus::AtcaNotLocked;
        expected_64_internal_key = AtcaStatus::AtcaNotLocked;
        expected_24 = AtcaStatus::AtcaNotLocked;
        expected_16 = AtcaStatus::AtcaNotLocked;
        expected_2 = AtcaStatus::AtcaNotLocked;
        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected_64 = AtcaStatus::AtcaSuccess;
        expected_64_internal_key = AtcaStatus::AtcaSuccess;
        expected_24 = AtcaStatus::AtcaSuccess;
        expected_16 = AtcaStatus::AtcaSuccess;
        expected_2 = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;
    }

    let result_64 = device.cipher_decrypt(
        CipherAlgorithm::Cfb(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_64,
    );
    let result_64_internal_key = device.cipher_decrypt(
        CipherAlgorithm::Cfb(param_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_64_internal_key,
    );
    let result_24 = device.cipher_decrypt(
        CipherAlgorithm::Cfb(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_24,
    );
    let result_16 = device.cipher_decrypt(
        CipherAlgorithm::Cfb(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_16,
    );
    let result_2 = device.cipher_decrypt(
        CipherAlgorithm::Cfb(param),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_2,
    );

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert_eq!(data_64, plain_text.to_vec());
        assert_eq!(data_64_internal_key, plain_text.to_vec());
        assert_eq!(data_24, plain_text[..DATA_24_SIZE].to_vec());
        assert_eq!(data_16, plain_text[..DATA_16_SIZE].to_vec());
        assert_eq!(data_2, plain_text[..DATA_2_SIZE].to_vec());
    }
    assert_eq!(result_64, expected_64);
    assert_eq!(result_64_internal_key, expected_64_internal_key);
    assert_eq!(result_24, expected_24);
    assert_eq!(result_16, expected_16);
    assert_eq!(result_2, expected_2);
}

#[test]
#[serial]
fn cipher_cfb_decrypt_bad_data() {
    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let mut data_ok: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE];
    let mut data_empty: Vec<u8> = Vec::new();

    let param_ok = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_wrong_key_length = CipherParam {
        key: Some(vec![0x00; ATCA_AES_DATA_SIZE + 1]),
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_no_key = CipherParam {
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_no_iv = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };

    let mut expected_bad_1 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_2 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_3 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_4 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_5 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_6 = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_bad_1 = AtcaStatus::AtcaNotLocked;
        expected_bad_2 = AtcaStatus::AtcaNotLocked;
        expected_bad_3 = AtcaStatus::AtcaNotLocked;
        expected_bad_4 = AtcaStatus::AtcaNotLocked;
        expected_bad_5 = AtcaStatus::AtcaNotLocked;
        expected_bad_6 = AtcaStatus::AtcaNotLocked;
    }

    if chip_is_locked && device.is_aes_enabled() {
        expected_bad_1 = AtcaStatus::AtcaInvalidId;
        expected_bad_2 = AtcaStatus::AtcaInvalidId;
        expected_bad_3 = AtcaStatus::AtcaBadParam;
        expected_bad_4 = AtcaStatus::AtcaInvalidSize;
        expected_bad_5 = AtcaStatus::AtcaBadParam;
        expected_bad_6 = AtcaStatus::AtcaBadParam;
    }

    // slot_id is too big
    let result_bad_1 = device.cipher_decrypt(
        CipherAlgorithm::Cfb(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &mut data_ok,
    );

    // slot holds a key other than AES
    let result_bad_2 =
        device.cipher_decrypt(CipherAlgorithm::Cfb(param_ok.clone()), 0x00, &mut data_ok);

    // slot_id points to TEMP_KEY but no key data
    let result_bad_3 = device.cipher_decrypt(
        CipherAlgorithm::Cfb(param_bad_no_key),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // no data to encrypt
    let result_bad_4 = device.cipher_decrypt(
        CipherAlgorithm::Cfb(param_ok),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_empty,
    );

    // no IV in param
    let result_bad_5 = device.cipher_decrypt(
        CipherAlgorithm::Cfb(param_bad_no_iv),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // wrong key length
    let result_bad_6 = device.cipher_decrypt(
        CipherAlgorithm::Cfb(param_bad_wrong_key_length),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_bad_1, expected_bad_1);
    assert_eq!(result_bad_2, expected_bad_2);
    assert_eq!(result_bad_3, expected_bad_3);
    assert_eq!(result_bad_4, expected_bad_4);
    assert_eq!(result_bad_5, expected_bad_5);
    assert_eq!(result_bad_6, expected_bad_6);
}

#[test]
#[serial]
fn cipher_ofb_encrypt_proper_data() {
    const DATA_64_SIZE: usize = 64;
    const DATA_24_SIZE: usize = 24;
    const DATA_16_SIZE: usize = 16;
    const DATA_2_SIZE: usize = 2;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    // Test Vector from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_OFB.pdf
    let iv = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];

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

    let cipher_text = [
        0x3B, 0x3F, 0xD9, 0x2E, 0xB7, 0x2D, 0xAD, 0x20, 0x33, 0x34, 0x49, 0xF8, 0xE8, 0x3C, 0xFB,
        0x4A, 0x77, 0x89, 0x50, 0x8D, 0x16, 0x91, 0x8F, 0x03, 0xF5, 0x3C, 0x52, 0xDA, 0xC5, 0x4E,
        0xD8, 0x25, 0x97, 0x40, 0x05, 0x1E, 0x9C, 0x5F, 0xEC, 0xF6, 0x43, 0x44, 0xF7, 0xA8, 0x22,
        0x60, 0xED, 0xCC, 0x30, 0x4C, 0x65, 0x28, 0xF6, 0x59, 0xC7, 0x78, 0x66, 0xA5, 0x10, 0xD9,
        0xC1, 0xD6, 0xAE, 0x5E,
    ];

    let mut data_64: Vec<u8> = Vec::new();
    data_64.extend_from_slice(&plain_text[..DATA_64_SIZE]);
    let mut data_64_internal_key: Vec<u8> = Vec::new();
    data_64_internal_key.extend_from_slice(&plain_text[..DATA_64_SIZE]);
    let mut data_24: Vec<u8> = Vec::new();
    data_24.extend_from_slice(&plain_text[..DATA_24_SIZE]);
    let mut data_16: Vec<u8> = Vec::new();
    data_16.extend_from_slice(&plain_text[..DATA_16_SIZE]);
    let mut data_2: Vec<u8> = Vec::new();
    data_2.extend_from_slice(&plain_text[..DATA_2_SIZE]);

    let param = CipherParam {
        iv: Some(iv),
        key: Some(aes_key.to_vec()),
        ..Default::default()
    };
    let param_internal_key = CipherParam {
        iv: Some(iv),
        ..Default::default()
    };

    let mut expected_64 = AtcaStatus::AtcaBadParam;
    let mut expected_64_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_24 = AtcaStatus::AtcaBadParam;
    let mut expected_16 = AtcaStatus::AtcaBadParam;
    let mut expected_2 = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_64 = AtcaStatus::AtcaNotLocked;
        expected_64_internal_key = AtcaStatus::AtcaNotLocked;
        expected_24 = AtcaStatus::AtcaNotLocked;
        expected_16 = AtcaStatus::AtcaNotLocked;
        expected_2 = AtcaStatus::AtcaNotLocked;
        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected_64 = AtcaStatus::AtcaSuccess;
        expected_64_internal_key = AtcaStatus::AtcaSuccess;
        expected_24 = AtcaStatus::AtcaSuccess;
        expected_16 = AtcaStatus::AtcaSuccess;
        expected_2 = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;
    }

    let result_64 = device.cipher_encrypt(
        CipherAlgorithm::Ofb(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_64,
    );
    let result_64_internal_key = device.cipher_encrypt(
        CipherAlgorithm::Ofb(param_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_64_internal_key,
    );
    let result_24 = device.cipher_encrypt(
        CipherAlgorithm::Ofb(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_24,
    );
    let result_16 = device.cipher_encrypt(
        CipherAlgorithm::Ofb(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_16,
    );
    let result_2 = device.cipher_encrypt(
        CipherAlgorithm::Ofb(param),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_2,
    );

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert_eq!(data_64, cipher_text.to_vec());
        assert_eq!(data_64_internal_key, cipher_text.to_vec());
        assert_eq!(data_24, cipher_text[..DATA_24_SIZE].to_vec());
        assert_eq!(data_16, cipher_text[..DATA_16_SIZE].to_vec());
        assert_eq!(data_2, cipher_text[..DATA_2_SIZE].to_vec());
    }
    assert_eq!(result_64, expected_64);
    assert_eq!(result_64_internal_key, expected_64_internal_key);
    assert_eq!(result_24, expected_24);
    assert_eq!(result_16, expected_16);
    assert_eq!(result_2, expected_2);
}

#[test]
#[serial]
fn cipher_ofb_encrypt_bad_data() {
    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let mut data_ok: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE];
    let mut data_empty: Vec<u8> = Vec::new();

    let param_ok = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_wrong_key_length = CipherParam {
        key: Some(vec![0x00; ATCA_AES_DATA_SIZE + 1]),
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_no_key = CipherParam {
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_no_iv = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };

    let mut expected_bad_1 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_2 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_3 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_4 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_5 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_6 = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_bad_1 = AtcaStatus::AtcaNotLocked;
        expected_bad_2 = AtcaStatus::AtcaNotLocked;
        expected_bad_3 = AtcaStatus::AtcaNotLocked;
        expected_bad_4 = AtcaStatus::AtcaNotLocked;
        expected_bad_5 = AtcaStatus::AtcaNotLocked;
        expected_bad_6 = AtcaStatus::AtcaNotLocked;
    }

    if chip_is_locked && device.is_aes_enabled() {
        expected_bad_1 = AtcaStatus::AtcaInvalidId;
        expected_bad_2 = AtcaStatus::AtcaInvalidId;
        expected_bad_3 = AtcaStatus::AtcaBadParam;
        expected_bad_4 = AtcaStatus::AtcaInvalidSize;
        expected_bad_5 = AtcaStatus::AtcaBadParam;
        expected_bad_6 = AtcaStatus::AtcaBadParam;
    }

    // slot_id is too big
    let result_bad_1 = device.cipher_encrypt(
        CipherAlgorithm::Ofb(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &mut data_ok,
    );

    // slot holds a key other than AES
    let result_bad_2 =
        device.cipher_encrypt(CipherAlgorithm::Ofb(param_ok.clone()), 0x00, &mut data_ok);

    // slot_id points to TEMP_KEY but no key data
    let result_bad_3 = device.cipher_encrypt(
        CipherAlgorithm::Ofb(param_bad_no_key),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // no data to encrypt
    let result_bad_4 = device.cipher_encrypt(
        CipherAlgorithm::Ofb(param_ok),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_empty,
    );

    // no IV in param
    let result_bad_5 = device.cipher_encrypt(
        CipherAlgorithm::Ofb(param_bad_no_iv),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // wrong key length
    let result_bad_6 = device.cipher_encrypt(
        CipherAlgorithm::Ofb(param_bad_wrong_key_length),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_bad_1, expected_bad_1);
    assert_eq!(result_bad_2, expected_bad_2);
    assert_eq!(result_bad_3, expected_bad_3);
    assert_eq!(result_bad_4, expected_bad_4);
    assert_eq!(result_bad_5, expected_bad_5);
    assert_eq!(result_bad_6, expected_bad_6);
}

#[test]
#[serial]
fn cipher_ofb_decrypt_proper_data() {
    const DATA_64_SIZE: usize = 64;
    const DATA_24_SIZE: usize = 24;
    const DATA_16_SIZE: usize = 16;
    const DATA_2_SIZE: usize = 2;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    // Test Vector from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_OFB.pdf
    let iv = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];

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

    let cipher_text = [
        0x3B, 0x3F, 0xD9, 0x2E, 0xB7, 0x2D, 0xAD, 0x20, 0x33, 0x34, 0x49, 0xF8, 0xE8, 0x3C, 0xFB,
        0x4A, 0x77, 0x89, 0x50, 0x8D, 0x16, 0x91, 0x8F, 0x03, 0xF5, 0x3C, 0x52, 0xDA, 0xC5, 0x4E,
        0xD8, 0x25, 0x97, 0x40, 0x05, 0x1E, 0x9C, 0x5F, 0xEC, 0xF6, 0x43, 0x44, 0xF7, 0xA8, 0x22,
        0x60, 0xED, 0xCC, 0x30, 0x4C, 0x65, 0x28, 0xF6, 0x59, 0xC7, 0x78, 0x66, 0xA5, 0x10, 0xD9,
        0xC1, 0xD6, 0xAE, 0x5E,
    ];

    let mut data_64: Vec<u8> = Vec::new();
    data_64.extend_from_slice(&cipher_text[..DATA_64_SIZE]);
    let mut data_64_internal_key: Vec<u8> = Vec::new();
    data_64_internal_key.extend_from_slice(&cipher_text[..DATA_64_SIZE]);
    let mut data_24: Vec<u8> = Vec::new();
    data_24.extend_from_slice(&cipher_text[..DATA_24_SIZE]);
    let mut data_16: Vec<u8> = Vec::new();
    data_16.extend_from_slice(&cipher_text[..DATA_16_SIZE]);
    let mut data_2: Vec<u8> = Vec::new();
    data_2.extend_from_slice(&cipher_text[..DATA_2_SIZE]);

    let param = CipherParam {
        iv: Some(iv),
        key: Some(aes_key.to_vec()),
        ..Default::default()
    };
    let param_internal_key = CipherParam {
        iv: Some(iv),
        ..Default::default()
    };

    let mut expected_64 = AtcaStatus::AtcaBadParam;
    let mut expected_64_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_24 = AtcaStatus::AtcaBadParam;
    let mut expected_16 = AtcaStatus::AtcaBadParam;
    let mut expected_2 = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_64 = AtcaStatus::AtcaNotLocked;
        expected_64_internal_key = AtcaStatus::AtcaNotLocked;
        expected_24 = AtcaStatus::AtcaNotLocked;
        expected_16 = AtcaStatus::AtcaNotLocked;
        expected_2 = AtcaStatus::AtcaNotLocked;
        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected_64 = AtcaStatus::AtcaSuccess;
        expected_64_internal_key = AtcaStatus::AtcaSuccess;
        expected_24 = AtcaStatus::AtcaSuccess;
        expected_16 = AtcaStatus::AtcaSuccess;
        expected_2 = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;
    }

    let result_64 = device.cipher_decrypt(
        CipherAlgorithm::Ofb(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_64,
    );
    let result_64_internal_key = device.cipher_decrypt(
        CipherAlgorithm::Ofb(param_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_64_internal_key,
    );
    let result_24 = device.cipher_decrypt(
        CipherAlgorithm::Ofb(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_24,
    );
    let result_16 = device.cipher_decrypt(
        CipherAlgorithm::Ofb(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_16,
    );
    let result_2 = device.cipher_decrypt(
        CipherAlgorithm::Ofb(param),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_2,
    );

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert_eq!(data_64, plain_text.to_vec());
        assert_eq!(data_64_internal_key, plain_text.to_vec());
        assert_eq!(data_24, plain_text[..DATA_24_SIZE].to_vec());
        assert_eq!(data_16, plain_text[..DATA_16_SIZE].to_vec());
        assert_eq!(data_2, plain_text[..DATA_2_SIZE].to_vec());
    }
    assert_eq!(result_64, expected_64);
    assert_eq!(result_64_internal_key, expected_64_internal_key);
    assert_eq!(result_24, expected_24);
    assert_eq!(result_16, expected_16);
    assert_eq!(result_2, expected_2);
}

#[test]
#[serial]
fn cipher_ofb_decrypt_bad_data() {
    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let mut data_ok: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE];
    let mut data_empty: Vec<u8> = Vec::new();

    let param_ok = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_wrong_key_length = CipherParam {
        key: Some(vec![0x00; ATCA_AES_DATA_SIZE + 1]),
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_no_key = CipherParam {
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_no_iv = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };

    let mut expected_bad_1 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_2 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_3 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_4 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_5 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_6 = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_bad_1 = AtcaStatus::AtcaNotLocked;
        expected_bad_2 = AtcaStatus::AtcaNotLocked;
        expected_bad_3 = AtcaStatus::AtcaNotLocked;
        expected_bad_4 = AtcaStatus::AtcaNotLocked;
        expected_bad_5 = AtcaStatus::AtcaNotLocked;
        expected_bad_6 = AtcaStatus::AtcaNotLocked;
    }

    if chip_is_locked && device.is_aes_enabled() {
        expected_bad_1 = AtcaStatus::AtcaInvalidId;
        expected_bad_2 = AtcaStatus::AtcaInvalidId;
        expected_bad_3 = AtcaStatus::AtcaBadParam;
        expected_bad_4 = AtcaStatus::AtcaInvalidSize;
        expected_bad_5 = AtcaStatus::AtcaBadParam;
        expected_bad_6 = AtcaStatus::AtcaBadParam;
    }

    // slot_id is too big
    let result_bad_1 = device.cipher_decrypt(
        CipherAlgorithm::Ofb(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &mut data_ok,
    );

    // slot holds a key other than AES
    let result_bad_2 =
        device.cipher_decrypt(CipherAlgorithm::Ofb(param_ok.clone()), 0x00, &mut data_ok);

    // slot_id points to TEMP_KEY but no key data
    let result_bad_3 = device.cipher_decrypt(
        CipherAlgorithm::Cfb(param_bad_no_key),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // no data to encrypt
    let result_bad_4 = device.cipher_decrypt(
        CipherAlgorithm::Ofb(param_ok),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_empty,
    );

    // no IV in param
    let result_bad_5 = device.cipher_decrypt(
        CipherAlgorithm::Ofb(param_bad_no_iv),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // wrong key length
    let result_bad_6 = device.cipher_decrypt(
        CipherAlgorithm::Ofb(param_bad_wrong_key_length),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_bad_1, expected_bad_1);
    assert_eq!(result_bad_2, expected_bad_2);
    assert_eq!(result_bad_3, expected_bad_3);
    assert_eq!(result_bad_4, expected_bad_4);
    assert_eq!(result_bad_5, expected_bad_5);
    assert_eq!(result_bad_6, expected_bad_6);
}

#[test]
#[serial]
fn aes_ctr_internal_functions() {
    use cryptoauthlib_sys::atca_aes_ctr_ctx_t;
    const COUNTER_SIZE: u8 = 4;

    let device = test_setup();

    let iv_ok: [u8; ATCA_AES_DATA_SIZE] = [0x00; ATCA_AES_DATA_SIZE];
    let iv_bad_len: [u8; ATCA_AES_DATA_SIZE - 1] = [0x00; ATCA_AES_DATA_SIZE - 1];

    let mut result_bad_1 = AtcaStatus::AtcaUnknown;
    let result_1: AtcaStatus;
    let result_2: AtcaStatus;

    let mut ctx: atca_aes_ctr_ctx_t = {
        let ctx = MaybeUninit::<atca_aes_ctr_ctx_t>::zeroed();
        unsafe { ctx.assume_init() }
    };

    match device.aes_ctr_init(ATCA_ATECC_SLOTS_COUNT, COUNTER_SIZE, &iv_bad_len) {
        Ok(_) => (),
        Err(err) => result_bad_1 = err,
    }

    match device.aes_ctr_init(ATCA_ATECC_SLOTS_COUNT, COUNTER_SIZE, &iv_ok) {
        Ok(val) => {
            ctx = val;
            result_1 = AtcaStatus::AtcaSuccess;
        }
        Err(err) => result_1 = err,
    }

    match device.aes_ctr_increment(ctx) {
        Ok(val) => {
            ctx = val;
            result_2 = AtcaStatus::AtcaSuccess;
        }
        Err(err) => result_2 = err,
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_bad_1, AtcaStatus::AtcaInvalidSize);
    assert_eq!(result_1, AtcaStatus::AtcaSuccess);
    assert_eq!(result_2, AtcaStatus::AtcaSuccess);
    assert_eq!(ctx.key_id, ATCA_ATECC_TEMPKEY_KEYID);
    assert_eq!(ctx.counter_size, COUNTER_SIZE);
    assert_eq!(ctx.cb[ATCA_AES_DATA_SIZE - 1], 0x01);
}

#[test]
#[serial]
fn cipher_ctr_encrypt_proper_data() {
    const DATA_64_SIZE: usize = 64;
    const DATA_24_SIZE: usize = 24;
    const DATA_16_SIZE: usize = 16;
    const DATA_2_SIZE: usize = 2;
    const AES_KEY_SLOT_IDX: u8 = 0x09;
    const AES_CTR_COUNTER_SIZE: u8 = 4;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    // Test Vector from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CTR.pdf
    let iv = [
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE,
        0xFF,
    ];

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

    let cipher_text = [
        0x87, 0x4D, 0x61, 0x91, 0xB6, 0x20, 0xE3, 0x26, 0x1B, 0xEF, 0x68, 0x64, 0x99, 0x0D, 0xB6,
        0xCE, 0x98, 0x06, 0xF6, 0x6B, 0x79, 0x70, 0xFD, 0xFF, 0x86, 0x17, 0x18, 0x7B, 0xB9, 0xFF,
        0xFD, 0xFF, 0x5A, 0xE4, 0xDF, 0x3E, 0xDB, 0xD5, 0xD3, 0x5E, 0x5B, 0x4F, 0x09, 0x02, 0x0D,
        0xB0, 0x3E, 0xAB, 0x1E, 0x03, 0x1D, 0xDA, 0x2F, 0xBE, 0x03, 0xD1, 0x79, 0x21, 0x70, 0xA0,
        0xF3, 0x00, 0x9C, 0xEE,
    ];

    let mut data_64: Vec<u8> = Vec::new();
    data_64.extend_from_slice(&plain_text[..DATA_64_SIZE]);
    let mut data_64_internal_key: Vec<u8> = Vec::new();
    data_64_internal_key.extend_from_slice(&plain_text[..DATA_64_SIZE]);
    let mut data_24: Vec<u8> = Vec::new();
    data_24.extend_from_slice(&plain_text[..DATA_24_SIZE]);
    let mut data_16: Vec<u8> = Vec::new();
    data_16.extend_from_slice(&plain_text[..DATA_16_SIZE]);
    let mut data_2: Vec<u8> = Vec::new();
    data_2.extend_from_slice(&plain_text[..DATA_2_SIZE]);

    let param = CipherParam {
        iv: Some(iv),
        counter_size: Some(AES_CTR_COUNTER_SIZE),
        key: Some(aes_key.to_vec()),
    };
    let param_internal_key = CipherParam {
        iv: Some(iv),
        counter_size: Some(AES_CTR_COUNTER_SIZE),
        ..Default::default()
    };

    let mut expected_64 = AtcaStatus::AtcaBadParam;
    let mut expected_64_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_24 = AtcaStatus::AtcaBadParam;
    let mut expected_16 = AtcaStatus::AtcaBadParam;
    let mut expected_2 = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_64 = AtcaStatus::AtcaNotLocked;
        expected_64_internal_key = AtcaStatus::AtcaNotLocked;
        expected_24 = AtcaStatus::AtcaNotLocked;
        expected_16 = AtcaStatus::AtcaNotLocked;
        expected_2 = AtcaStatus::AtcaNotLocked;
        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected_64 = AtcaStatus::AtcaSuccess;
        expected_64_internal_key = AtcaStatus::AtcaSuccess;
        expected_24 = AtcaStatus::AtcaSuccess;
        expected_16 = AtcaStatus::AtcaSuccess;
        expected_2 = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;
    }

    let result_64 = device.cipher_encrypt(
        CipherAlgorithm::Ctr(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_64,
    );
    let result_64_internal_key = device.cipher_encrypt(
        CipherAlgorithm::Ctr(param_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_64_internal_key,
    );
    let result_24 = device.cipher_encrypt(
        CipherAlgorithm::Ctr(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_24,
    );
    let result_16 = device.cipher_encrypt(
        CipherAlgorithm::Ctr(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_16,
    );
    let result_2 = device.cipher_encrypt(
        CipherAlgorithm::Ctr(param),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_2,
    );

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert_eq!(data_64, cipher_text.to_vec());
        assert_eq!(data_64_internal_key, cipher_text.to_vec());
        assert_eq!(data_24, cipher_text[..DATA_24_SIZE].to_vec());
        assert_eq!(data_16, cipher_text[..DATA_16_SIZE].to_vec());
        assert_eq!(data_2, cipher_text[..DATA_2_SIZE].to_vec());
    }
    assert_eq!(result_64, expected_64);
    assert_eq!(result_64_internal_key, expected_64_internal_key);
    assert_eq!(result_24, expected_24);
    assert_eq!(result_16, expected_16);
    assert_eq!(result_2, expected_2);
}

#[test]
#[serial]
fn cipher_ctr_encrypt_bad_data() {
    const AES_CTR_COUNTER_SIZE_OK: u8 = 4;
    const AES_CTR_COUNTER_SIZE_TOO_BIG: u8 = (ATCA_AES_DATA_SIZE + 1) as u8;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let mut data_ok: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE];
    let mut data_empty: Vec<u8> = Vec::new();

    let param_ok = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        counter_size: Some(AES_CTR_COUNTER_SIZE_OK),
    };
    let param_bad_wrong_key_length = CipherParam {
        key: Some(vec![0x00; ATCA_AES_DATA_SIZE + 1]),
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        counter_size: Some(AES_CTR_COUNTER_SIZE_OK),
    };
    let param_bad_no_key = CipherParam {
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        counter_size: Some(AES_CTR_COUNTER_SIZE_OK),
        ..Default::default()
    };
    let param_bad_no_iv = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        counter_size: Some(AES_CTR_COUNTER_SIZE_OK),
        ..Default::default()
    };
    let param_bad_no_counter_size = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_counter_size_too_big = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        counter_size: Some(AES_CTR_COUNTER_SIZE_TOO_BIG),
    };

    let mut expected_bad_1 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_2 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_3 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_4 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_5 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_6 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_7 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_8 = AtcaStatus::AtcaBadParam;

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
        expected_bad_5 = AtcaStatus::AtcaBadParam;
        expected_bad_6 = AtcaStatus::AtcaBadParam;
        expected_bad_7 = AtcaStatus::AtcaInvalidSize;
        expected_bad_8 = AtcaStatus::AtcaBadParam;
    }

    // slot_id is too big
    let result_bad_1 = device.cipher_encrypt(
        CipherAlgorithm::Ctr(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &mut data_ok,
    );

    // slot holds a key other than AES
    let result_bad_2 =
        device.cipher_encrypt(CipherAlgorithm::Ctr(param_ok.clone()), 0x00, &mut data_ok);

    // slot_id points to TEMP_KEY but no key data
    let result_bad_3 = device.cipher_encrypt(
        CipherAlgorithm::Ctr(param_bad_no_key),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // no data to encrypt
    let result_bad_4 = device.cipher_encrypt(
        CipherAlgorithm::Ctr(param_ok),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_empty,
    );

    // no IV in param
    let result_bad_5 = device.cipher_encrypt(
        CipherAlgorithm::Ctr(param_bad_no_iv),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // no 'counter_size' in param
    let result_bad_6 = device.cipher_encrypt(
        CipherAlgorithm::Ctr(param_bad_no_counter_size),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // 'counter_size' is too big
    let result_bad_7 = device.cipher_encrypt(
        CipherAlgorithm::Ctr(param_bad_counter_size_too_big),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // wrong key length
    let result_bad_8 = device.cipher_encrypt(
        CipherAlgorithm::Ctr(param_bad_wrong_key_length),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

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
fn cipher_ctr_decrypt_proper_data() {
    const DATA_64_SIZE: usize = 64;
    const DATA_24_SIZE: usize = 24;
    const DATA_16_SIZE: usize = 16;
    const DATA_2_SIZE: usize = 2;
    const AES_KEY_SLOT_IDX: u8 = 0x09;
    const AES_CTR_COUNTER_SIZE: u8 = 4;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    // Test Vector from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CTR.pdf
    let iv = [
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE,
        0xFF,
    ];

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

    let cipher_text = [
        0x87, 0x4D, 0x61, 0x91, 0xB6, 0x20, 0xE3, 0x26, 0x1B, 0xEF, 0x68, 0x64, 0x99, 0x0D, 0xB6,
        0xCE, 0x98, 0x06, 0xF6, 0x6B, 0x79, 0x70, 0xFD, 0xFF, 0x86, 0x17, 0x18, 0x7B, 0xB9, 0xFF,
        0xFD, 0xFF, 0x5A, 0xE4, 0xDF, 0x3E, 0xDB, 0xD5, 0xD3, 0x5E, 0x5B, 0x4F, 0x09, 0x02, 0x0D,
        0xB0, 0x3E, 0xAB, 0x1E, 0x03, 0x1D, 0xDA, 0x2F, 0xBE, 0x03, 0xD1, 0x79, 0x21, 0x70, 0xA0,
        0xF3, 0x00, 0x9C, 0xEE,
    ];

    let mut data_64: Vec<u8> = Vec::new();
    data_64.extend_from_slice(&cipher_text[..DATA_64_SIZE]);
    let mut data_64_internal_key: Vec<u8> = Vec::new();
    data_64_internal_key.extend_from_slice(&cipher_text[..DATA_64_SIZE]);
    let mut data_24: Vec<u8> = Vec::new();
    data_24.extend_from_slice(&cipher_text[..DATA_24_SIZE]);
    let mut data_16: Vec<u8> = Vec::new();
    data_16.extend_from_slice(&cipher_text[..DATA_16_SIZE]);
    let mut data_2: Vec<u8> = Vec::new();
    data_2.extend_from_slice(&cipher_text[..DATA_2_SIZE]);

    let param = CipherParam {
        iv: Some(iv),
        counter_size: Some(AES_CTR_COUNTER_SIZE),
        key: Some(aes_key.to_vec()),
    };
    let param_internal_key = CipherParam {
        iv: Some(iv),
        counter_size: Some(AES_CTR_COUNTER_SIZE),
        ..Default::default()
    };

    let mut expected_64 = AtcaStatus::AtcaBadParam;
    let mut expected_64_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_24 = AtcaStatus::AtcaBadParam;
    let mut expected_16 = AtcaStatus::AtcaBadParam;
    let mut expected_2 = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_64 = AtcaStatus::AtcaNotLocked;
        expected_64_internal_key = AtcaStatus::AtcaNotLocked;
        expected_24 = AtcaStatus::AtcaNotLocked;
        expected_16 = AtcaStatus::AtcaNotLocked;
        expected_2 = AtcaStatus::AtcaNotLocked;
        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected_64 = AtcaStatus::AtcaSuccess;
        expected_64_internal_key = AtcaStatus::AtcaSuccess;
        expected_24 = AtcaStatus::AtcaSuccess;
        expected_16 = AtcaStatus::AtcaSuccess;
        expected_2 = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;
    }

    let result_64 = device.cipher_decrypt(
        CipherAlgorithm::Ctr(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_64,
    );
    let result_64_internal_key = device.cipher_decrypt(
        CipherAlgorithm::Ctr(param_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_64_internal_key,
    );
    let result_24 = device.cipher_decrypt(
        CipherAlgorithm::Ctr(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_24,
    );
    let result_16 = device.cipher_decrypt(
        CipherAlgorithm::Ctr(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_16,
    );
    let result_2 = device.cipher_decrypt(
        CipherAlgorithm::Ctr(param),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_2,
    );

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert_eq!(data_64, plain_text.to_vec());
        assert_eq!(data_64_internal_key, plain_text.to_vec());
        assert_eq!(data_24, plain_text[..DATA_24_SIZE].to_vec());
        assert_eq!(data_16, plain_text[..DATA_16_SIZE].to_vec());
        assert_eq!(data_2, plain_text[..DATA_2_SIZE].to_vec());
    }
    assert_eq!(result_64, expected_64);
    assert_eq!(result_64_internal_key, expected_64_internal_key);
    assert_eq!(result_24, expected_24);
    assert_eq!(result_16, expected_16);
    assert_eq!(result_2, expected_2);
}

#[test]
#[serial]
fn cipher_ctr_decrypt_bad_data() {
    const AES_CTR_COUNTER_SIZE_OK: u8 = 4;
    const AES_CTR_COUNTER_SIZE_TOO_BIG: u8 = (ATCA_AES_DATA_SIZE + 1) as u8;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let mut data_ok: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE];
    let mut data_empty: Vec<u8> = Vec::new();

    let param_ok = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        counter_size: Some(AES_CTR_COUNTER_SIZE_OK),
    };
    let param_bad_wrong_key_length = CipherParam {
        key: Some(vec![0x00; ATCA_AES_DATA_SIZE + 1]),
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        counter_size: Some(AES_CTR_COUNTER_SIZE_OK),
    };
    let param_bad_no_key = CipherParam {
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        counter_size: Some(AES_CTR_COUNTER_SIZE_OK),
        ..Default::default()
    };
    let param_bad_no_iv = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        counter_size: Some(AES_CTR_COUNTER_SIZE_OK),
        ..Default::default()
    };
    let param_bad_no_counter_size = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_counter_size_too_big = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        counter_size: Some(AES_CTR_COUNTER_SIZE_TOO_BIG),
    };

    let mut expected_bad_1 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_2 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_3 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_4 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_5 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_6 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_7 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_8 = AtcaStatus::AtcaBadParam;

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
        expected_bad_5 = AtcaStatus::AtcaBadParam;
        expected_bad_6 = AtcaStatus::AtcaBadParam;
        expected_bad_7 = AtcaStatus::AtcaInvalidSize;
        expected_bad_8 = AtcaStatus::AtcaBadParam;
    }

    // slot_id is too big
    let result_bad_1 = device.cipher_decrypt(
        CipherAlgorithm::Ctr(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &mut data_ok,
    );

    // slot holds a key other than AES
    let result_bad_2 =
        device.cipher_decrypt(CipherAlgorithm::Ctr(param_ok.clone()), 0x00, &mut data_ok);

    // slot_id points to TEMP_KEY but no key data
    let result_bad_3 = device.cipher_decrypt(
        CipherAlgorithm::Ctr(param_bad_no_key),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // no data to encrypt
    let result_bad_4 = device.cipher_decrypt(
        CipherAlgorithm::Ctr(param_ok),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_empty,
    );

    // no IV in param
    let result_bad_5 = device.cipher_decrypt(
        CipherAlgorithm::Ctr(param_bad_no_iv),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // no 'counter_size' in param
    let result_bad_6 = device.cipher_decrypt(
        CipherAlgorithm::Ctr(param_bad_no_counter_size),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // 'counter_size' is too big
    let result_bad_7 = device.cipher_decrypt(
        CipherAlgorithm::Ctr(param_bad_counter_size_too_big),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // wrong key length
    let result_bad_8 = device.cipher_decrypt(
        CipherAlgorithm::Ctr(param_bad_wrong_key_length),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

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
