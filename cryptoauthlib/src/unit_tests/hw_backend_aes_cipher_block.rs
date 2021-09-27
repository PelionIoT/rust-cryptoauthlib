// Types
use super::{AtcaStatus, CipherAlgorithm, CipherParam, KeyType};
// Constants
use super::{
    ATCA_AES_DATA_SIZE, ATCA_AES_KEY_SIZE, ATCA_ATECC_SLOTS_COUNT, ATCA_ATECC_TEMPKEY_KEYID,
};

use super::hw_backend_common::*;
use serial_test::serial;

#[test]
#[serial]
fn aes_cipher_block_bad_data() {
    let device = test_setup();

    let data_bad_len: [u8; (ATCA_AES_DATA_SIZE - 1)] = [0x00; (ATCA_AES_DATA_SIZE - 1)];

    let mut result_bad_1 = AtcaStatus::AtcaUnknown;
    let mut result_bad_2 = AtcaStatus::AtcaUnknown;
    let mut result_bad_3 = AtcaStatus::AtcaUnknown;

    match device.aes_encrypt_block(ATCA_ATECC_TEMPKEY_KEYID, 0x00, &data_bad_len) {
        Ok(_) => (),
        Err(err) => result_bad_1 = err,
    }

    match device.aes_decrypt_block(ATCA_ATECC_TEMPKEY_KEYID, 0x00, &data_bad_len) {
        Ok(_) => (),
        Err(err) => result_bad_2 = err,
    }

    match device.aes_cbc_init(ATCA_ATECC_SLOTS_COUNT, &data_bad_len) {
        Ok(_) => (),
        Err(err) => result_bad_3 = err,
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_bad_1, AtcaStatus::AtcaInvalidSize);
    assert_eq!(result_bad_2, AtcaStatus::AtcaInvalidSize);
    assert_eq!(result_bad_3, AtcaStatus::AtcaInvalidSize);
}

#[test]
#[serial]
fn cipher_ecb_encrypt_proper_data() {
    const DATA_64_SIZE: usize = 64;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    // Test Vector from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ECB.pdf
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
        0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF,
        0x97, 0xF5, 0xD3, 0xD5, 0x85, 0x03, 0xB9, 0x69, 0x9D, 0xE7, 0x85, 0x89, 0x5A, 0x96, 0xFD,
        0xBA, 0xAF, 0x43, 0xB1, 0xCD, 0x7F, 0x59, 0x8E, 0xCE, 0x23, 0x88, 0x1B, 0x00, 0xE3, 0xED,
        0x03, 0x06, 0x88, 0x7B, 0x0C, 0x78, 0x5E, 0x27, 0xE8, 0xAD, 0x3F, 0x82, 0x23, 0x20, 0x71,
        0x04, 0x72, 0x5D, 0xD4,
    ];

    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&plain_text[..DATA_64_SIZE]);
    let mut data_internal_key: Vec<u8> = Vec::new();
    data_internal_key.extend_from_slice(&plain_text[..DATA_64_SIZE]);

    let param = CipherParam {
        key: Some(aes_key.to_vec()),
        ..Default::default()
    };
    let param_internal_key = CipherParam {
        ..Default::default()
    };

    let mut expected = AtcaStatus::AtcaBadParam;
    let mut expected_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected = AtcaStatus::AtcaNotLocked;
        expected_internal_key = AtcaStatus::AtcaNotLocked;
        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected = AtcaStatus::AtcaSuccess;
        expected_internal_key = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;
    }

    let result = device.cipher_encrypt(
        CipherAlgorithm::Ecb(param),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    );
    let result_internal_key = device.cipher_encrypt(
        CipherAlgorithm::Ecb(param_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_internal_key,
    );

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert_eq!(data, cipher_text.to_vec());
        assert_eq!(data_internal_key, cipher_text.to_vec());
    }
    assert_eq!(result, expected);
    assert_eq!(result_internal_key, expected_internal_key);
}

#[test]
#[serial]
fn cipher_ecb_encrypt_bad_data() {
    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let mut data_ok: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE];
    let mut data_bad_len: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE - 1];
    let mut data_empty: Vec<u8> = Vec::new();

    let param_ok = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_wrong_key_length = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE + 1]),
        ..Default::default()
    };
    let param_bad_no_key = CipherParam {
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
        expected_bad_5 = AtcaStatus::AtcaInvalidSize;
        expected_bad_6 = AtcaStatus::AtcaBadParam;
    }

    // slot_id is too big
    let result_bad_1 = device.cipher_encrypt(
        CipherAlgorithm::Ecb(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &mut data_ok,
    );

    // slot holds a key other than AES
    let result_bad_2 =
        device.cipher_encrypt(CipherAlgorithm::Ecb(param_ok.clone()), 0x00, &mut data_ok);

    // slot_id points to TEMP_KEY but no key data
    let result_bad_3 = device.cipher_encrypt(
        CipherAlgorithm::Ecb(param_bad_no_key),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // no data to encrypt
    let result_bad_4 = device.cipher_encrypt(
        CipherAlgorithm::Ecb(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_empty,
    );

    // bad amount of data to encrypt
    let result_bad_5 = device.cipher_encrypt(
        CipherAlgorithm::Ecb(param_ok),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_bad_len,
    );

    // wrong key length
    let result_bad_6 = device.cipher_encrypt(
        CipherAlgorithm::Ecb(param_bad_wrong_key_length),
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
fn cipher_ecb_decrypt_proper_data() {
    const DATA_64_SIZE: usize = 64;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    // Test Vector from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ECB.pdf
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
        0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF,
        0x97, 0xF5, 0xD3, 0xD5, 0x85, 0x03, 0xB9, 0x69, 0x9D, 0xE7, 0x85, 0x89, 0x5A, 0x96, 0xFD,
        0xBA, 0xAF, 0x43, 0xB1, 0xCD, 0x7F, 0x59, 0x8E, 0xCE, 0x23, 0x88, 0x1B, 0x00, 0xE3, 0xED,
        0x03, 0x06, 0x88, 0x7B, 0x0C, 0x78, 0x5E, 0x27, 0xE8, 0xAD, 0x3F, 0x82, 0x23, 0x20, 0x71,
        0x04, 0x72, 0x5D, 0xD4,
    ];

    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&cipher_text[..DATA_64_SIZE]);
    let mut data_internal_key: Vec<u8> = Vec::new();
    data_internal_key.extend_from_slice(&cipher_text[..DATA_64_SIZE]);

    let param = CipherParam {
        key: Some(aes_key.to_vec()),
        ..Default::default()
    };
    let param_internal_key = CipherParam {
        ..Default::default()
    };

    let mut expected = AtcaStatus::AtcaBadParam;
    let mut expected_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected = AtcaStatus::AtcaNotLocked;
        expected_internal_key = AtcaStatus::AtcaNotLocked;
        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected = AtcaStatus::AtcaSuccess;
        expected_internal_key = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;
    }

    let result = device.cipher_decrypt(
        CipherAlgorithm::Ecb(param),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    );
    let result_internal_key = device.cipher_decrypt(
        CipherAlgorithm::Ecb(param_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_internal_key,
    );

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert_eq!(data, plain_text.to_vec());
        assert_eq!(data_internal_key, plain_text.to_vec());
    }
    assert_eq!(result, expected);
    assert_eq!(result_internal_key, expected_internal_key);
}

#[test]
#[serial]
fn cipher_ecb_decrypt_bad_data() {
    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let mut data_ok: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE];
    let mut data_bad_len: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE - 1];
    let mut data_empty: Vec<u8> = Vec::new();

    let param_ok = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_wrong_key_length = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE + 1]),
        ..Default::default()
    };
    let param_bad_no_key = CipherParam {
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
        expected_bad_5 = AtcaStatus::AtcaInvalidSize;
        expected_bad_6 = AtcaStatus::AtcaBadParam;
    }

    // slot_id is too big
    let result_bad_1 = device.cipher_decrypt(
        CipherAlgorithm::Ecb(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &mut data_ok,
    );

    // slot holds a key other than AES
    let result_bad_2 =
        device.cipher_decrypt(CipherAlgorithm::Ecb(param_ok.clone()), 0x00, &mut data_ok);

    // slot_id points to TEMP_KEY but no key data
    let result_bad_3 = device.cipher_decrypt(
        CipherAlgorithm::Ecb(param_bad_no_key),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // no data to encrypt
    let result_bad_4 = device.cipher_decrypt(
        CipherAlgorithm::Ecb(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_empty,
    );

    // bad amount of data to encrypt
    let result_bad_5 = device.cipher_decrypt(
        CipherAlgorithm::Ecb(param_ok),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_bad_len,
    );

    // wrong key length
    let result_bad_6 = device.cipher_decrypt(
        CipherAlgorithm::Ecb(param_bad_wrong_key_length),
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
fn cipher_cbc_encrypt_proper_data() {
    const DATA_64_SIZE: usize = 64;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    // Test Vector from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CBC.pdf
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
        0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19,
        0x7D, 0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76,
        0x78, 0xB2, 0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22,
        0x22, 0x95, 0x16, 0x3F, 0xF1, 0xCA, 0xA1, 0x68, 0x1F, 0xAC, 0x09, 0x12, 0x0E, 0xCA, 0x30,
        0x75, 0x86, 0xE1, 0xA7,
    ];

    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&plain_text[..DATA_64_SIZE]);
    let mut data_internal_key: Vec<u8> = Vec::new();
    data_internal_key.extend_from_slice(&plain_text[..DATA_64_SIZE]);

    let param = CipherParam {
        key: Some(aes_key.to_vec()),
        iv: Some(iv),
        ..Default::default()
    };
    let param_internal_key = CipherParam {
        iv: Some(iv),
        ..Default::default()
    };

    let mut expected = AtcaStatus::AtcaBadParam;
    let mut expected_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected = AtcaStatus::AtcaNotLocked;
        expected_internal_key = AtcaStatus::AtcaNotLocked;
        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected = AtcaStatus::AtcaSuccess;
        expected_internal_key = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;
    }

    let result = device.cipher_encrypt(
        CipherAlgorithm::Cbc(param),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    );
    let result_internal_key = device.cipher_encrypt(
        CipherAlgorithm::Cbc(param_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_internal_key,
    );

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert_eq!(data, cipher_text.to_vec());
        assert_eq!(data_internal_key, cipher_text.to_vec());
    }
    assert_eq!(result, expected);
    assert_eq!(result_internal_key, expected_internal_key);
}

#[test]
#[serial]
fn cipher_cbc_encrypt_bad_data() {
    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let mut data_ok: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE];
    let mut data_bad_len: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE - 1];
    let mut data_empty: Vec<u8> = Vec::new();

    let param_ok = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_wrong_key_length = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE + 1]),
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
    let mut expected_bad_7 = AtcaStatus::AtcaBadParam;

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
    }

    if chip_is_locked && device.is_aes_enabled() {
        expected_bad_1 = AtcaStatus::AtcaInvalidId;
        expected_bad_2 = AtcaStatus::AtcaInvalidId;
        expected_bad_3 = AtcaStatus::AtcaBadParam;
        expected_bad_4 = AtcaStatus::AtcaInvalidSize;
        expected_bad_5 = AtcaStatus::AtcaInvalidSize;
        expected_bad_6 = AtcaStatus::AtcaBadParam;
        expected_bad_7 = AtcaStatus::AtcaBadParam;
    }

    // slot_id is too big
    let result_bad_1 = device.cipher_encrypt(
        CipherAlgorithm::Cbc(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &mut data_ok,
    );

    // slot holds a key other than AES
    let result_bad_2 =
        device.cipher_encrypt(CipherAlgorithm::Cbc(param_ok.clone()), 0x00, &mut data_ok);

    // slot_id points to TEMP_KEY but no key data
    let result_bad_3 = device.cipher_encrypt(
        CipherAlgorithm::Cbc(param_bad_no_key),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // no data to encrypt
    let result_bad_4 = device.cipher_encrypt(
        CipherAlgorithm::Cbc(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_empty,
    );

    // bad amount of data to encrypt
    let result_bad_5 = device.cipher_encrypt(
        CipherAlgorithm::Cbc(param_ok),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_bad_len,
    );

    // no IV in param
    let result_bad_6 = device.cipher_encrypt(
        CipherAlgorithm::Cbc(param_bad_no_iv),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // wrong key length
    let result_bad_7 = device.cipher_encrypt(
        CipherAlgorithm::Cbc(param_bad_wrong_key_length),
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
}

#[test]
#[serial]
fn cipher_cbc_decrypt_proper_data() {
    const DATA_64_SIZE: usize = 64;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    // Test Vector from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CBC.pdf
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
        0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19,
        0x7D, 0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76,
        0x78, 0xB2, 0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22,
        0x22, 0x95, 0x16, 0x3F, 0xF1, 0xCA, 0xA1, 0x68, 0x1F, 0xAC, 0x09, 0x12, 0x0E, 0xCA, 0x30,
        0x75, 0x86, 0xE1, 0xA7,
    ];

    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&cipher_text[..DATA_64_SIZE]);
    let mut data_internal_key: Vec<u8> = Vec::new();
    data_internal_key.extend_from_slice(&cipher_text[..DATA_64_SIZE]);

    let param = CipherParam {
        key: Some(aes_key.to_vec()),
        iv: Some(iv),
        ..Default::default()
    };
    let param_internal_key = CipherParam {
        iv: Some(iv),
        ..Default::default()
    };

    let mut expected = AtcaStatus::AtcaBadParam;
    let mut expected_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected = AtcaStatus::AtcaNotLocked;
        expected_internal_key = AtcaStatus::AtcaNotLocked;
        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected = AtcaStatus::AtcaSuccess;
        expected_internal_key = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;
    }

    let result = device.cipher_decrypt(
        CipherAlgorithm::Cbc(param),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data,
    );
    let result_internal_key = device.cipher_decrypt(
        CipherAlgorithm::Cbc(param_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_internal_key,
    );

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert_eq!(data, plain_text.to_vec());
        assert_eq!(data_internal_key, plain_text.to_vec());
    }
    assert_eq!(result, expected);
    assert_eq!(result_internal_key, expected_internal_key);
}

#[test]
#[serial]
fn cipher_cbc_decrypt_bad_data() {
    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let mut data_ok: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE];
    let mut data_bad_len: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE - 1];
    let mut data_empty: Vec<u8> = Vec::new();

    let param_ok = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE]),
        iv: Some([0x00; ATCA_AES_KEY_SIZE]),
        ..Default::default()
    };
    let param_bad_wrong_key_length = CipherParam {
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE + 1]),
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
    let mut expected_bad_7 = AtcaStatus::AtcaBadParam;

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
    }

    if chip_is_locked && device.is_aes_enabled() {
        expected_bad_1 = AtcaStatus::AtcaInvalidId;
        expected_bad_2 = AtcaStatus::AtcaInvalidId;
        expected_bad_3 = AtcaStatus::AtcaBadParam;
        expected_bad_4 = AtcaStatus::AtcaInvalidSize;
        expected_bad_5 = AtcaStatus::AtcaInvalidSize;
        expected_bad_6 = AtcaStatus::AtcaBadParam;
        expected_bad_7 = AtcaStatus::AtcaBadParam;
    }

    // slot_id is too big
    let result_bad_1 = device.cipher_decrypt(
        CipherAlgorithm::Cbc(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &mut data_ok,
    );

    // slot holds a key other than AES
    let result_bad_2 =
        device.cipher_decrypt(CipherAlgorithm::Cbc(param_ok.clone()), 0x00, &mut data_ok);

    // slot_id points to TEMP_KEY but no key data
    let result_bad_3 = device.cipher_decrypt(
        CipherAlgorithm::Cbc(param_bad_no_key),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // no data to encrypt
    let result_bad_4 = device.cipher_decrypt(
        CipherAlgorithm::Cbc(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_empty,
    );

    // bad amount of data to encrypt
    let result_bad_5 = device.cipher_decrypt(
        CipherAlgorithm::Cbc(param_ok),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_bad_len,
    );

    // no IV in param
    let result_bad_6 = device.cipher_decrypt(
        CipherAlgorithm::Cbc(param_bad_no_iv),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // wrong key length
    let result_bad_7 = device.cipher_decrypt(
        CipherAlgorithm::Cbc(param_bad_wrong_key_length),
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
}

#[test]
#[serial]
fn cipher_cbc_pkcs7_encrypt_proper_data() {
    const DATA_64_SIZE: usize = 64;
    const DATA_17_SIZE: usize = 17;
    const DATA_15_SIZE: usize = 15;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

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

    let cipher_text_64 = [
        0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19,
        0x7D, 0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76,
        0x78, 0xB2, 0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22,
        0x22, 0x95, 0x16, 0x3F, 0xF1, 0xCA, 0xA1, 0x68, 0x1F, 0xAC, 0x09, 0x12, 0x0E, 0xCA, 0x30,
        0x75, 0x86, 0xE1, 0xA7, 0x8C, 0xB8, 0x28, 0x07, 0x23, 0x0E, 0x13, 0x21, 0xD3, 0xFA, 0xE0,
        0x0D, 0x18, 0xCC, 0x20, 0x12,
    ];

    let cipher_text_17 = [
        0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19,
        0x7D, 0x34, 0xD2, 0xD2, 0x60, 0x17, 0x31, 0x13, 0x00, 0x8C, 0x28, 0x11, 0x2C, 0x77, 0x66,
        0x8C, 0x86,
    ];

    let cipher_text_15 = [
        0x9B, 0xE1, 0xE5, 0x79, 0xD1, 0x07, 0xA1, 0x36, 0xC0, 0x31, 0xB6, 0x45, 0xA8, 0x8D, 0xA7,
        0x50,
    ];

    let mut data_64: Vec<u8> = Vec::new();
    data_64.extend_from_slice(&plain_text[..DATA_64_SIZE]);
    let mut data_64_internal_key: Vec<u8> = Vec::new();
    data_64_internal_key.extend_from_slice(&plain_text[..DATA_64_SIZE]);
    let mut data_17: Vec<u8> = Vec::new();
    data_17.extend_from_slice(&plain_text[..DATA_17_SIZE]);
    let mut data_15: Vec<u8> = Vec::new();
    data_15.extend_from_slice(&plain_text[..DATA_15_SIZE]);

    let param = CipherParam {
        key: Some(aes_key.to_vec()),
        iv: Some(iv),
        ..Default::default()
    };
    let param_internal_key = CipherParam {
        iv: Some(iv),
        ..Default::default()
    };

    let mut expected_64 = AtcaStatus::AtcaBadParam;
    let mut expected_64_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_17 = AtcaStatus::AtcaBadParam;
    let mut expected_15 = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_64 = AtcaStatus::AtcaNotLocked;
        expected_64_internal_key = AtcaStatus::AtcaNotLocked;
        expected_17 = AtcaStatus::AtcaNotLocked;
        expected_15 = AtcaStatus::AtcaNotLocked;
        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected_64 = AtcaStatus::AtcaSuccess;
        expected_64_internal_key = AtcaStatus::AtcaSuccess;
        expected_17 = AtcaStatus::AtcaSuccess;
        expected_15 = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;
    }

    let result_64 = device.cipher_encrypt(
        CipherAlgorithm::CbcPkcs7(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_64,
    );
    let result_64_internal_key = device.cipher_encrypt(
        CipherAlgorithm::CbcPkcs7(param_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_64_internal_key,
    );
    let result_17 = device.cipher_encrypt(
        CipherAlgorithm::CbcPkcs7(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_17,
    );
    let result_15 = device.cipher_encrypt(
        CipherAlgorithm::CbcPkcs7(param),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_15,
    );

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert_eq!(data_64, cipher_text_64.to_vec());
        assert_eq!(data_64_internal_key, cipher_text_64.to_vec());
        assert_eq!(data_17, cipher_text_17.to_vec());
        assert_eq!(data_15, cipher_text_15.to_vec());
    }
    assert_eq!(result_64, expected_64);
    assert_eq!(result_64_internal_key, expected_64_internal_key);
    assert_eq!(result_17, expected_17);
    assert_eq!(result_15, expected_15);
}

#[test]
#[serial]
fn cipher_cbc_pkcs7_encrypt_bad_data() {
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
        key: Some(vec![0x00; ATCA_AES_KEY_SIZE + 1]),
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
        CipherAlgorithm::CbcPkcs7(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &mut data_ok,
    );

    // slot holds a key other than AES
    let result_bad_2 = device.cipher_encrypt(
        CipherAlgorithm::CbcPkcs7(param_ok.clone()),
        0x00,
        &mut data_ok,
    );

    // slot_id points to TEMP_KEY but no key data
    let result_bad_3 = device.cipher_encrypt(
        CipherAlgorithm::CbcPkcs7(param_bad_no_key),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // no data to encrypt
    let result_bad_4 = device.cipher_encrypt(
        CipherAlgorithm::CbcPkcs7(param_ok),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_empty,
    );

    // no IV in param
    let result_bad_5 = device.cipher_encrypt(
        CipherAlgorithm::CbcPkcs7(param_bad_no_iv),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // wrong key length
    let result_bad_6 = device.cipher_encrypt(
        CipherAlgorithm::CbcPkcs7(param_bad_wrong_key_length),
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
fn cipher_cbc_pkcs7_decrypt_proper_data() {
    const DATA_17_SIZE: usize = 17;
    const DATA_15_SIZE: usize = 15;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

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

    let cipher_text_64 = [
        0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19,
        0x7D, 0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76,
        0x78, 0xB2, 0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22,
        0x22, 0x95, 0x16, 0x3F, 0xF1, 0xCA, 0xA1, 0x68, 0x1F, 0xAC, 0x09, 0x12, 0x0E, 0xCA, 0x30,
        0x75, 0x86, 0xE1, 0xA7, 0x8C, 0xB8, 0x28, 0x07, 0x23, 0x0E, 0x13, 0x21, 0xD3, 0xFA, 0xE0,
        0x0D, 0x18, 0xCC, 0x20, 0x12,
    ];

    let cipher_text_17 = [
        0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19,
        0x7D, 0x34, 0xD2, 0xD2, 0x60, 0x17, 0x31, 0x13, 0x00, 0x8C, 0x28, 0x11, 0x2C, 0x77, 0x66,
        0x8C, 0x86,
    ];

    let cipher_text_15 = [
        0x9B, 0xE1, 0xE5, 0x79, 0xD1, 0x07, 0xA1, 0x36, 0xC0, 0x31, 0xB6, 0x45, 0xA8, 0x8D, 0xA7,
        0x50,
    ];

    let mut data_64: Vec<u8> = Vec::new();
    data_64.extend_from_slice(&cipher_text_64);
    let mut data_64_internal_key: Vec<u8> = Vec::new();
    data_64_internal_key.extend_from_slice(&cipher_text_64);
    let mut data_17: Vec<u8> = Vec::new();
    data_17.extend_from_slice(&cipher_text_17);
    let mut data_15: Vec<u8> = Vec::new();
    data_15.extend_from_slice(&cipher_text_15);

    let param = CipherParam {
        key: Some(aes_key.to_vec()),
        iv: Some(iv),
        ..Default::default()
    };
    let param_internal_key = CipherParam {
        iv: Some(iv),
        ..Default::default()
    };

    let mut expected_64 = AtcaStatus::AtcaBadParam;
    let mut expected_64_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_17 = AtcaStatus::AtcaBadParam;
    let mut expected_15 = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_64 = AtcaStatus::AtcaNotLocked;
        expected_64_internal_key = AtcaStatus::AtcaNotLocked;
        expected_17 = AtcaStatus::AtcaNotLocked;
        expected_15 = AtcaStatus::AtcaNotLocked;
        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected_64 = AtcaStatus::AtcaSuccess;
        expected_64_internal_key = AtcaStatus::AtcaSuccess;
        expected_17 = AtcaStatus::AtcaSuccess;
        expected_15 = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;
    }

    let result_64 = device.cipher_decrypt(
        CipherAlgorithm::CbcPkcs7(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_64,
    );
    let result_64_internal_key = device.cipher_decrypt(
        CipherAlgorithm::CbcPkcs7(param_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_64_internal_key,
    );
    let result_17 = device.cipher_decrypt(
        CipherAlgorithm::CbcPkcs7(param.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_17,
    );
    let result_15 = device.cipher_decrypt(
        CipherAlgorithm::CbcPkcs7(param),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_15,
    );

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert_eq!(data_64, plain_text.to_vec());
        assert_eq!(data_64_internal_key, plain_text.to_vec());
        assert_eq!(data_17, plain_text[..DATA_17_SIZE].to_vec());
        assert_eq!(data_15, plain_text[..DATA_15_SIZE].to_vec());
    }
    assert_eq!(result_64, expected_64);
    assert_eq!(result_64_internal_key, expected_64_internal_key);
    assert_eq!(result_17, expected_17);
    assert_eq!(result_15, expected_15);
}

#[test]
#[serial]
fn cipher_cbc_pkcs7_decrypt_bad_data() {
    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let iv = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];

    let aes_key = [
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F,
        0x3C,
    ];

    let mut data_ok: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE];
    let mut data_bad_len: Vec<u8> = vec![0x00; ATCA_AES_DATA_SIZE - 1];
    let mut data_bad_padding = vec![
        0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19,
        0x7D,
    ];
    let mut data_empty: Vec<u8> = Vec::new();

    let param_ok = CipherParam {
        key: Some(aes_key.to_vec()),
        iv: Some(iv),
        ..Default::default()
    };
    let param_bad_wrong_key_length = CipherParam {
        key: Some(vec![0x00; ATCA_AES_DATA_SIZE + 1]),
        iv: Some(iv),
        ..Default::default()
    };
    let param_bad_no_key = CipherParam {
        iv: Some(iv),
        ..Default::default()
    };
    let param_bad_no_iv = CipherParam {
        key: Some(aes_key.to_vec()),
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
        expected_bad_6 = AtcaStatus::AtcaInvalidSize;
        expected_bad_7 = AtcaStatus::AtcaInvalidSize;
        expected_bad_8 = AtcaStatus::AtcaBadParam;
    }

    // slot_id is too big
    let result_bad_1 = device.cipher_decrypt(
        CipherAlgorithm::CbcPkcs7(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT + 1,
        &mut data_ok,
    );

    // slot holds a key other than AES
    let result_bad_2 = device.cipher_decrypt(
        CipherAlgorithm::CbcPkcs7(param_ok.clone()),
        0x00,
        &mut data_ok,
    );

    // slot_id points to TEMP_KEY but no key data
    let result_bad_3 = device.cipher_decrypt(
        CipherAlgorithm::CbcPkcs7(param_bad_no_key),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // no data to encrypt
    let result_bad_4 = device.cipher_decrypt(
        CipherAlgorithm::CbcPkcs7(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_empty,
    );

    // no IV in param
    let result_bad_5 = device.cipher_decrypt(
        CipherAlgorithm::CbcPkcs7(param_bad_no_iv),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_ok,
    );

    // bad data length
    let result_bad_6 = device.cipher_decrypt(
        CipherAlgorithm::CbcPkcs7(param_ok.clone()),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_bad_len,
    );

    // bad padding in ciphertext
    let result_bad_7 = device.cipher_decrypt(
        CipherAlgorithm::CbcPkcs7(param_ok),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_bad_padding,
    );

    // wrong key length
    let result_bad_8 = device.cipher_decrypt(
        CipherAlgorithm::CbcPkcs7(param_bad_wrong_key_length),
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
