// Types
use super::{
    AtcaDeviceType, AtcaStatus, EcdhParams, EcdhSource, EcdhTarget, HkdfDetails, HkdfMsgLoc,
    KdfAlgorithm, KdfParams, KdfSource, KdfTarget, KeyType, NonceTarget,
};
// Constants
use super::{ATCA_ATECC_PUB_KEY_SIZE, ATCA_ATECC_SLOTS_COUNT, ATCA_ECDH_KEY_SIZE};

use super::hw_backend_common::*;
use serial_test::serial;

#[test]
#[serial]
fn ecdh_proper_data() {
    const ENCRYPTION_KEY_SLOT: u8 = 0x06;
    const ALICE_KEY_SLOT: u8 = 0x00;
    const ALICE_OUT_ECDH_SLOT: u8 = 0x0A;
    const BOB_KEY_SLOT: u8 = 0x02;

    let bob_priv_key = [
        0xF5, 0xDB, 0x6B, 0xA1, 0x82, 0x22, 0xCE, 0xC1, 0x54, 0x53, 0xE5, 0x63, 0xDE, 0xC5, 0xC7,
        0x94, 0xCD, 0x48, 0x95, 0xF2, 0x8C, 0xC2, 0x7F, 0x50, 0xC2, 0x7E, 0xC3, 0x1B, 0xAF, 0x44,
        0xEA, 0x54,
    ];
    let bob_pub_key = [
        0xBA, 0x6A, 0xB5, 0xF1, 0x19, 0xAF, 0x21, 0x73, 0x03, 0x75, 0xD1, 0x8D, 0x6B, 0x5F, 0xF1,
        0x94, 0x33, 0xE5, 0x3A, 0xEE, 0x5F, 0x6F, 0xBA, 0x22, 0x97, 0x77, 0x13, 0xEA, 0x82, 0xD3,
        0x74, 0x84, 0x8E, 0x39, 0x78, 0x66, 0xE8, 0x36, 0xB3, 0xFE, 0xD3, 0x22, 0x87, 0x74, 0xA5,
        0x00, 0xC5, 0x5C, 0x17, 0x73, 0x5A, 0x92, 0x4B, 0xB3, 0x9F, 0xE4, 0x98, 0x52, 0x62, 0xA5,
        0x36, 0xC5, 0x00, 0x9C,
    ];
    let some_alice_pub_key = [
        0xDB, 0x66, 0xE8, 0x67, 0x9C, 0xF5, 0x53, 0xD8, 0xC1, 0xEC, 0x7F, 0x69, 0xDB, 0xB9, 0x23,
        0x4C, 0x60, 0xA4, 0xA7, 0xD5, 0xB0, 0x6E, 0xC7, 0xDB, 0x71, 0x2E, 0xBE, 0xD2, 0x9B, 0x39,
        0x60, 0x94, 0xD8, 0x5E, 0xD7, 0x55, 0x52, 0x30, 0x6D, 0xAA, 0xC0, 0xBD, 0x65, 0xEA, 0x5F,
        0xE5, 0x94, 0xD8, 0x98, 0xEA, 0xF5, 0x17, 0xDD, 0xC2, 0xE3, 0x61, 0x1B, 0x8B, 0xF8, 0xF2,
        0x79, 0x31, 0xB0, 0xB5,
    ];
    let hkdf_of_pms = [
        0xC9, 0x78, 0x6B, 0xF1, 0xFB, 0x33, 0x6A, 0x1D, 0xF5, 0xAA, 0x99, 0xFD, 0xA3, 0xC0, 0x8D,
        0xA6, 0x66, 0x29, 0x70, 0x2C, 0xFC, 0x6F, 0x2E, 0x30, 0x25, 0x97, 0x04, 0xEE, 0x25, 0x2E,
        0x81, 0xCD,
    ];
    let some_alice_and_bob_pms = [
        0x4C, 0x85, 0xF7, 0xFA, 0x88, 0x45, 0x20, 0x2D, 0x01, 0x1D, 0x3E, 0xB6, 0x36, 0xA5, 0xE7,
        0x36, 0x00, 0x9F, 0xFC, 0x67, 0x28, 0xF5, 0x17, 0x1D, 0x67, 0x0E, 0x3B, 0xA7, 0x45, 0x2A,
        0xCA, 0x93,
    ];

    let device = test_setup();

    let is_dev_type_atecc608: bool = AtcaDeviceType::ATECC608A == device.get_device_type();
    let mut chip_is_locked: bool = true;

    let mut expected_generate_alice_key = AtcaStatus::AtcaSuccess;
    let mut expected_get_alice_pub_key = AtcaStatus::AtcaSuccess;
    let mut expected_import_bob_key = AtcaStatus::AtcaSuccess;
    let mut expected_read_alice_side_pms = AtcaStatus::AtcaSuccess;

    let mut decrypt_result = AtcaStatus::AtcaUnknown;
    let mut out_pms: Vec<u8> = Vec::new();

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_get_alice_pub_key = AtcaStatus::AtcaNotLocked;
        expected_import_bob_key = AtcaStatus::AtcaNotLocked;
        expected_read_alice_side_pms = AtcaStatus::AtcaNotLocked;
        if !device.is_configuration_locked() {
            expected_generate_alice_key = AtcaStatus::AtcaNotLocked;
        }
    }

    let result_set_write_key = device.add_access_key(ENCRYPTION_KEY_SLOT, WRITE_KEY);

    let mut alice_pub_key: Vec<u8> = Vec::new();
    let result_generate_alice_key = device.gen_key(KeyType::P256EccKey, ALICE_KEY_SLOT);
    let result_get_alice_pub_key = device.get_public_key(ALICE_KEY_SLOT, &mut alice_pub_key);
    let result_import_bob_key = device.import_key(KeyType::P256EccKey, &bob_priv_key, BOB_KEY_SLOT);

    let alice_parameters_1 = EcdhParams {
        out_target: EcdhTarget::Compatibility,
        slot_id: Some(ALICE_KEY_SLOT),
        ..Default::default()
    };

    let alice_parameters_2 = EcdhParams {
        out_target: EcdhTarget::Output,
        slot_id: Some(ALICE_KEY_SLOT),
        ..Default::default()
    };

    let alice_parameters_3 = EcdhParams {
        key_source: EcdhSource::TempKey,
        out_target: EcdhTarget::Output,
        ..Default::default()
    };

    let alice_parameters_4 = EcdhParams {
        key_source: EcdhSource::TempKey,
        out_target: EcdhTarget::Slot,
        slot_id: Some(ALICE_OUT_ECDH_SLOT),
        ..Default::default()
    };

    let alice_parameters_5 = EcdhParams {
        key_source: EcdhSource::TempKey,
        out_target: EcdhTarget::TempKey,
        ..Default::default()
    };

    let bob_parameters_1 = EcdhParams {
        out_target: EcdhTarget::Compatibility,
        slot_id: Some(BOB_KEY_SLOT),
        ..Default::default()
    };

    let bob_parameters_2 = EcdhParams {
        out_target: EcdhTarget::Output,
        slot_id: Some(BOB_KEY_SLOT),
        ..Default::default()
    };

    let bob_parameters_3 = EcdhParams {
        out_target: EcdhTarget::TempKey,
        slot_id: Some(BOB_KEY_SLOT),
        ..Default::default()
    };

    let bob_parameters_4 = EcdhParams {
        out_target: EcdhTarget::Output,
        slot_id: Some(BOB_KEY_SLOT),
        ..Default::default()
    };

    let bob_parameters_5 = EcdhParams {
        out_target: EcdhTarget::Output,
        out_encrypt: true,
        slot_id: Some(BOB_KEY_SLOT),
        ..Default::default()
    };

    let hkdf_details = HkdfDetails {
        msg_loc: HkdfMsgLoc::TempKey,
        zero_key: true,
        ..Default::default()
    };
    let hkdf_parameters = KdfParams {
        source: KdfSource::TempKey,
        target: KdfTarget::Output,
        ..Default::default()
    };
    let hkdf_algorithm: KdfAlgorithm = KdfAlgorithm::Hkdf(hkdf_details);

    let mut alice_side_pms_1: Vec<u8> = vec![0x00; ATCA_ECDH_KEY_SIZE];
    let result_ecdh_alice_side_1 = device.ecdh(alice_parameters_1, &bob_pub_key);
    let result_read_alice_side_pms_1 = device.export_key(
        KeyType::ShaOrText,
        &mut alice_side_pms_1,
        ALICE_KEY_SLOT + 1,
    );
    let result_ecdh_bob_side_1 = device.ecdh(bob_parameters_1, &alice_pub_key);

    let result_ecdh_alice_side_2 = device.ecdh(alice_parameters_2, &bob_pub_key);
    let result_ecdh_bob_side_2 = device.ecdh(bob_parameters_2.clone(), &alice_pub_key);

    let result_ecdh_bob_side_3 = device.ecdh(bob_parameters_3, &some_alice_pub_key);
    let result_ecdh_bob_side_3x = device.kdf(
        hkdf_algorithm.clone(),
        hkdf_parameters.clone(),
        None,
        ATCA_ECDH_KEY_SIZE,
    );

    let result_ecdh_bob_side_4 = device.ecdh(bob_parameters_4, &some_alice_pub_key);

    let result_ecdh_bob_side_5 = device.ecdh(bob_parameters_5, &some_alice_pub_key);
    if result_ecdh_bob_side_5.is_ok() {
        out_pms = result_ecdh_bob_side_5.clone().unwrap().pms.unwrap();
        let nonce: Vec<u8> = result_ecdh_bob_side_5.clone().unwrap().out_nonce.unwrap();
        decrypt_result = io_decrypt(&device, &mut out_pms, &nonce);
    }

    let mut alice_export_priv_key: Vec<u8> = Vec::new();
    let result_alice_genkey_1 = device.gen_key(KeyType::P256EccKey, ATCA_ATECC_SLOTS_COUNT);
    let result_alice_export_priv_key_1 =
        device.get_public_key(ATCA_ATECC_SLOTS_COUNT, &mut alice_export_priv_key);
    let result_ecdh_alice_side_3 = device.ecdh(alice_parameters_3, &bob_pub_key);
    let result_ecdh_bob_side_6 = device.ecdh(bob_parameters_2.clone(), &alice_export_priv_key);

    let result_alice_genkey_2 = device.gen_key(KeyType::P256EccKey, ATCA_ATECC_SLOTS_COUNT);
    let result_alice_export_priv_key_2 =
        device.get_public_key(ATCA_ATECC_SLOTS_COUNT, &mut alice_export_priv_key);
    let mut alice_side_pms_2: Vec<u8> = vec![0x00; ATCA_ECDH_KEY_SIZE];
    let result_ecdh_alice_side_4 = device.ecdh(alice_parameters_4, &bob_pub_key);
    let result_read_alice_side_pms_2 = device.export_key(
        KeyType::ShaOrText,
        &mut alice_side_pms_2,
        ALICE_OUT_ECDH_SLOT,
    );
    let result_ecdh_bob_side_7 = device.ecdh(bob_parameters_2.clone(), &alice_export_priv_key);

    let result_alice_genkey_3 = device.gen_key(KeyType::P256EccKey, ATCA_ATECC_SLOTS_COUNT);
    let result_alice_export_priv_key_3 =
        device.get_public_key(ATCA_ATECC_SLOTS_COUNT, &mut alice_export_priv_key);
    let result_ecdh_alice_side_5 = device.ecdh(alice_parameters_5, &bob_pub_key);
    let result_ecdh_alice_side_5x = device.kdf(
        hkdf_algorithm.clone(),
        hkdf_parameters.clone(),
        None,
        ATCA_ECDH_KEY_SIZE,
    );
    let result_ecdh_bob_side_8 = device.ecdh(bob_parameters_2, &alice_export_priv_key);
    let result_ecdh_bob_side_8x =
        device.kdf(hkdf_algorithm, hkdf_parameters, None, ATCA_ECDH_KEY_SIZE);

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_set_write_key, AtcaStatus::AtcaSuccess);
    assert_eq!(result_generate_alice_key, expected_generate_alice_key);
    assert_eq!(result_get_alice_pub_key, expected_get_alice_pub_key);
    assert_eq!(result_import_bob_key, expected_import_bob_key);
    assert_eq!(result_read_alice_side_pms_1, expected_read_alice_side_pms);

    if chip_is_locked {
        assert!(result_ecdh_alice_side_1.is_ok());
        assert!(result_ecdh_bob_side_1.is_ok());
        assert_eq!(
            alice_side_pms_1,
            result_ecdh_bob_side_1.unwrap().pms.unwrap()
        );

        if is_dev_type_atecc608 {
            assert!(result_ecdh_alice_side_2.is_ok());
            assert!(result_ecdh_bob_side_2.is_ok());
            assert_eq!(
                result_ecdh_alice_side_2.unwrap().pms.unwrap(),
                result_ecdh_bob_side_2.unwrap().pms.unwrap()
            );

            assert!(result_ecdh_bob_side_3.is_ok());
            assert!(result_ecdh_bob_side_3x.is_ok());
            assert_eq!(
                result_ecdh_bob_side_3x.unwrap().out_data.unwrap(),
                hkdf_of_pms.to_vec()
            );

            assert!(result_ecdh_bob_side_4.is_ok());
            assert_eq!(
                result_ecdh_bob_side_4.unwrap().pms.unwrap(),
                some_alice_and_bob_pms.to_vec()
            );

            assert!(result_ecdh_bob_side_5.is_ok());
            assert_eq!(decrypt_result, AtcaStatus::AtcaSuccess);
            assert_eq!(out_pms, some_alice_and_bob_pms.to_vec());

            assert_eq!(result_alice_genkey_1, AtcaStatus::AtcaSuccess);
            assert_eq!(result_alice_export_priv_key_1, AtcaStatus::AtcaSuccess);
            assert!(result_ecdh_alice_side_3.is_ok());
            assert!(result_ecdh_bob_side_6.is_ok());
            assert_eq!(
                result_ecdh_alice_side_3.unwrap().pms.unwrap(),
                result_ecdh_bob_side_6.unwrap().pms.unwrap()
            );

            assert_eq!(result_alice_genkey_2, AtcaStatus::AtcaSuccess);
            assert_eq!(result_alice_export_priv_key_2, AtcaStatus::AtcaSuccess);
            assert!(result_ecdh_alice_side_4.is_ok());
            assert_eq!(result_read_alice_side_pms_2, AtcaStatus::AtcaSuccess);
            assert!(result_ecdh_bob_side_7.is_ok());
            assert_eq!(
                alice_side_pms_2,
                result_ecdh_bob_side_7.unwrap().pms.unwrap()
            );

            assert_eq!(result_alice_genkey_3, AtcaStatus::AtcaSuccess);
            assert_eq!(result_alice_export_priv_key_3, AtcaStatus::AtcaSuccess);
            assert!(result_ecdh_alice_side_5.is_ok());
            assert!(result_ecdh_alice_side_5x.is_ok());
            assert!(result_ecdh_bob_side_8.is_ok());
            assert!(result_ecdh_bob_side_8x.is_ok());
            assert_eq!(
                result_ecdh_alice_side_5x.unwrap().out_data.unwrap(),
                result_ecdh_bob_side_8x.unwrap().out_data.unwrap()
            );
        }
    } else {
        assert!(result_ecdh_alice_side_1.is_err());
        assert!(result_ecdh_bob_side_1.is_err());
        assert_eq!(
            result_ecdh_alice_side_1.unwrap_err(),
            AtcaStatus::AtcaNotLocked
        );
        assert_eq!(
            result_ecdh_bob_side_1.unwrap_err(),
            AtcaStatus::AtcaNotLocked
        );
    }
}

#[test]
#[serial]
fn ecdh_bad_data() {
    const KEY_SLOT: u8 = 0x02;

    let pub_key: Vec<u8> = vec![0x00; ATCA_ATECC_PUB_KEY_SIZE];

    let device = test_setup();

    let is_dev_type_atecc608: bool = AtcaDeviceType::ATECC608A == device.get_device_type();
    let is_dev_type_atecc508: bool = AtcaDeviceType::ATECC508A == device.get_device_type();

    let mut expected_bad_ecdh_result_1 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_ecdh_result_2 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_ecdh_result_3 = AtcaStatus::AtcaInvalidId;
    let mut expected_bad_ecdh_result_4 = AtcaStatus::AtcaInvalidSize;
    let mut expected_bad_ecdh_result_5 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_ecdh_result_6 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_ecdh_result_7 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_ecdh_result_8 = AtcaStatus::AtcaBadParam;
    let mut expected_bad_ecdh_result_9 = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");

        expected_bad_ecdh_result_1 = AtcaStatus::AtcaNotLocked;
        expected_bad_ecdh_result_2 = AtcaStatus::AtcaNotLocked;
        expected_bad_ecdh_result_3 = AtcaStatus::AtcaNotLocked;
        expected_bad_ecdh_result_4 = AtcaStatus::AtcaNotLocked;
        expected_bad_ecdh_result_5 = AtcaStatus::AtcaNotLocked;
        expected_bad_ecdh_result_6 = AtcaStatus::AtcaNotLocked;
        expected_bad_ecdh_result_7 = AtcaStatus::AtcaNotLocked;
        expected_bad_ecdh_result_8 = AtcaStatus::AtcaNotLocked;
        expected_bad_ecdh_result_9 = AtcaStatus::AtcaNotLocked;
    }

    let proper_parameters_1 = EcdhParams {
        slot_id: Some(KEY_SLOT),
        ..Default::default()
    };

    let bad_parameters_1 = EcdhParams {
        out_target: EcdhTarget::Slot,
        slot_id: Some(KEY_SLOT),
        ..Default::default()
    };

    let bad_parameters_2 = EcdhParams {
        ..Default::default()
    };

    let bad_parameters_3 = EcdhParams {
        slot_id: Some(ATCA_ATECC_SLOTS_COUNT),
        ..Default::default()
    };

    let bad_parameters_4 = EcdhParams {
        key_source: EcdhSource::TempKey,
        ..Default::default()
    };

    let bad_parameters_5 = EcdhParams {
        out_target: EcdhTarget::Output,
        slot_id: Some(KEY_SLOT),
        ..Default::default()
    };

    let bad_parameters_6 = EcdhParams {
        out_encrypt: true,
        slot_id: Some(KEY_SLOT),
        ..Default::default()
    };

    let bad_parameters_7 = EcdhParams {
        key_source: EcdhSource::TempKey,
        out_target: EcdhTarget::Slot,
        slot_id: Some(KEY_SLOT),
        ..Default::default()
    };

    let bad_parameters_8 = EcdhParams {
        key_source: EcdhSource::TempKey,
        out_target: EcdhTarget::Output,
        slot_id: Some(KEY_SLOT),
        ..Default::default()
    };

    // both the source of private key and the target of ECDH function result is 'Slot'
    let bad_ecdh_result_1 = device.ecdh(bad_parameters_1, &pub_key);
    // required slot_id parameter was not specified
    let bad_ecdh_result_2 = device.ecdh(bad_parameters_2, &pub_key);
    // specified slot_id parameter is too large
    let bad_ecdh_result_3 = device.ecdh(bad_parameters_3, &pub_key);
    // wrong peer's public key size
    let bad_ecdh_result_4 =
        device.ecdh(proper_parameters_1, &pub_key[..ATCA_ATECC_PUB_KEY_SIZE - 1]);
    // for chip ATECC508A, TempKey was specified as the source of private key
    let bad_ecdh_result_5 = device.ecdh(bad_parameters_4, &pub_key);
    // for ATECC508A chip, a value other than 'Compatibility' was specified as target of ECDH output
    let bad_ecdh_result_6 = device.ecdh(bad_parameters_5, &pub_key);
    // for ATECC508A chip, output data encryption was requested
    let bad_ecdh_result_7 = device.ecdh(bad_parameters_6, &pub_key);
    // for the given slot for saving the result of the ECDH function
    // its slots[slot_idx].write_config parameter is not set as 'Always'
    let bad_ecdh_result_8 = device.ecdh(bad_parameters_7, &pub_key);
    // slot_id was specified when it is neither the source of private key
    // nor the target of an ECDH output
    let bad_ecdh_result_9 = device.ecdh(bad_parameters_8, &pub_key);

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert!(bad_ecdh_result_1.is_err());
    assert_eq!(bad_ecdh_result_1.unwrap_err(), expected_bad_ecdh_result_1);
    assert!(bad_ecdh_result_2.is_err());
    assert_eq!(bad_ecdh_result_2.unwrap_err(), expected_bad_ecdh_result_2);
    assert!(bad_ecdh_result_3.is_err());
    assert_eq!(bad_ecdh_result_3.unwrap_err(), expected_bad_ecdh_result_3);
    assert!(bad_ecdh_result_4.is_err());
    assert_eq!(bad_ecdh_result_4.unwrap_err(), expected_bad_ecdh_result_4);

    if is_dev_type_atecc508 {
        assert!(bad_ecdh_result_5.is_err());
        assert_eq!(bad_ecdh_result_5.unwrap_err(), expected_bad_ecdh_result_5);
        assert!(bad_ecdh_result_6.is_err());
        assert_eq!(bad_ecdh_result_6.unwrap_err(), expected_bad_ecdh_result_6);
        assert!(bad_ecdh_result_7.is_err());
        assert_eq!(bad_ecdh_result_7.unwrap_err(), expected_bad_ecdh_result_7);
    }

    if is_dev_type_atecc608 {
        assert!(bad_ecdh_result_8.is_err());
        assert_eq!(bad_ecdh_result_8.unwrap_err(), expected_bad_ecdh_result_8);
        assert!(bad_ecdh_result_9.is_err());
        assert_eq!(bad_ecdh_result_9.unwrap_err(), expected_bad_ecdh_result_9);
    }
}
