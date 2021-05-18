use serde::Deserialize;
use serial_test::serial;
use std::fs::read_to_string;
use std::path::Path;

#[derive(Deserialize)]
struct Config {
    pub device: Device,
    pub interface: Option<Interface>,
}

#[derive(Deserialize)]
struct Device {
    pub device_type: String,
    pub iface_type: String,
    pub wake_delay: Option<u16>,
    pub rx_retries: Option<i32>,
}

#[derive(Deserialize, Copy, Clone)]
struct Interface {
    pub slave_address: u8,
    pub bus: u8,
    pub baud: u32,
}

fn is_chip_version_608(device: &super::AteccDevice) -> Result<bool, super::AtcaStatus> {
    const LEN: u8 = 4;
    const OFFSET_REV: u8 = 1;
    const INDEX_OF_REV: usize = 2;

    let mut data: Vec<u8> = Vec::with_capacity(LEN as usize);

    let result_dev_type =
        device.read_zone(super::ATCA_ZONE_CONFIG, 0, 0, OFFSET_REV, &mut data, LEN);

    match result_dev_type {
        super::AtcaStatus::AtcaSuccess => Ok((data[INDEX_OF_REV] & 0xF0) == 0x60),
        _ => Err(result_dev_type),
    }
}

fn iface_setup(config_file: String) -> Result<super::AtcaIfaceCfg, String> {
    let config_path = Path::new(&config_file);
    let config_string = read_to_string(config_path).expect("file not found");
    let config: Config = toml::from_str(&config_string).unwrap();
    let iface_cfg = super::AtcaIfaceCfg::default();

    match config.device.iface_type.as_str() {
        "i2c" => Ok(iface_cfg
            .set_iface_type("i2c".to_owned())
            .set_devtype(config.device.device_type)
            .set_wake_delay(config.device.wake_delay.unwrap())
            .set_rx_retries(config.device.rx_retries.unwrap())
            .set_iface(
                super::AtcaIface::default().set_atcai2c(
                    super::AtcaIfaceI2c::default()
                        .set_slave_address(config.interface.unwrap().slave_address)
                        .set_bus(config.interface.unwrap().bus)
                        .set_baud(config.interface.unwrap().baud),
                ),
            )),
        "test-interface" => Ok(iface_cfg
            .set_iface_type("test-interface".to_owned())
            .set_devtype(config.device.device_type.as_str().to_owned())),
        _ => Err("unsupported interface type".to_owned()),
    }
}

/// Setup tests.
///
/// # Arguments
/// * 'data_zone_must_be_locked == true' prevents further calls if data zone is not locked
/// * 'data_zone_must_be_locked == false' allows further calls even if data zone is not locked
pub fn test_setup() -> super::AteccDevice {
    let result_iface_cfg = iface_setup("config.toml".to_owned());
    assert_eq!(result_iface_cfg.is_ok(), true);

    let iface_cfg = result_iface_cfg.unwrap();
    assert_eq!(iface_cfg.iface_type.to_string(), "AtcaI2cIface");

    let result = super::setup_atecc_device(iface_cfg);
    match result {
        Ok(_) => (),
        Err(err) => panic!("{}", err),
    };

    result.unwrap()
}

// test_teardown() is not needed, it is a one-liner and if it fails, then
// there is a larger problem - elsewhere...

#[test]
#[serial]
fn new() {
    const SLOTS_COUNT: usize = super::ATCA_ATECC_SLOTS_COUNT as usize;
    let device = test_setup();

    let serial_number = device.get_serial_number();
    let mut slots = Vec::new();
    let get_config = device.get_config(&mut slots);

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(serial_number[0], 0x01);
    assert_eq!(serial_number[1], 0x23);
    assert_eq!(get_config.to_string(), "AtcaSuccess");
    assert_eq!(slots.len(), SLOTS_COUNT);
    assert_eq!(slots[0].id, 0);
    assert_eq!(slots[SLOTS_COUNT - 1].id, (SLOTS_COUNT - 1) as u8);
    assert_ne!(slots[0].config.key_type, super::KeyType::Rfu);
    assert_ne!(slots[SLOTS_COUNT - 1].config.key_type, super::KeyType::Rfu);
}

#[test]
#[serial]
fn sha() {
    let device = test_setup();

    let test_message = "TestMessage";
    let test_message_hash = [
        0x04, 0x6B, 0xA6, 0xF2, 0xDB, 0x97, 0x9E, 0x92, 0x56, 0xF1, 0x19, 0xBC, 0x15, 0xD1, 0x7E,
        0x3E, 0xA8, 0x88, 0xF1, 0xEB, 0x9D, 0xE2, 0x46, 0x31, 0x51, 0x50, 0xD0, 0xAA, 0xF7, 0xE7,
        0x00, 0x73,
    ];
    let message = test_message.as_bytes().to_vec();
    let mut digest: Vec<u8> = Vec::new();
    let device_sha = device.sha(message, &mut digest);

    let mut expected = super::AtcaStatus::AtcaSuccess;
    if !device.configuration_is_locked() {
        println!("\u{001b}[1m\u{001b}[33mConfiguration not Locked!\u{001b}[0m");
        expected = super::AtcaStatus::AtcaNotLocked;
    } else {
        assert_eq!(digest, test_message_hash);
    };
    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(device_sha, expected);
}

#[test]
#[serial]
fn nonce() {
    let device = test_setup();

    let nonce_64 = [
        0x41, 0xDA, 0xC9, 0xA1, 0x4B, 0x4F, 0xAE, 0xAE, 0x7D, 0xD5, 0x97, 0xD2, 0xA6, 0x78, 0x81,
        0xCE, 0x40, 0x9D, 0x0C, 0x38, 0x85, 0xCA, 0x6F, 0x07, 0x9A, 0xBC, 0xE2, 0x82, 0x89, 0x06,
        0x24, 0xFE, 0x9B, 0x8D, 0xD4, 0xD3, 0x93, 0x15, 0x1E, 0xCB, 0x5C, 0x05, 0x8A, 0x48, 0x27,
        0x6C, 0x7E, 0x62, 0x76, 0x86, 0xE2, 0x2C, 0x96, 0xAE, 0x84, 0x7C, 0xD4, 0x73, 0x50, 0x2A,
        0xDB, 0x41, 0x42, 0xDE,
    ];

    let nonce_32 = &nonce_64[0..=31];
    let nonce_too_small = &nonce_64[0..super::ATCA_NONCE_NUMIN_SIZE];
    let mut check_ver_result = super::AtcaStatus::AtcaSuccess;
    let expected = match is_chip_version_608(&device) {
        Ok(true) => super::AtcaStatus::AtcaSuccess,
        Ok(false) => super::AtcaStatus::AtcaBadParam,
        Err(err) => {
            check_ver_result = err;
            super::AtcaStatus::AtcaBadParam
        }
    };

    let nonce_32_ok = device.nonce(super::NonceTarget::TempKey, &nonce_32);
    let nonce_64_ok = device.nonce(super::NonceTarget::MsgDigBuf, &nonce_64);
    let nonce_bad = device.nonce(super::NonceTarget::TempKey, &nonce_too_small);

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(nonce_32_ok.to_string(), "AtcaSuccess");
    assert_eq!(nonce_64_ok, expected);
    assert_eq!(nonce_bad.to_string(), "AtcaBadParam");
    assert_eq!(check_ver_result.to_string(), "AtcaSuccess");
}

#[test]
#[serial]
fn nonce_rand() {
    let device = test_setup();

    let nonce = [
        0x41, 0xDA, 0xC9, 0xA1, 0x4B, 0x4F, 0xAE, 0xAE, 0x7D, 0xD5, 0x97, 0xD2, 0xA6, 0x78, 0x81,
        0xCE, 0x40, 0x9D, 0x0C, 0x38,
    ];
    let nonce_too_small = &nonce[0..10];
    let mut rand_out = Vec::new();

    let nonce_ok = device.nonce_rand(&nonce, &mut rand_out);
    let nonce_bad = device.nonce_rand(&nonce_too_small, &mut rand_out);

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(rand_out.len(), super::ATCA_RANDOM_BUFFER_SIZE);
    assert_eq!(nonce_ok.to_string(), "AtcaSuccess");
    assert_eq!(nonce_bad.to_string(), "AtcaInvalidSize");
}

#[test]
#[serial]
fn gen_key() {
    let device = test_setup();

    let write_key = [
        0x4D, 0x50, 0x72, 0x6F, 0x20, 0x49, 0x4F, 0x20, 0x4B, 0x65, 0x79, 0x20, 0x9E, 0x31, 0xBD,
        0x05, 0x82, 0x58, 0x76, 0xCE, 0x37, 0x90, 0xEA, 0x77, 0x42, 0x32, 0xBB, 0x51, 0x81, 0x49,
        0x66, 0x45,
    ];

    let mut check_ver_result: super::AtcaStatus = super::AtcaStatus::AtcaSuccess;
    let mut expected_device_gen_key_bad_2 = match is_chip_version_608(&device) {
        Ok(true) => super::AtcaStatus::AtcaSuccess,
        Ok(false) => super::AtcaStatus::AtcaBadParam,
        Err(err) => {
            check_ver_result = err;
            super::AtcaStatus::AtcaBadParam
        }
    };

    let mut expected_device_gen_key_bad_1 = super::AtcaStatus::AtcaInvalidId;
    let mut expected_device_gen_key_bad_3 = super::AtcaStatus::AtcaBadParam;
    let mut expected_device_gen_key_bad_4 = super::AtcaStatus::AtcaBadParam;
    let mut expected_device_gen_key_ok_1 = super::AtcaStatus::AtcaSuccess;
    if !device.configuration_is_locked() {
        println!("\u{001b}[1m\u{001b}[33mConfiguration not Locked!\u{001b}[0m");
        expected_device_gen_key_bad_1 = super::AtcaStatus::AtcaNotLocked;
        expected_device_gen_key_bad_2 = super::AtcaStatus::AtcaNotLocked;
        expected_device_gen_key_bad_3 = super::AtcaStatus::AtcaNotLocked;
        expected_device_gen_key_bad_4 = super::AtcaStatus::AtcaNotLocked;
        expected_device_gen_key_ok_1 = super::AtcaStatus::AtcaNotLocked;
    }
    let device_gen_key_bad_1 =
        device.gen_key(super::KeyType::Aes, super::ATCA_ATECC_SLOTS_COUNT + 1);
    let device_gen_key_bad_2 = device.gen_key(super::KeyType::Aes, 9);
    let device_gen_key_bad_3 =
        device.gen_key(super::KeyType::P256EccKey, super::ATCA_ATECC_SLOTS_COUNT);
    let device_gen_key_bad_4 = device.gen_key(super::KeyType::ShaOrText, 0);
    let device_gen_key_ok_1 = device.gen_key(super::KeyType::P256EccKey, 0);

    let _expected_device_gen_key_bad_1 = super::AtcaStatus::AtcaInvalidId;

    match is_chip_version_608(&device) {
        Ok(true) => {
            let aes_key_ok_1 = device.gen_key(super::KeyType::Aes, 0x09);
            assert_eq!(aes_key_ok_1.to_string(), "AtcaSuccess");

            let write_key_set_success = device.set_write_encryption_key(&write_key);
            assert_eq!(write_key_set_success.to_string(), "AtcaSuccess");

            if write_key_set_success == super::AtcaStatus::AtcaSuccess {
                let aes_key_ok_2 = device.gen_key(super::KeyType::Aes, 0x04);
                // let aes_key_bad_1 = device.gen_key(super::KeyType::Aes, &aes_key_bad, 0x09);

                assert_eq!(aes_key_ok_2.to_string(), "AtcaSuccess");
                // assert_eq!(aes_key_bad_1.to_string(), "AtcaInvalidSize");
            }
        }
        Ok(false) => (),
        Err(err) => panic!("is_chip_version_608() error: {}", err.to_string()),
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(check_ver_result.to_string(), "AtcaSuccess");
    assert_eq!(device_gen_key_bad_1, expected_device_gen_key_bad_1);
    assert_eq!(device_gen_key_bad_2, expected_device_gen_key_bad_2);
    assert_eq!(device_gen_key_bad_3, expected_device_gen_key_bad_3);
    assert_eq!(device_gen_key_bad_4, expected_device_gen_key_bad_4);
    assert_eq!(device_gen_key_ok_1, expected_device_gen_key_ok_1);
}

#[test]
#[serial]
fn import_key() {
    let device = test_setup();

    let priv_key = [
        0xF5, 0xDB, 0x6B, 0xA1, 0x82, 0x22, 0xCE, 0xC1, 0x54, 0x53, 0xE5, 0x63, 0xDE, 0xC5, 0xC7,
        0x94, 0xCD, 0x48, 0x95, 0xF2, 0x8C, 0xC2, 0x7F, 0x50, 0xC2, 0x7E, 0xC3, 0x1B, 0xAF, 0x44,
        0xEA, 0x54,
    ];
    let pub_key = [
        0xBA, 0x6A, 0xB5, 0xF1, 0x19, 0xAF, 0x21, 0x73, 0x03, 0x75, 0xD1, 0x8D, 0x6B, 0x5F, 0xF1,
        0x94, 0x33, 0xE5, 0x3A, 0xEE, 0x5F, 0x6F, 0xBA, 0x22, 0x97, 0x77, 0x13, 0xEA, 0x82, 0xD3,
        0x74, 0x84, 0x8E, 0x39, 0x78, 0x66, 0xE8, 0x36, 0xB3, 0xFE, 0xD3, 0x22, 0x87, 0x74, 0xA5,
        0x00, 0xC5, 0x5C, 0x17, 0x73, 0x5A, 0x92, 0x4B, 0xB3, 0x9F, 0xE4, 0x98, 0x52, 0x62, 0xA5,
        0x36, 0xC5, 0x00, 0x9C,
    ];
    let write_key = [
        0x4D, 0x50, 0x72, 0x6F, 0x20, 0x49, 0x4F, 0x20, 0x4B, 0x65, 0x79, 0x20, 0x9E, 0x31, 0xBD,
        0x05, 0x82, 0x58, 0x76, 0xCE, 0x37, 0x90, 0xEA, 0x77, 0x42, 0x32, 0xBB, 0x51, 0x81, 0x49,
        0x66, 0x45,
    ];
    let priv_key_bad = &priv_key[0..=25];
    let pub_key_bad = &pub_key[0..=60];
    let aes_key = &priv_key[0..=15];
    let aes_key_bad = &priv_key[0..=10];

    let write_key_set_success = device.set_write_encryption_key(&write_key);
    assert_eq!(write_key_set_success.to_string(), "AtcaSuccess");
    if write_key_set_success == super::AtcaStatus::AtcaSuccess {
        let priv_key_ok = device.import_key(super::KeyType::P256EccKey, &priv_key, 0x02);
        let priv_key_bad_1 = device.import_key(super::KeyType::P256EccKey, &priv_key_bad, 0x00);
        let priv_key_bad_2 = device.import_key(super::KeyType::P256EccKey, &priv_key, 0x01);

        let pub_key_ok = device.import_key(super::KeyType::P256EccKey, &pub_key, 0x0B);
        let pub_key_bad_1 = device.import_key(super::KeyType::P256EccKey, &pub_key_bad, 0x0B);
        // slot number too low
        let pub_key_bad_2 = device.import_key(super::KeyType::P256EccKey, &pub_key, 0x03);
        // writing to a slot with a key type other than P256
        let pub_key_bad_3 = device.import_key(super::KeyType::P256EccKey, &pub_key, 0x0C);

        let mut expected_priv_key_ok = super::AtcaStatus::AtcaSuccess;
        let mut expected_priv_key_bad_1 = super::AtcaStatus::AtcaInvalidSize;
        let mut expected_priv_key_bad_2 = super::AtcaStatus::AtcaBadParam;
        let mut expected_pub_key_ok = super::AtcaStatus::AtcaSuccess;
        let mut expected_pub_key_bad_1 = super::AtcaStatus::AtcaInvalidSize;
        let mut expected_pub_key_bad_2 = super::AtcaStatus::AtcaInvalidId;
        let mut expected_pub_key_bad_3 = super::AtcaStatus::AtcaBadParam;
        if !(device.configuration_is_locked() && device.data_zone_is_locked()) {
            println!("\u{001b}[1m\u{001b}[33mConfiguration not Locked!\u{001b}[0m");
            expected_priv_key_ok = super::AtcaStatus::AtcaNotLocked;
            expected_priv_key_bad_1 = super::AtcaStatus::AtcaNotLocked;
            expected_priv_key_bad_2 = super::AtcaStatus::AtcaNotLocked;

            expected_pub_key_ok = super::AtcaStatus::AtcaNotLocked;
            expected_pub_key_bad_1 = super::AtcaStatus::AtcaNotLocked;
            expected_pub_key_bad_2 = super::AtcaStatus::AtcaNotLocked;
            expected_pub_key_bad_3 = super::AtcaStatus::AtcaNotLocked;
        }

        assert_eq!(priv_key_ok, expected_priv_key_ok);
        assert_eq!(priv_key_bad_1, expected_priv_key_bad_1);
        assert_eq!(priv_key_bad_2, expected_priv_key_bad_2);

        assert_eq!(pub_key_ok, expected_pub_key_ok);
        assert_eq!(pub_key_bad_1, expected_pub_key_bad_1);
        assert_eq!(pub_key_bad_2, expected_pub_key_bad_2);
        assert_eq!(pub_key_bad_3, expected_pub_key_bad_3);
    }

    // TODO AES keys check
    match is_chip_version_608(&device) {
        Ok(true) => {
            let aes_key_ok = device.import_key(super::KeyType::Aes, &aes_key, 0x09);
            let aes_key_bad_1 = device.import_key(super::KeyType::Aes, &aes_key_bad, 0x09);

            assert_eq!(aes_key_ok.to_string(), "AtcaSuccess");
            assert_eq!(aes_key_bad_1.to_string(), "AtcaInvalidSize");
        }
        Ok(false) => (),
        Err(err) => panic!("is_chip_version_608() error: {}", err.to_string()),
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");
}

#[test]
#[serial]
fn get_pubkey() {
    let device = test_setup();

    let mut public_key: Vec<u8> = Vec::new();
    let public_key_write = [
        0xBA, 0x6A, 0xB5, 0xF1, 0x19, 0xAF, 0x21, 0x73, 0x03, 0x75, 0xD1, 0x8D, 0x6B, 0x5F, 0xF1,
        0x94, 0x33, 0xE5, 0x3A, 0xEE, 0x5F, 0x6F, 0xBA, 0x22, 0x97, 0x77, 0x13, 0xEA, 0x82, 0xD3,
        0x74, 0x84, 0x8E, 0x39, 0x78, 0x66, 0xE8, 0x36, 0xB3, 0xFE, 0xD3, 0x22, 0x87, 0x74, 0xA5,
        0x00, 0xC5, 0x5C, 0x17, 0x73, 0x5A, 0x92, 0x4B, 0xB3, 0x9F, 0xE4, 0x98, 0x52, 0x62, 0xA5,
        0x36, 0xC5, 0x00, 0x9C,
    ]
    .to_vec();

    let get_key_ok_1 = device.get_public_key(0x00, &mut public_key);
    let sum: u16 = public_key.iter().fold(0, |s, &x| s + x as u16);
    let mut get_key_ok_2 = super::AtcaStatus::AtcaUnknown;
    let get_key_bad_1 = device.get_public_key(0x01, &mut public_key);

    let mut expected_get_key_ok_1 = super::AtcaStatus::AtcaSuccess;
    let mut expected_get_key_ok_2 = super::AtcaStatus::AtcaSuccess;
    let mut expected_get_key_bad_1 = super::AtcaStatus::AtcaBadParam;

    if !device.configuration_is_locked() {
        println!("\u{001b}[1m\u{001b}[33mConfiguration not Locked!\u{001b}[0m");
        expected_get_key_ok_1 = super::AtcaStatus::AtcaNotLocked;
        expected_get_key_ok_2 = super::AtcaStatus::AtcaNotLocked;
        expected_get_key_bad_1 = super::AtcaStatus::AtcaNotLocked;
    } else {
        assert_eq!(public_key.len(), super::ATCA_ATECC_PUB_KEY_SIZE);
        assert_ne!(sum, 0);
    }

    if device.import_key(super::KeyType::P256EccKey, &public_key_write, 0x0B)
        == super::AtcaStatus::AtcaSuccess
    {
        get_key_ok_2 = device.get_public_key(0x0B, &mut public_key);
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(get_key_ok_1, expected_get_key_ok_1);
    assert_eq!(get_key_ok_2, expected_get_key_ok_2);
    assert_eq!(public_key_write, public_key);
    assert_eq!(get_key_bad_1, expected_get_key_bad_1);
}

#[test]
#[serial]
fn sign_verify_hash() {
    let device = test_setup();

    let hash: Vec<u8> = vec![0xA5; 32];
    let internal_sig = super::SignEcdsaParam {
        is_invalidate: false,
        is_full_sn: false,
    };
    let internal_mac_verify = super::VerifyEcdsaParam::default();

    let mut signature: Vec<u8> = Vec::new();
    let mut public_key: Vec<u8> = Vec::new();
    let mut is_verified: bool = false;

    let mode_sign = super::SignMode::Internal(internal_sig);
    let sign_internal = device.sign_hash(mode_sign, 0x00, &mut signature);
    let mode_verify = super::VerifyMode::InternalMac(internal_mac_verify);
    let mut verify_external_result = super::AtcaStatus::AtcaSuccess;
    if let Err(err) = device.verify_hash(mode_verify, &hash.to_vec(), &signature) {
        verify_external_result = err
    };

    let mode_sign = super::SignMode::External(hash.to_vec());
    let sign_external = device.sign_hash(mode_sign, 0x00, &mut signature);
    let get_pub_key_result = device.get_public_key(0x00, &mut public_key);
    let mode_verify = super::VerifyMode::External(public_key);
    let mut verify_internal_result = super::AtcaStatus::AtcaSuccess;
    match device.verify_hash(mode_verify, &hash.to_vec(), &signature) {
        Err(err) => verify_internal_result = err,
        Ok(val) => is_verified = val,
    };

    let mut expected_sign_internal = super::AtcaStatus::AtcaUnimplemented;
    let mut expected_verify_external_result = super::AtcaStatus::AtcaUnimplemented;
    let mut expected_sign_external = super::AtcaStatus::AtcaSuccess;
    let mut expected_get_pub_key_result = super::AtcaStatus::AtcaSuccess;
    let mut expected_verify_internal_result = super::AtcaStatus::AtcaSuccess;
    if !device.configuration_is_locked() {
        expected_get_pub_key_result = super::AtcaStatus::AtcaNotLocked;
    }
    if !(device.configuration_is_locked() && device.data_zone_is_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration not Locked!\u{001b}[0m");
        expected_sign_internal = super::AtcaStatus::AtcaNotLocked;
        expected_verify_external_result = super::AtcaStatus::AtcaNotLocked;
        expected_sign_external = super::AtcaStatus::AtcaNotLocked;
        expected_verify_internal_result = super::AtcaStatus::AtcaNotLocked;
    } else {
        assert_eq!(signature.len(), super::ATCA_SIG_SIZE);
        assert_eq!(is_verified, true);
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(sign_internal, expected_sign_internal);
    assert_eq!(verify_external_result, expected_verify_external_result);

    assert_eq!(sign_external, expected_sign_external);
    assert_eq!(get_pub_key_result, expected_get_pub_key_result);
    assert_eq!(verify_internal_result, expected_verify_internal_result);
}

#[test]
#[serial]
fn cmp_config_zone() {
    let device = test_setup();

    let mut config_data = Vec::new();
    let device_read_config_zone = device.read_config_zone(&mut config_data);
    let mut same_config = false;
    let device_cmp_config_zone = device.cmp_config_zone(&mut config_data, &mut same_config);

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(device_read_config_zone.to_string(), "AtcaSuccess");
    assert_eq!(device_cmp_config_zone.to_string(), "AtcaSuccess");
    assert_eq!(same_config, true);
}

#[test]
#[serial]
fn configuration_is_locked() {
    let device = test_setup();
    let is_locked = device.configuration_is_locked();

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(is_locked, true);
}

#[test]
#[serial]
fn data_zone_is_locked() {
    let device = test_setup();
    let is_locked = device.data_zone_is_locked();

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(is_locked, true);
}

#[test]
#[serial]
fn get_config_from_config_zone() {
    let mut config_data = Vec::new();
    let device = test_setup();
    let device_atcab_read_config_zone = device.read_config_zone(&mut config_data);

    config_data[88] = 0b10111111;
    config_data[89] = 0b01111111;
    config_data[20] = 0b10000000;
    config_data[22] = 0b00000000;
    let mut slots: Vec<super::AtcaSlot> = Vec::new();
    super::hw_impl::atcab_get_config_from_config_zone(&config_data, &mut slots);

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(device_atcab_read_config_zone.to_string(), "AtcaSuccess");
    assert_eq!(slots.len(), usize::from(super::ATCA_ATECC_SLOTS_COUNT));
    assert_eq!(slots[0].id, 0);
    assert_eq!(slots[15].id, 15);
    assert_eq!(slots[0].is_locked, false);
    assert_eq!(slots[6].is_locked, true);
    assert_eq!(slots[15].is_locked, true);
    assert_eq!(slots[0].config.is_secret, true);
    assert_eq!(slots[1].config.is_secret, false);
}

#[test]
#[serial]
fn get_config() {
    let device = test_setup();
    let mut slots: Vec<super::AtcaSlot> = Vec::new();
    let get_config = device.get_config(&mut slots);

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(get_config.to_string(), "AtcaSuccess");
    assert_eq!(slots.len(), super::ATCA_ATECC_SLOTS_COUNT as usize);
}

#[test]
#[serial]
fn info_cmd() {
    let device = test_setup();
    let mut result_key_valid = super::AtcaStatus::AtcaSuccess;
    let mut result_revision = super::AtcaStatus::AtcaSuccess;
    let mut revision: Vec<u8> = Vec::new();

    match device.info_cmd(super::InfoCmdType::KeyValid) {
        Ok(_val) => (),
        Err(err) => result_key_valid = err,
    }

    match device.info_cmd(super::InfoCmdType::Revision) {
        Ok(val) => revision = val,
        Err(err) => result_revision = err,
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_key_valid.to_string(), "AtcaUnimplemented");
    assert_eq!(revision.len(), 4);
    assert_eq!(result_revision.to_string(), "AtcaSuccess");
}

#[test]
#[serial]
fn gen_key_sign_hash() {
    let device = test_setup();

    let write_key = [
        0x4D, 0x50, 0x72, 0x6F, 0x20, 0x49, 0x4F, 0x20, 0x4B, 0x65, 0x79, 0x20, 0x9E, 0x31, 0xBD,
        0x05, 0x82, 0x58, 0x76, 0xCE, 0x37, 0x90, 0xEA, 0x77, 0x42, 0x32, 0xBB, 0x51, 0x81, 0x49,
        0x66, 0x45,
    ];

    let device_set_write_key = device.set_write_encryption_key(&write_key);

    let mut digest: Vec<u8> = Vec::new();
    let device_sha = device.sha("Bob wrote this message.".as_bytes().to_vec(), &mut digest);

    let device_gen_key = device.gen_key(super::KeyType::P256EccKey, 0);
    let mut signature = vec![0u8; super::ATCA_SIG_SIZE];

    let device_sign_hash = device.sign_hash(super::SignMode::External(digest), 0, &mut signature);

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(device_set_write_key.to_string(), "AtcaSuccess");
    assert_eq!(device_sha.to_string(), "AtcaSuccess");
    assert_eq!(device_gen_key.to_string(), "AtcaSuccess");
    assert_eq!(device_sign_hash.to_string(), "AtcaSuccess");
}
