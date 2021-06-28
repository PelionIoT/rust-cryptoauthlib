use serde::Deserialize;
use serial_test::serial;
use std::fs::read_to_string;
use std::path::Path;

// Types
use super::{
    AeadAlgorithm, AeadParam, AtcaIface, AtcaIfaceCfg, AtcaIfaceI2c, AtcaSlot, AtcaStatus,
    AteccDevice, InfoCmdType, KeyType, NonceTarget, SignEcdsaParam, SignMode, VerifyEcdsaParam,
    VerifyMode,
};
// Constants
use super::{
    ATCA_AES_DATA_SIZE, ATCA_AES_GCM_IV_STD_LENGTH, ATCA_AES_KEY_SIZE, ATCA_ATECC_PUB_KEY_SIZE,
    ATCA_ATECC_SLOTS_COUNT, ATCA_NONCE_NUMIN_SIZE, ATCA_RANDOM_BUFFER_SIZE, ATCA_SIG_SIZE,
    ATCA_ZONE_CONFIG,
};
// Functions
use super::hw_impl::atcab_get_config_from_config_zone;
use super::setup_atecc_device;

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

fn is_chip_version_608(device: &AteccDevice) -> Result<bool, AtcaStatus> {
    const LEN: u8 = 4;
    const OFFSET_REV: u8 = 1;
    const INDEX_OF_REV: usize = 2;

    let mut data: Vec<u8> = Vec::with_capacity(LEN as usize);

    let result_dev_type = device.read_zone(ATCA_ZONE_CONFIG, 0, 0, OFFSET_REV, &mut data, LEN);

    match result_dev_type {
        AtcaStatus::AtcaSuccess => Ok((data[INDEX_OF_REV] & 0xF0) == 0x60),
        _ => Err(result_dev_type),
    }
}

fn iface_setup(config_file: String) -> Result<AtcaIfaceCfg, String> {
    let config_path = Path::new(&config_file);
    let config_string = read_to_string(config_path).expect("file not found");
    let config: Config = toml::from_str(&config_string).unwrap();
    let iface_cfg = AtcaIfaceCfg::default();

    match config.device.iface_type.as_str() {
        "i2c" => Ok(iface_cfg
            .set_iface_type("i2c".to_owned())
            .set_devtype(config.device.device_type)
            .set_wake_delay(config.device.wake_delay.unwrap())
            .set_rx_retries(config.device.rx_retries.unwrap())
            .set_iface(
                AtcaIface::default().set_atcai2c(
                    AtcaIfaceI2c::default()
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
pub fn test_setup() -> AteccDevice {
    let result_iface_cfg = iface_setup("config.toml".to_owned());
    assert_eq!(result_iface_cfg.is_ok(), true);

    let iface_cfg = result_iface_cfg.unwrap();
    assert_eq!(iface_cfg.iface_type.to_string(), "AtcaI2cIface");

    let result = setup_atecc_device(iface_cfg);
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
    const SLOTS_COUNT: usize = ATCA_ATECC_SLOTS_COUNT as usize;

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
    assert_ne!(slots[0].config.key_type, KeyType::Rfu);
    assert_ne!(slots[SLOTS_COUNT - 1].config.key_type, KeyType::Rfu);
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

    let mut expected = AtcaStatus::AtcaSuccess;
    if !device.is_configuration_locked() {
        println!("\u{001b}[1m\u{001b}[33mConfiguration not Locked!\u{001b}[0m ");
        expected = AtcaStatus::AtcaNotLocked;
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(device_sha, expected);
    if AtcaStatus::AtcaSuccess == expected {
        assert_eq!(digest, test_message_hash);
    }
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
    let nonce_too_small = &nonce_64[0..ATCA_NONCE_NUMIN_SIZE];
    let mut check_ver_result = AtcaStatus::AtcaSuccess;
    let expected = match is_chip_version_608(&device) {
        Ok(true) => AtcaStatus::AtcaSuccess,
        Ok(false) => AtcaStatus::AtcaBadParam,
        Err(err) => {
            check_ver_result = err;
            AtcaStatus::AtcaBadParam
        }
    };

    let nonce_32_ok = device.nonce(NonceTarget::TempKey, &nonce_32);
    let nonce_64_ok = device.nonce(NonceTarget::MsgDigBuf, &nonce_64);
    let nonce_bad = device.nonce(NonceTarget::TempKey, &nonce_too_small);

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(nonce_32_ok, AtcaStatus::AtcaSuccess);
    assert_eq!(nonce_64_ok, expected);
    assert_eq!(nonce_bad, AtcaStatus::AtcaInvalidSize);
    assert_eq!(check_ver_result, AtcaStatus::AtcaSuccess);
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

    assert_eq!(rand_out.len(), ATCA_RANDOM_BUFFER_SIZE);
    assert_eq!(nonce_ok, AtcaStatus::AtcaSuccess);
    assert_eq!(nonce_bad, AtcaStatus::AtcaInvalidSize);
}

#[test]
#[serial]
fn gen_key() {
    const ENCRYPTION_KEY_SLOT: u8 = 0x06;

    let device = test_setup();

    let write_key = [
        0x4D, 0x50, 0x72, 0x6F, 0x20, 0x49, 0x4F, 0x20, 0x4B, 0x65, 0x79, 0x20, 0x9E, 0x31, 0xBD,
        0x05, 0x82, 0x58, 0x76, 0xCE, 0x37, 0x90, 0xEA, 0x77, 0x42, 0x32, 0xBB, 0x51, 0x81, 0x49,
        0x66, 0x45,
    ];

    let mut chip_is_locked: bool = true;
    let mut expected_device_gen_key_ok_1 = AtcaStatus::AtcaSuccess;
    let mut expected_device_gen_key_ok_2 = AtcaStatus::AtcaSuccess;
    let mut expected_device_gen_key_ok_3 = AtcaStatus::AtcaSuccess;
    let mut expected_device_gen_key_bad_1 = AtcaStatus::AtcaInvalidId;
    let mut expected_device_gen_key_bad_2 = AtcaStatus::AtcaBadParam;
    let mut expected_device_gen_key_bad_3 = AtcaStatus::AtcaBadParam;
    let mut expected_device_gen_key_bad_4 = AtcaStatus::AtcaBadParam;

    if !device.is_configuration_locked() {
        println!("\u{001b}[1m\u{001b}[33mConfiguration not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_device_gen_key_ok_1 = AtcaStatus::AtcaNotLocked;
        expected_device_gen_key_ok_2 = AtcaStatus::AtcaNotLocked;
        expected_device_gen_key_ok_3 = AtcaStatus::AtcaNotLocked;
        expected_device_gen_key_bad_1 = AtcaStatus::AtcaNotLocked;
        expected_device_gen_key_bad_2 = AtcaStatus::AtcaNotLocked;
        expected_device_gen_key_bad_3 = AtcaStatus::AtcaNotLocked;
        expected_device_gen_key_bad_4 = AtcaStatus::AtcaNotLocked;
    }
    if chip_is_locked {
        if device.is_aes_enabled() {
            expected_device_gen_key_ok_2 = AtcaStatus::AtcaSuccess;
            expected_device_gen_key_ok_3 = AtcaStatus::AtcaSuccess;
            expected_device_gen_key_bad_2 = AtcaStatus::AtcaBadParam;
        } else {
            expected_device_gen_key_ok_2 = AtcaStatus::AtcaBadParam;
            expected_device_gen_key_ok_3 = AtcaStatus::AtcaBadParam;
        }
    }

    let write_key_set_success = device.add_access_key(ENCRYPTION_KEY_SLOT, &write_key);
    let device_gen_key_ok_1 = device.gen_key(KeyType::P256EccKey, 0x00);
    let device_gen_key_ok_2 = device.gen_key(KeyType::Aes, 0x09);
    let device_gen_key_ok_3 = device.gen_key(KeyType::Aes, 0x04);
    let device_gen_key_bad_1 = device.gen_key(KeyType::Aes, ATCA_ATECC_SLOTS_COUNT + 1);
    let device_gen_key_bad_2 = device.gen_key(KeyType::Aes, 0x00);
    let device_gen_key_bad_3 = device.gen_key(KeyType::P256EccKey, ATCA_ATECC_SLOTS_COUNT);
    let device_gen_key_bad_4 = device.gen_key(KeyType::ShaOrText, 0x00);

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(write_key_set_success, AtcaStatus::AtcaSuccess);
    assert_eq!(device_gen_key_ok_1, expected_device_gen_key_ok_1);
    assert_eq!(device_gen_key_ok_2, expected_device_gen_key_ok_2);
    assert_eq!(device_gen_key_ok_3, expected_device_gen_key_ok_3);
    assert_eq!(device_gen_key_bad_1, expected_device_gen_key_bad_1);
    assert_eq!(device_gen_key_bad_2, expected_device_gen_key_bad_2);
    assert_eq!(device_gen_key_bad_3, expected_device_gen_key_bad_3);
    assert_eq!(device_gen_key_bad_4, expected_device_gen_key_bad_4);
}

#[test]
#[serial]
fn import_key() {
    const ENCRYPTION_KEY_SLOT: u8 = 0x06;

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

    let mut chip_is_locked: bool = true;
    let mut expected_priv_key_ok = AtcaStatus::AtcaInvalidId;
    let mut expected_priv_key_bad_1 = AtcaStatus::AtcaInvalidSize;
    let mut expected_priv_key_bad_2 = AtcaStatus::AtcaBadParam;
    let mut expected_pub_key_ok = AtcaStatus::AtcaSuccess;
    let mut expected_pub_key_bad_1 = AtcaStatus::AtcaInvalidSize;
    let mut expected_pub_key_bad_2 = AtcaStatus::AtcaInvalidId;
    let mut expected_pub_key_bad_3 = AtcaStatus::AtcaBadParam;
    let mut expected_aes_key_ok = AtcaStatus::AtcaBadParam;
    let mut expected_aes_key_bad_1 = AtcaStatus::AtcaBadParam;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_priv_key_ok = AtcaStatus::AtcaNotLocked;
        expected_priv_key_bad_1 = AtcaStatus::AtcaNotLocked;
        expected_priv_key_bad_2 = AtcaStatus::AtcaNotLocked;

        expected_pub_key_ok = AtcaStatus::AtcaNotLocked;
        expected_pub_key_bad_1 = AtcaStatus::AtcaNotLocked;
        expected_pub_key_bad_2 = AtcaStatus::AtcaNotLocked;
        expected_pub_key_bad_3 = AtcaStatus::AtcaNotLocked;

        expected_aes_key_ok = AtcaStatus::AtcaNotLocked;
        expected_aes_key_bad_1 = AtcaStatus::AtcaNotLocked;
    }

    if chip_is_locked && device.is_aes_enabled() {
        expected_aes_key_ok = AtcaStatus::AtcaSuccess;
        expected_aes_key_bad_1 = AtcaStatus::AtcaInvalidSize;
    }

    let write_key_set_success = device.add_access_key(ENCRYPTION_KEY_SLOT, &write_key);
    if chip_is_locked && (AtcaStatus::AtcaSuccess == write_key_set_success) {
        expected_priv_key_ok = AtcaStatus::AtcaSuccess;
    }

    let priv_key_ok = device.import_key(KeyType::P256EccKey, &priv_key, 0x02);
    let priv_key_bad_1 = device.import_key(KeyType::P256EccKey, &priv_key_bad, 0x00);
    let priv_key_bad_2 = device.import_key(KeyType::P256EccKey, &priv_key, 0x01);

    let pub_key_ok = device.import_key(KeyType::P256EccKey, &pub_key, 0x0B);
    let pub_key_bad_1 = device.import_key(KeyType::P256EccKey, &pub_key_bad, 0x0B);
    // slot number too low
    let pub_key_bad_2 = device.import_key(KeyType::P256EccKey, &pub_key, 0x03);
    // writing to a slot with a key type other than P256
    let pub_key_bad_3 = device.import_key(KeyType::P256EccKey, &pub_key, 0x0C);

    let aes_key_ok = device.import_key(KeyType::Aes, &aes_key, 0x09);
    let aes_key_bad_1 = device.import_key(KeyType::Aes, &aes_key_bad, 0x09);

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(write_key_set_success, AtcaStatus::AtcaSuccess);

    assert_eq!(priv_key_ok, expected_priv_key_ok);
    assert_eq!(priv_key_bad_1, expected_priv_key_bad_1);
    assert_eq!(priv_key_bad_2, expected_priv_key_bad_2);

    assert_eq!(pub_key_ok, expected_pub_key_ok);
    assert_eq!(pub_key_bad_1, expected_pub_key_bad_1);
    assert_eq!(pub_key_bad_2, expected_pub_key_bad_2);
    assert_eq!(pub_key_bad_3, expected_pub_key_bad_3);

    assert_eq!(aes_key_ok, expected_aes_key_ok);
    assert_eq!(aes_key_bad_1, expected_aes_key_bad_1);
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

    let mut chip_is_locked: bool = true;
    let get_key_ok_1 = device.get_public_key(0x00, &mut public_key);
    let sum: u16 = public_key.iter().fold(0, |s, &x| s + x as u16);
    let get_key_bad_1 = device.get_public_key(0x01, &mut public_key);

    let mut expected_get_key_ok_1 = AtcaStatus::AtcaSuccess;
    let mut expected_get_key_ok_2 = AtcaStatus::AtcaSuccess;
    let mut expected_get_key_bad_1 = AtcaStatus::AtcaBadParam;
    let mut expected_import_key = AtcaStatus::AtcaSuccess;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_get_key_ok_1 = AtcaStatus::AtcaNotLocked;
        expected_get_key_ok_2 = AtcaStatus::AtcaNotLocked;
        expected_get_key_bad_1 = AtcaStatus::AtcaNotLocked;
        expected_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::P256EccKey, &public_key_write, 0x0B);
    let get_key_ok_2 = device.get_public_key(0x0B, &mut public_key);

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_import_key);
    if chip_is_locked {
        assert_eq!(public_key.len(), ATCA_ATECC_PUB_KEY_SIZE);
        assert_ne!(sum, 0);
    }
    if AtcaStatus::AtcaSuccess == get_key_ok_2 {
        assert_eq!(public_key_write, public_key);
    }
    assert_eq!(get_key_ok_1, expected_get_key_ok_1);
    assert_eq!(get_key_ok_2, expected_get_key_ok_2);
    assert_eq!(get_key_bad_1, expected_get_key_bad_1);
}

#[test]
#[serial]
fn export_key_aes() {
    const AES_SLOT_IDX_OK: u8 = 0x09;
    const AES_SLOT_IDX_BAD: u8 = 0x01;
    const ENCRYPTION_KEY_SLOT: u8 = 0x06;

    let device = test_setup();

    let aes_key_write: [u8; ATCA_AES_KEY_SIZE] = [
        0xBA, 0x6A, 0xB5, 0xF1, 0x19, 0xAF, 0x21, 0x73, 0x03, 0x75, 0xD1, 0x8D, 0x6B, 0x5F, 0xF1,
        0x94,
    ];

    let write_key = [
        0x4D, 0x50, 0x72, 0x6F, 0x20, 0x49, 0x4F, 0x20, 0x4B, 0x65, 0x79, 0x20, 0x9E, 0x31, 0xBD,
        0x05, 0x82, 0x58, 0x76, 0xCE, 0x37, 0x90, 0xEA, 0x77, 0x42, 0x32, 0xBB, 0x51, 0x81, 0x49,
        0x66, 0x45,
    ];

    let mut aes_key_read: Vec<u8> = Vec::new();

    let mut expected_export_key_bad_1 = AtcaStatus::AtcaInvalidId;
    let mut expected_export_key_bad_2 = AtcaStatus::AtcaBadParam;
    let mut expected_import_key_result = AtcaStatus::AtcaSuccess;
    let mut expected_export_key_ok_1 = AtcaStatus::AtcaSuccess;

    if !device.is_aes_enabled() {
        expected_export_key_bad_2 = AtcaStatus::AtcaBadParam;
        expected_import_key_result = AtcaStatus::AtcaBadParam;
        expected_export_key_ok_1 = AtcaStatus::AtcaBadParam;
    }
    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        expected_export_key_bad_1 = AtcaStatus::AtcaNotLocked;
        expected_export_key_bad_2 = AtcaStatus::AtcaNotLocked;
        expected_import_key_result = AtcaStatus::AtcaNotLocked;
        expected_export_key_ok_1 = AtcaStatus::AtcaNotLocked;
    }

    let export_key_bad_1 =
        device.export_key(KeyType::Aes, &mut aes_key_read, ATCA_ATECC_SLOTS_COUNT);
    let export_key_bad_2 = device.export_key(KeyType::Aes, &mut aes_key_read, AES_SLOT_IDX_BAD);

    let device_set_write_key = device.add_access_key(ENCRYPTION_KEY_SLOT, &write_key);
    let import_key_result = device.import_key(KeyType::Aes, &aes_key_write, AES_SLOT_IDX_OK);
    let export_key_ok_1 = device.export_key(KeyType::Aes, &mut aes_key_read, AES_SLOT_IDX_OK);
    // Due to the limited number of available slots, there is no AES slot in the configuration with reading without encryption

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(export_key_bad_1, expected_export_key_bad_1);
    assert_eq!(export_key_bad_2, expected_export_key_bad_2);

    assert_eq!(device_set_write_key, AtcaStatus::AtcaSuccess);
    assert_eq!(import_key_result, expected_import_key_result);
    assert_eq!(export_key_ok_1, expected_export_key_ok_1);
    if (AtcaStatus::AtcaNotLocked != expected_export_key_ok_1) && device.is_aes_enabled() {
        assert_eq!(aes_key_read, aes_key_write.to_vec())
    }
}

#[test]
#[serial]
fn sign_verify_hash() {
    let device = test_setup();

    let mut chip_is_fully_locked: bool = true;
    let hash: Vec<u8> = vec![0xA5; 32];
    let internal_sig = SignEcdsaParam {
        is_invalidate: false,
        is_full_sn: false,
    };
    let internal_mac_verify = VerifyEcdsaParam::default();

    let mut signature: Vec<u8> = Vec::new();
    let mut public_key: Vec<u8> = Vec::new();
    let mut is_verified: bool = false;

    let mode_sign = SignMode::Internal(internal_sig);
    let sign_internal = device.sign_hash(mode_sign, 0x00, &mut signature);
    let mode_verify = VerifyMode::InternalMac(internal_mac_verify);
    let mut verify_external_result = AtcaStatus::AtcaSuccess;
    if let Err(err) = device.verify_hash(mode_verify, &hash.to_vec(), &signature) {
        verify_external_result = err
    };

    let mode_sign = SignMode::External(hash.to_vec());
    let sign_external = device.sign_hash(mode_sign, 0x00, &mut signature);
    let get_pub_key_result = device.get_public_key(0x00, &mut public_key);
    let mode_verify = VerifyMode::External(public_key);
    let mut verify_internal_result = AtcaStatus::AtcaSuccess;
    match device.verify_hash(mode_verify, &hash.to_vec(), &signature) {
        Err(err) => verify_internal_result = err,
        Ok(val) => is_verified = val,
    };

    let mut expected_sign_internal = AtcaStatus::AtcaUnimplemented;
    let mut expected_verify_external_result = AtcaStatus::AtcaUnimplemented;
    let mut expected_sign_external = AtcaStatus::AtcaSuccess;
    let mut expected_get_pub_key_result = AtcaStatus::AtcaSuccess;
    let mut expected_verify_internal_result = AtcaStatus::AtcaSuccess;
    if !device.is_configuration_locked() {
        println!("\u{001b}[1m\u{001b}[33mConfiguration not Locked!\u{001b}[0m ");
        expected_get_pub_key_result = AtcaStatus::AtcaNotLocked;
    }
    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mData zone not Locked!\u{001b}[0m ");
        chip_is_fully_locked = false;

        expected_sign_internal = AtcaStatus::AtcaNotLocked;
        expected_verify_external_result = AtcaStatus::AtcaNotLocked;
        expected_sign_external = AtcaStatus::AtcaNotLocked;
        expected_verify_internal_result = AtcaStatus::AtcaNotLocked;
        expected_get_pub_key_result = AtcaStatus::AtcaNotLocked;
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    if chip_is_fully_locked {
        assert_eq!(signature.len(), ATCA_SIG_SIZE);
        assert_eq!(is_verified, true);
    }
    assert_eq!(sign_internal, expected_sign_internal);
    assert_eq!(verify_external_result, expected_verify_external_result);

    assert_eq!(sign_external, expected_sign_external);
    assert_eq!(get_pub_key_result, expected_get_pub_key_result);
    assert_eq!(verify_internal_result, expected_verify_internal_result);
}

#[test]
#[serial]
fn gen_key_sign_hash() {
    const ENCRYPTION_KEY_SLOT: u8 = 0x06;

    let device = test_setup();

    let write_key = [
        0x4D, 0x50, 0x72, 0x6F, 0x20, 0x49, 0x4F, 0x20, 0x4B, 0x65, 0x79, 0x20, 0x9E, 0x31, 0xBD,
        0x05, 0x82, 0x58, 0x76, 0xCE, 0x37, 0x90, 0xEA, 0x77, 0x42, 0x32, 0xBB, 0x51, 0x81, 0x49,
        0x66, 0x45,
    ];

    let mut expected_device_sha = AtcaStatus::AtcaSuccess;
    let mut expected_device_gen_key = AtcaStatus::AtcaSuccess;
    let mut expected_device_sign_hash = AtcaStatus::AtcaSuccess;

    if !device.is_configuration_locked() {
        println!("\u{001b}[1m\u{001b}[33Configuration not Locked!\u{001b}[0m ");
        expected_device_sha = AtcaStatus::AtcaNotLocked;
        expected_device_gen_key = AtcaStatus::AtcaNotLocked;
    }
    if !device.is_data_zone_locked() {
        println!("\u{001b}[1m\u{001b}[33mData zone not Locked!\u{001b}[0m ");
        expected_device_sign_hash = AtcaStatus::AtcaNotLocked;
    }

    let device_set_write_key = device.add_access_key(ENCRYPTION_KEY_SLOT, &write_key);

    let mut digest: Vec<u8> = Vec::new();
    let device_sha = device.sha("Bob wrote this message.".as_bytes().to_vec(), &mut digest);
    let device_gen_key = device.gen_key(KeyType::P256EccKey, 0);
    let mut signature = vec![0u8; ATCA_SIG_SIZE];
    let device_sign_hash = device.sign_hash(SignMode::External(digest), 0, &mut signature);

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(device_set_write_key, AtcaStatus::AtcaSuccess);
    assert_eq!(device_sha, expected_device_sha);
    assert_eq!(device_gen_key, expected_device_gen_key);
    assert_eq!(device_sign_hash, expected_device_sign_hash);
}

#[test]
#[serial]
fn aead_ccm_encrypt_proper_data() {
    let device = test_setup();

    // let mut chip_is_locked: bool = true;

    let aes_key = [
        0xB7, 0xCF, 0x6C, 0xF5, 0xE7, 0xF3, 0xCA, 0x22, 0x3C, 0xA7, 0x3C, 0x81, 0x9D, 0xCD, 0x62,
        0xFE,
    ];
    let iv = [
        0xA4, 0x13, 0x60, 0x09, 0xC0, 0xA7, 0xFD, 0xAC, 0xFE, 0x53, 0xF5, 0x07,
    ];
    //let mut plain_text = [
    let mut data_32 = [
        0x9F, 0xEE, 0xBB, 0xDF, 0x16, 0x0F, 0x96, 0x52, 0x53, 0xD9, 0x99, 0x58, 0xCC, 0xB1, 0x76,
        0xDF, 0x9F, 0xEE, 0xBB, 0xDF, 0x16, 0x0F, 0x96, 0x52, 0x53, 0xD9, 0x99, 0x58, 0xCC, 0xB1,
        0x76, 0xDF,
    ];
    let aad = [
        0x47, 0x6B, 0x48, 0x80, 0xF5, 0x93, 0x33, 0x14, 0xDC, 0xC2, 0x3D, 0xF5, 0xDC, 0xB0, 0x09,
        0x66, 0x47, 0x6B, 0x48, 0x80, 0xF5, 0x93, 0x33, 0x14, 0xDC, 0xC2, 0x3D, 0xF5, 0xDC, 0xB0,
        0x09, 0x66,
    ];

    let param_32 = AeadParam {
        key: Some(aes_key),
        nonce: iv.to_vec(),
        additional_data: Some(aad.to_vec()),
        ..Default::default()
    };

    let mut result_32: AtcaStatus = AtcaStatus::AtcaUnknown;
    // let result_tag_32: Vec<u8> = Vec::new();

    match device.aead_encrypt(
        AeadAlgorithm::Ccm(param_32),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_32,
    ) {
        Ok(_) => (), // Ok(tag) => result_tag_32 = tag,
        Err(err) => result_32 = err,
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    if AtcaStatus::AtcaUnimplemented != result_32 {}
}

#[test]
#[serial]
fn aead_gcm_encrypt_proper_data() {
    const DATA_32_SIZE: usize = 32;
    const DATA_24_SIZE: usize = 24;
    const SHORT_TAG_SIZE: usize = 12;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let aes_key = [
        0xB7, 0xCF, 0x6C, 0xF5, 0xE7, 0xF3, 0xCA, 0x22, 0x3C, 0xA7, 0x3C, 0x81, 0x9D, 0xCD, 0x62,
        0xFE,
    ];
    let iv = [
        0xA4, 0x13, 0x60, 0x09, 0xC0, 0xA7, 0xFD, 0xAC, 0xFE, 0x53, 0xF5, 0x07,
    ];
    let plain_text = [
        0x9F, 0xEE, 0xBB, 0xDF, 0x16, 0x0F, 0x96, 0x52, 0x53, 0xD9, 0x99, 0x58, 0xCC, 0xB1, 0x76,
        0xDF, 0x9F, 0xEE, 0xBB, 0xDF, 0x16, 0x0F, 0x96, 0x52, 0x53, 0xD9, 0x99, 0x58, 0xCC, 0xB1,
        0x76, 0xDF,
    ];
    let cipher_text = [
        0xA6, 0x97, 0x10, 0x3A, 0x70, 0x29, 0x7A, 0xAA, 0xCD, 0x25, 0x9E, 0x1A, 0x85, 0x36, 0xA7,
        0xDC, 0x3E, 0x61, 0x7D, 0xA2, 0xA8, 0x66, 0x3F, 0xD2, 0xFC, 0x5D, 0x6A, 0x6C, 0x36, 0xEA,
        0x2C, 0xD8,
    ];
    let aad = [
        0x47, 0x6B, 0x48, 0x80, 0xF5, 0x93, 0x33, 0x14, 0xDC, 0xC2, 0x3D, 0xF5, 0xDC, 0xB0, 0x09,
        0x66, 0x47, 0x6B, 0x48, 0x80, 0xF5, 0x93, 0x33, 0x14, 0xDC, 0xC2, 0x3D, 0xF5, 0xDC, 0xB0,
        0x09, 0x66,
    ];
    let tag_32 = [
        0x3E, 0xCA, 0xD1, 0x08, 0xF6, 0x8D, 0xC4, 0x54, 0xE6, 0xA1, 0x17, 0x5B, 0x9D, 0x4E, 0x16,
        0xB3,
    ];
    let tag_24 = [
        0x74, 0x99, 0x3B, 0x31, 0x06, 0xBA, 0x6B, 0xE5, 0x00, 0x8F, 0xD5, 0x3A, 0xA4, 0x91, 0xAA,
        0xAF,
    ];

    let param_32 = AeadParam {
        key: Some(aes_key),
        nonce: iv.to_vec(),
        additional_data: Some(aad.to_vec()),
        ..Default::default()
    };
    let param_32_short_tag = AeadParam {
        key: Some(aes_key),
        nonce: iv.to_vec(),
        additional_data: Some(aad.to_vec()),
        tag_length: Some(SHORT_TAG_SIZE as u8),
        ..Default::default()
    };
    let param_24 = AeadParam {
        key: Some(aes_key),
        nonce: iv.to_vec(),
        additional_data: Some(aad[..DATA_24_SIZE].to_vec()),
        ..Default::default()
    };
    let param_32_internal_key = AeadParam {
        nonce: iv.to_vec(),
        additional_data: Some(aad.to_vec()),
        ..Default::default()
    };
    let param_24_internal_key = AeadParam {
        nonce: iv.to_vec(),
        additional_data: Some(aad[..DATA_24_SIZE].to_vec()),
        ..Default::default()
    };

    let mut data_24: [u8; DATA_24_SIZE] = [0x00; DATA_24_SIZE];
    data_24.clone_from_slice(&plain_text[..DATA_24_SIZE]);
    let mut data_32: [u8; DATA_32_SIZE] = [0x00; DATA_32_SIZE];
    data_32.clone_from_slice(&plain_text);
    let mut data_32_short_tag: [u8; DATA_32_SIZE] = [0x00; DATA_32_SIZE];
    data_32_short_tag.clone_from_slice(&plain_text);
    let mut data_24_internal: [u8; DATA_24_SIZE] = [0x00; DATA_24_SIZE];
    data_24_internal.clone_from_slice(&plain_text[..DATA_24_SIZE]);
    let mut data_32_internal: [u8; DATA_32_SIZE] = [0x00; DATA_32_SIZE];
    data_32_internal.clone_from_slice(&plain_text);

    let mut result_tag_32 = vec![0x00; ATCA_AES_KEY_SIZE];
    let mut result_tag_32_short = vec![0x00; SHORT_TAG_SIZE];
    let mut result_tag_24 = vec![0x00; ATCA_AES_KEY_SIZE];
    let mut result_tag_32_internal = vec![0x00; ATCA_AES_KEY_SIZE];
    let mut result_tag_24_internal = vec![0x00; ATCA_AES_KEY_SIZE];

    let mut expected_32 = AtcaStatus::AtcaBadParam;
    let mut expected_32_short_tag = AtcaStatus::AtcaBadParam;
    let mut expected_24 = AtcaStatus::AtcaBadParam;
    let mut expected_32_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_24_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;
    let mut result_32 = AtcaStatus::AtcaUnknown;
    let mut result_32_short_tag = AtcaStatus::AtcaUnknown;
    let mut result_24 = AtcaStatus::AtcaUnknown;
    let mut result_32_internal_key = AtcaStatus::AtcaUnknown;
    let mut result_24_internal_key = AtcaStatus::AtcaUnknown;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_32 = AtcaStatus::AtcaNotLocked;
        expected_32_short_tag = AtcaStatus::AtcaNotLocked;
        expected_24 = AtcaStatus::AtcaNotLocked;
        expected_32_internal_key = AtcaStatus::AtcaNotLocked;
        expected_24_internal_key = AtcaStatus::AtcaNotLocked;
        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected_32 = AtcaStatus::AtcaSuccess;
        expected_32_short_tag = AtcaStatus::AtcaSuccess;
        expected_24 = AtcaStatus::AtcaSuccess;
        expected_32_internal_key = AtcaStatus::AtcaSuccess;
        expected_24_internal_key = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;
        result_32 = AtcaStatus::AtcaSuccess;
        result_32_short_tag = AtcaStatus::AtcaSuccess;
        result_24 = AtcaStatus::AtcaSuccess;
        result_32_internal_key = AtcaStatus::AtcaSuccess;
        result_24_internal_key = AtcaStatus::AtcaSuccess;
    }

    match device.aead_encrypt(
        AeadAlgorithm::Gcm(param_32),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_32,
    ) {
        Ok(tag) => result_tag_32 = tag,
        Err(err) => result_32 = err,
    }

    match device.aead_encrypt(
        AeadAlgorithm::Gcm(param_32_short_tag),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_32_short_tag,
    ) {
        Ok(tag) => result_tag_32_short = tag,
        Err(err) => result_32_short_tag = err,
    }

    match device.aead_encrypt(
        AeadAlgorithm::Gcm(param_24),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_24,
    ) {
        Ok(tag) => result_tag_24 = tag,
        Err(err) => result_24 = err,
    }

    match device.aead_encrypt(
        AeadAlgorithm::Gcm(param_32_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_32_internal,
    ) {
        Ok(tag) => result_tag_32_internal = tag,
        Err(err) => result_32_internal_key = err,
    }

    match device.aead_encrypt(
        AeadAlgorithm::Gcm(param_24_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_24_internal,
    ) {
        Ok(tag) => result_tag_24_internal = tag,
        Err(err) => result_24_internal_key = err,
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert_eq!(result_tag_32, tag_32);
        let mut tag_32_short: Vec<u8> = vec![0x00; SHORT_TAG_SIZE];
        tag_32_short.copy_from_slice(&tag_32[..SHORT_TAG_SIZE]);
        assert_eq!(result_tag_32_short, tag_32_short);
        assert_eq!(data_32, cipher_text);
        assert_eq!(result_tag_24, tag_24);
        assert_eq!(data_24.to_vec(), cipher_text[..DATA_24_SIZE].to_vec());
        assert_eq!(result_tag_32_internal, tag_32);
        assert_eq!(data_32_internal, cipher_text);
        assert_eq!(result_tag_24_internal, tag_24);
        assert_eq!(
            data_24_internal.to_vec(),
            cipher_text[..DATA_24_SIZE].to_vec()
        );
    }
    assert_eq!(result_32, expected_32);
    assert_eq!(result_32_short_tag, expected_32_short_tag);
    assert_eq!(result_24, expected_24);
    assert_eq!(result_32_internal_key, expected_32_internal_key);
    assert_eq!(result_24_internal_key, expected_24_internal_key);
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
    const DATA_32_SIZE: usize = 32;
    const DATA_24_SIZE: usize = 24;
    const SHORT_TAG_SIZE: usize = 12;
    const AES_KEY_SLOT_IDX: u8 = 0x09;

    let device = test_setup();

    let mut chip_is_locked: bool = true;

    let aes_key = [
        0xB7, 0xCF, 0x6C, 0xF5, 0xE7, 0xF3, 0xCA, 0x22, 0x3C, 0xA7, 0x3C, 0x81, 0x9D, 0xCD, 0x62,
        0xFE,
    ];
    let iv = [
        0xA4, 0x13, 0x60, 0x09, 0xC0, 0xA7, 0xFD, 0xAC, 0xFE, 0x53, 0xF5, 0x07,
    ];
    let plain_text = [
        0x9F, 0xEE, 0xBB, 0xDF, 0x16, 0x0F, 0x96, 0x52, 0x53, 0xD9, 0x99, 0x58, 0xCC, 0xB1, 0x76,
        0xDF, 0x9F, 0xEE, 0xBB, 0xDF, 0x16, 0x0F, 0x96, 0x52, 0x53, 0xD9, 0x99, 0x58, 0xCC, 0xB1,
        0x76, 0xDF,
    ];
    let cipher_text = [
        0xA6, 0x97, 0x10, 0x3A, 0x70, 0x29, 0x7A, 0xAA, 0xCD, 0x25, 0x9E, 0x1A, 0x85, 0x36, 0xA7,
        0xDC, 0x3E, 0x61, 0x7D, 0xA2, 0xA8, 0x66, 0x3F, 0xD2, 0xFC, 0x5D, 0x6A, 0x6C, 0x36, 0xEA,
        0x2C, 0xD8,
    ];
    let aad = [
        0x47, 0x6B, 0x48, 0x80, 0xF5, 0x93, 0x33, 0x14, 0xDC, 0xC2, 0x3D, 0xF5, 0xDC, 0xB0, 0x09,
        0x66, 0x47, 0x6B, 0x48, 0x80, 0xF5, 0x93, 0x33, 0x14, 0xDC, 0xC2, 0x3D, 0xF5, 0xDC, 0xB0,
        0x09, 0x66,
    ];
    let tag_32 = [
        0x3E, 0xCA, 0xD1, 0x08, 0xF6, 0x8D, 0xC4, 0x54, 0xE6, 0xA1, 0x17, 0x5B, 0x9D, 0x4E, 0x16,
        0xB3,
    ];
    let tag_24 = [
        0x74, 0x99, 0x3B, 0x31, 0x06, 0xBA, 0x6B, 0xE5, 0x00, 0x8F, 0xD5, 0x3A, 0xA4, 0x91, 0xAA,
        0xAF,
    ];

    let param_32 = AeadParam {
        nonce: iv.to_vec(),
        key: Some(aes_key),
        tag: Some(tag_32.to_vec()),
        additional_data: Some(aad.to_vec()),
        ..Default::default()
    };
    let mut tag_32_short: Vec<u8> = vec![0x00; SHORT_TAG_SIZE];
    tag_32_short.copy_from_slice(&tag_32[..SHORT_TAG_SIZE]);
    let param_32_short_tag = AeadParam {
        nonce: iv.to_vec(),
        key: Some(aes_key),
        tag: Some(tag_32_short),
        additional_data: Some(aad.to_vec()),
        ..Default::default()
    };
    let param_24 = AeadParam {
        nonce: iv.to_vec(),
        key: Some(aes_key),
        tag: Some(tag_24.to_vec()),
        additional_data: Some(aad[..DATA_24_SIZE].to_vec()),
        ..Default::default()
    };
    let param_32_internal_key = AeadParam {
        nonce: iv.to_vec(),
        tag: Some(tag_32.to_vec()),
        additional_data: Some(aad.to_vec()),
        ..Default::default()
    };
    let param_24_internal_key = AeadParam {
        nonce: iv.to_vec(),
        tag: Some(tag_24.to_vec()),
        additional_data: Some(aad[..DATA_24_SIZE].to_vec()),
        ..Default::default()
    };

    let mut data_24: [u8; DATA_24_SIZE] = [0x00; DATA_24_SIZE];
    data_24.clone_from_slice(&cipher_text[..DATA_24_SIZE]);
    let mut data_32: [u8; DATA_32_SIZE] = [0x00; DATA_32_SIZE];
    data_32.clone_from_slice(&cipher_text);
    let mut data_32_short_tag: [u8; DATA_32_SIZE] = [0x00; DATA_32_SIZE];
    data_32_short_tag.clone_from_slice(&cipher_text);
    let mut data_24_internal: [u8; DATA_24_SIZE] = [0x00; DATA_24_SIZE];
    data_24_internal.clone_from_slice(&cipher_text[..DATA_24_SIZE]);
    let mut data_32_internal: [u8; DATA_32_SIZE] = [0x00; DATA_32_SIZE];
    data_32_internal.clone_from_slice(&cipher_text);

    let mut result_tag_32: bool = false;
    let mut result_tag_32_short: bool = false;
    let mut result_tag_24: bool = false;
    let mut result_tag_32_internal: bool = false;
    let mut result_tag_24_internal: bool = false;

    let mut expected_32 = AtcaStatus::AtcaBadParam;
    let mut expected_32_short_tag = AtcaStatus::AtcaBadParam;
    let mut expected_24 = AtcaStatus::AtcaBadParam;
    let mut expected_32_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_24_internal_key = AtcaStatus::AtcaBadParam;
    let mut expected_result_import_key = AtcaStatus::AtcaBadParam;
    let mut result_32 = AtcaStatus::AtcaUnknown;
    let mut result_32_short_tag = AtcaStatus::AtcaUnknown;
    let mut result_24 = AtcaStatus::AtcaUnknown;
    let mut result_32_internal_key = AtcaStatus::AtcaUnknown;
    let mut result_24_internal_key = AtcaStatus::AtcaUnknown;

    if !(device.is_configuration_locked() && device.is_data_zone_locked()) {
        println!("\u{001b}[1m\u{001b}[33mConfiguration and/or Data zone not Locked!\u{001b}[0m ");
        chip_is_locked = false;

        expected_32 = AtcaStatus::AtcaNotLocked;
        expected_32_short_tag = AtcaStatus::AtcaNotLocked;
        expected_24 = AtcaStatus::AtcaNotLocked;
        expected_32_internal_key = AtcaStatus::AtcaNotLocked;
        expected_24_internal_key = AtcaStatus::AtcaNotLocked;
        expected_result_import_key = AtcaStatus::AtcaNotLocked;
    }

    let result_import_key = device.import_key(KeyType::Aes, &aes_key, AES_KEY_SLOT_IDX);

    if chip_is_locked && device.is_aes_enabled() {
        expected_32 = AtcaStatus::AtcaSuccess;
        expected_32_short_tag = AtcaStatus::AtcaSuccess;
        expected_24 = AtcaStatus::AtcaSuccess;
        expected_32_internal_key = AtcaStatus::AtcaSuccess;
        expected_24_internal_key = AtcaStatus::AtcaSuccess;
        expected_result_import_key = AtcaStatus::AtcaSuccess;
        result_32 = AtcaStatus::AtcaSuccess;
        result_32_short_tag = AtcaStatus::AtcaSuccess;
        result_24 = AtcaStatus::AtcaSuccess;
        result_32_internal_key = AtcaStatus::AtcaSuccess;
        result_24_internal_key = AtcaStatus::AtcaSuccess;
    }

    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_32),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_32,
    ) {
        Ok(is_tag_ok) => result_tag_32 = is_tag_ok,
        Err(err) => result_32 = err,
    }

    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_32_short_tag),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_32_short_tag,
    ) {
        Ok(is_tag_ok) => result_tag_32_short = is_tag_ok,
        Err(err) => result_32_short_tag = err,
    }

    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_24),
        ATCA_ATECC_SLOTS_COUNT,
        &mut data_24,
    ) {
        Ok(is_tag_ok) => result_tag_24 = is_tag_ok,
        Err(err) => result_24 = err,
    }

    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_32_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_32_internal,
    ) {
        Ok(is_tag_ok) => result_tag_32_internal = is_tag_ok,
        Err(err) => result_32_internal_key = err,
    }

    match device.aead_decrypt(
        AeadAlgorithm::Gcm(param_24_internal_key),
        AES_KEY_SLOT_IDX,
        &mut data_24_internal,
    ) {
        Ok(is_tag_ok) => result_tag_24_internal = is_tag_ok,
        Err(err) => result_24_internal_key = err,
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_import_key, expected_result_import_key);
    if chip_is_locked && device.is_aes_enabled() {
        assert_eq!(result_tag_32, true);
        assert_eq!(data_32, plain_text);
        assert_eq!(result_tag_32_short, true);
        assert_eq!(data_32_short_tag, plain_text);
        assert_eq!(result_tag_24, true);
        assert_eq!(data_24.to_vec(), plain_text[..DATA_24_SIZE].to_vec());
        assert_eq!(result_tag_32_internal, true);
        assert_eq!(data_32_internal, plain_text);
        assert_eq!(result_tag_24_internal, true);
        assert_eq!(
            data_24_internal.to_vec(),
            plain_text[..DATA_24_SIZE].to_vec()
        );
    }
    assert_eq!(result_32, expected_32);
    assert_eq!(result_32_short_tag, expected_32_short_tag);
    assert_eq!(result_24, expected_24);
    assert_eq!(result_32_internal_key, expected_32_internal_key);
    assert_eq!(result_24_internal_key, expected_24_internal_key);
}

#[test]
#[serial]
fn aead_gcm_decrypt_bad_data() {
    const TAG_TOO_SHORT: usize = 11;
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
fn cmp_config_zone() {
    let device = test_setup();

    let mut config_data = Vec::new();
    let device_read_config_zone = device.read_config_zone(&mut config_data);
    let device_cmp_config_zone: AtcaStatus;
    let mut same_config: bool = false;
    match device.cmp_config_zone(&mut config_data) {
        Ok(val) => {
            same_config = val;
            device_cmp_config_zone = AtcaStatus::AtcaSuccess
        }
        Err(err) => device_cmp_config_zone = err,
    };

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(device_read_config_zone, AtcaStatus::AtcaSuccess);
    assert_eq!(device_cmp_config_zone, AtcaStatus::AtcaSuccess);
    assert_eq!(same_config, true);
}

#[test]
#[serial]
fn is_configuration_locked() {
    let device = test_setup();

    let is_locked = device.is_configuration_locked();

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(is_locked, true);
}

#[test]
#[serial]
fn is_data_zone_locked() {
    let device = test_setup();

    let is_locked = device.is_data_zone_locked();

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(is_locked, true);
}

#[test]
#[serial]
fn get_config_from_config_zone() {
    let device = test_setup();

    let mut config_data = Vec::new();
    let device_atcab_read_config_zone = device.read_config_zone(&mut config_data);

    config_data[88] = 0b10111111;
    config_data[89] = 0b01111111;
    config_data[20] = 0b10000000;
    config_data[22] = 0b00000000;
    let mut slots: Vec<AtcaSlot> = Vec::new();
    atcab_get_config_from_config_zone(&config_data, &mut slots);

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(device_atcab_read_config_zone, AtcaStatus::AtcaSuccess);
    assert_eq!(slots.len(), usize::from(ATCA_ATECC_SLOTS_COUNT));
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

    let mut slots: Vec<AtcaSlot> = Vec::new();
    let get_config = device.get_config(&mut slots);

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(get_config, AtcaStatus::AtcaSuccess);
    assert_eq!(slots.len(), ATCA_ATECC_SLOTS_COUNT as usize);
}

#[test]
#[serial]
fn info_cmd() {
    let device = test_setup();

    let mut result_key_valid = AtcaStatus::AtcaSuccess;
    let mut result_revision = AtcaStatus::AtcaSuccess;
    let mut revision: Vec<u8> = Vec::new();

    match device.info_cmd(InfoCmdType::KeyValid) {
        Ok(_val) => (),
        Err(err) => result_key_valid = err,
    }

    match device.info_cmd(InfoCmdType::Revision) {
        Ok(val) => revision = val,
        Err(err) => result_revision = err,
    }

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_key_valid, AtcaStatus::AtcaUnimplemented);
    assert_eq!(revision.len(), 4);
    assert_eq!(result_revision, AtcaStatus::AtcaSuccess);
}

#[test]
#[serial]
fn add_get_and_flush_access_keys() {
    const ATCA_KEY_SIZE: usize = 32;
    const OK_KEY_IDX_1: u8 = 0x06;
    const OK_KEY_IDX_2: u8 = (ATCA_ATECC_SLOTS_COUNT) - 1;
    const BAD_KEY_IDX_1: u8 = 0x05;
    const BAD_KEY_IDX_2: u8 = OK_KEY_IDX_2 + 1;
    const BAD_KEY_IDX_3: u8 = BAD_KEY_IDX_2 + 1;

    let device = test_setup();

    let test_key_1 = [
        0x4D, 0x50, 0x72, 0x6F, 0x20, 0x49, 0x4F, 0x20, 0x4B, 0x65, 0x79, 0x20, 0x9E, 0x31, 0xBD,
        0x05, 0x82, 0x58, 0x76, 0xCE, 0x37, 0x90, 0xEA, 0x77, 0x42, 0x32, 0xBB, 0x51, 0x81, 0x49,
        0x66, 0x45,
    ]
    .to_vec();
    let test_key_2 = [
        0x1A, 0x8A, 0x9D, 0xA1, 0x85, 0x99, 0x61, 0xE8, 0x00, 0x7B, 0xDB, 0x7A, 0x38, 0x10, 0x4D,
        0x33, 0x2F, 0xD6, 0xA3, 0x4B, 0xFF, 0x59, 0x17, 0xA7, 0x3B, 0x3F, 0x78, 0xCF, 0x37, 0x43,
        0x4F, 0x2D,
    ]
    .to_vec();

    let device_add_key_ok_1 = device.add_access_key(OK_KEY_IDX_1, &test_key_1);
    let mut device_get_key_ok_1 = vec![0; ATCA_KEY_SIZE];
    let result_get_key_ok_1 = device.get_access_key(OK_KEY_IDX_1, &mut device_get_key_ok_1);

    let device_add_key_ok_2 = device.add_access_key(OK_KEY_IDX_1, &test_key_2);
    let mut device_get_key_ok_2 = vec![0; ATCA_KEY_SIZE];
    let result_get_key_ok_2 = device.get_access_key(OK_KEY_IDX_1, &mut device_get_key_ok_2);

    let device_add_key_ok_3 = device.add_access_key(OK_KEY_IDX_2, &test_key_1);
    let mut device_get_key_ok_3 = vec![0; ATCA_KEY_SIZE];
    let result_get_key_ok_3 = device.get_access_key(OK_KEY_IDX_2, &mut device_get_key_ok_3);

    let device_add_key_bad_1 = device.add_access_key(BAD_KEY_IDX_3, &test_key_1);
    let device_add_key_bad_2 = device.add_access_key(OK_KEY_IDX_1, &test_key_1[0..=25]);

    let mut temp_arr = vec![0; ATCA_KEY_SIZE];
    let device_get_key_bad_1 = device.get_access_key(BAD_KEY_IDX_1, &mut temp_arr);
    let device_get_key_bad_2 = device.get_access_key(BAD_KEY_IDX_2, &mut temp_arr);

    device.flush_access_keys();
    let device_get_key_bad_3 = device.get_access_key(OK_KEY_IDX_1, &mut temp_arr);

    assert_eq!(device.release().to_string(), "AtcaSuccess");

    assert_eq!(result_get_key_ok_1, AtcaStatus::AtcaSuccess);
    assert_eq!(result_get_key_ok_2, AtcaStatus::AtcaSuccess);
    assert_eq!(result_get_key_ok_3, AtcaStatus::AtcaSuccess);
    assert_eq!(device_add_key_ok_1, AtcaStatus::AtcaSuccess);
    assert_eq!(device_get_key_ok_1, test_key_1);
    assert_eq!(device_add_key_ok_2, AtcaStatus::AtcaSuccess);
    assert_eq!(device_get_key_ok_2, test_key_2);
    assert_eq!(device_add_key_ok_3, AtcaStatus::AtcaSuccess);
    assert_eq!(device_get_key_ok_3, test_key_1);

    assert_eq!(device_add_key_bad_1, AtcaStatus::AtcaInvalidId);
    assert_eq!(device_add_key_bad_2, AtcaStatus::AtcaInvalidSize);
    assert_eq!(device_get_key_bad_1, AtcaStatus::AtcaInvalidId);
    assert_eq!(device_get_key_bad_2, AtcaStatus::AtcaInvalidId);
    assert_eq!(device_get_key_bad_3, AtcaStatus::AtcaInvalidId);
}
