mod c2rust;
mod rust2c;
#[cfg(test)]
mod unit_tests;
use std::convert::{From, TryFrom};
use std::sync::Mutex;
#[macro_use]
extern crate lazy_static;

include!("./types.rs");

struct AteccResourceManager {
    ref_counter: u8,
}

lazy_static! {
    static ref ATECC_RESOURCE_MANAGER: Mutex<AteccResourceManager> =
        Mutex::new(AteccResourceManager { ref_counter: 0 });
}

impl AteccResourceManager {
    fn acquire(&mut self) -> bool {
        if self.ref_counter == 0 {
            self.ref_counter = 1;
            true
        } else {
            false
        }
    }

    fn release(&mut self) -> bool {
        if self.ref_counter == 1 {
            self.ref_counter = 0;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct AteccDevice {
    iface_cfg_ptr: AtcaIfaceCfgPtrWrapper,
    api_mutex: Mutex<()>,
}

impl AteccDevice {
    pub fn new(r_iface_cfg: AtcaIfaceCfg) -> Result<AteccDevice, String> {
        if !ATECC_RESOURCE_MANAGER.lock().unwrap().acquire() {
            return Err(AtcaStatus::AtcaAllocFailure.to_string());
        }
        let iface_cfg = Box::new(
            match cryptoauthlib_sys::ATCAIfaceCfg::try_from(r_iface_cfg) {
                Ok(x) => x,
                Err(()) => {
                    ATECC_RESOURCE_MANAGER.lock().unwrap().release();
                    return Err(AtcaStatus::AtcaBadParam.to_string());
                }
            },
        );
        let iface_cfg_raw_ptr: *mut cryptoauthlib_sys::ATCAIfaceCfg = Box::into_raw(iface_cfg);
        // From now on iface_cfg is consumed and iface_cfg_ptr must be stored to be released
        // when no longer needed.
        let init_status =
            AtcaStatus::from(unsafe { cryptoauthlib_sys::atcab_init(iface_cfg_raw_ptr) });
        let atecc_device = match init_status {
            AtcaStatus::AtcaSuccess => AteccDevice {
                iface_cfg_ptr: AtcaIfaceCfgPtrWrapper {
                    ptr: iface_cfg_raw_ptr,
                },
                api_mutex: Mutex::new(()),
            },
            _ => {
                ATECC_RESOURCE_MANAGER.lock().unwrap().release();
                unsafe { Box::from_raw(iface_cfg_raw_ptr) };
                return Err(init_status.to_string());
            }
        };
        Ok(atecc_device)
    } // AteccDevice::new()

    pub fn sha(&self, message: Vec<u8>, digest: &mut Vec<u8>) -> AtcaStatus {
        let length: u16 = match u16::try_from(message.len()) {
            Ok(val) => val,
            Err(_) => return AtcaStatus::AtcaBadParam,
        };

        let digest_size: usize = cryptoauthlib_sys::ATCA_SHA2_256_DIGEST_SIZE as usize;

        if digest.len() != digest_size {
            digest.resize(digest_size, 0);
        }
        AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_sha(length, message.as_ptr(), digest.as_mut_ptr())
        })
    } // AteccDevice::sha()

    pub fn random(&self, rand_out: &mut Vec<u8>) -> AtcaStatus {
        if rand_out.len() != ATCA_RANDOM_BUFFER_SIZE {
            rand_out.resize(ATCA_RANDOM_BUFFER_SIZE, 0);
        }
        AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_random(rand_out.as_mut_ptr())
        })
    } // AteccDevice::random()

    fn read_zone(
        &self,
        zone: u8,
        slot: u16,
        block: u8,
        offset: u8,
        data: &mut Vec<u8>,
        len: u8,
    ) -> AtcaStatus {
        if data.len() != len as usize {
            data.resize(len as usize, 0)
        };
        AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_read_zone(zone, slot, block, offset, data.as_mut_ptr(), len)
        })
    } // AteccDevice::read_zone()

    fn write_zone(
        &self,
        zone: u8,
        slot: u16,
        block: u8,
        offset: u8,
        data: &mut Vec<u8>,
        len: u8,
    ) -> AtcaStatus {
        if data.len() != len as usize {
            data.resize(len as usize, 0)
        };
        AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_write_zone(zone, slot, block, offset, data.as_mut_ptr(), len)
        })
    } // AteccDevice::write_zone()

    fn aes_enabled(&self) -> Result<bool, AtcaStatus> {
        const LEN: u8 = 4;
        const OFFSET: u8 = 3;
        const INDEX_OF_AES_BYTE: usize = 1;
        const INDEX_OF_AES_BIT: u8 = 0;

        let mut data: Vec<u8> = Vec::with_capacity(LEN as usize);
        let result = self.read_zone(ATCA_ZONE_CONFIG, 0, 0, OFFSET, &mut data, LEN);
        if result != AtcaStatus::AtcaSuccess {
            Err(result)
        } else {
            Ok(atcab_get_bit_value(
                data[INDEX_OF_AES_BYTE],
                INDEX_OF_AES_BIT,
            ))
        }
    }

    pub fn gen_key(&self, key_type: KeyType, slot_number: u8) -> AtcaStatus {
        let mut _aes_enabled: bool = false;
        if key_type == KeyType::Aes {
            match self.aes_enabled() {
                Ok(val) => {
                    _aes_enabled = val;
                }
                Err(err) => return err,
            }
        };

        if (slot_number > ATCA_ATECC_SLOTS_COUNT)
            | ((slot_number == ATCA_ATECC_SLOTS_COUNT) & (key_type != KeyType::Aes))    // This is a special situation when an AES key can be generated in an ATECC TempKey slot.
            | ((key_type == KeyType::Aes) & !_aes_enabled)
        {
            return AtcaStatus::AtcaBadParam;
        }

        let slot = match slot_number {
            ATCA_ATECC_SLOTS_COUNT => cryptoauthlib_sys::ATCA_TEMPKEY_KEYID as u16,
            _ => slot_number as u16,
        };

        match key_type {
            KeyType::P256EccKey => {
                use std::ptr;
                return AtcaStatus::from(unsafe {
                    let _guard = self
                        .api_mutex
                        .lock()
                        .expect("Could not lock atcab API mutex");
                    cryptoauthlib_sys::atcab_genkey(slot, ptr::null_mut() as *mut u8)
                });
            }
            KeyType::Aes => {
                let mut key: Vec<u8> = Vec::with_capacity(ATCA_RANDOM_BUFFER_SIZE);
                let result = self.random(&mut key);
                if result != AtcaStatus::AtcaSuccess {
                    return result;
                };
                if key.len() > ATCA_AES_KEY_SIZE {
                    key.truncate(ATCA_AES_KEY_SIZE);
                }
                if key.len() < cryptoauthlib_sys::ATCA_BLOCK_SIZE as usize {
                    key.resize(cryptoauthlib_sys::ATCA_BLOCK_SIZE as usize, 0);
                }
                if slot != cryptoauthlib_sys::ATCA_TEMPKEY_KEYID as u16 {
                    const BLOCK_IDX: u8 = 0;
                    const OFFSET: u8 = 0;
                    // It will generate an error when SlotConfig.write_config = Encrypt
                    self.write_zone(
                        ATCA_ZONE_DATA,
                        slot,
                        BLOCK_IDX,
                        OFFSET,
                        &mut key,
                        cryptoauthlib_sys::ATCA_BLOCK_SIZE as u8,
                    )
                } else {
                    AtcaStatus::AtcaUnimplemented
                }
            }
            _ => AtcaStatus::AtcaBadParam,
        }
    } // AteccDevice::gen_key()

    pub fn get_device(&self) -> AtcaDevice {
        AtcaDevice {
            dev: unsafe {
                let _guard = self
                    .api_mutex
                    .lock()
                    .expect("Could not lock atcab API mutex");
                cryptoauthlib_sys::atcab_get_device()
            },
        }
    } // AteccDevice::get_device()

    pub fn get_device_type(&self) -> AtcaDeviceType {
        AtcaDeviceType::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_get_device_type()
        })
    } // AteccDevice::get_device_type()

    fn is_locked(&self, zone: u8, is_locked: *mut bool) -> AtcaStatus {
        AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_is_locked(zone, is_locked)
        })
    } // AteccDevice::is_locked()

    pub fn configuration_is_locked(&self, is_locked: &mut bool) -> AtcaStatus {
        self.is_locked(ATCA_ZONE_CONFIG, is_locked)
    } // AteccDevice::configuration_is_locked()

    fn get_config_buffer_size(&self) -> usize {
        let device_type = self.get_device_type();
        match device_type {
            AtcaDeviceType::ATECC508A | AtcaDeviceType::ATECC608A | AtcaDeviceType::ATECC108A => {
                ATCA_ATECC_CONFIG_BUFFER_SIZE
            }
            _ => ATCA_ATSHA_CONFIG_BUFFER_SIZE,
        }
    } // AteccDevice::get_config_buffer_size()

    pub fn read_config_zone(&self, config_data: &mut Vec<u8>) -> AtcaStatus {
        let buffer_size = self.get_config_buffer_size();
        if config_data.len() != buffer_size {
            config_data.resize(buffer_size, 0);
        }
        AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_read_config_zone(config_data.as_mut_ptr())
        })
    } // AteccDevice::read_config_zone()

    pub fn cmp_config_zone(&self, config_data: &mut Vec<u8>, same_config: &mut bool) -> AtcaStatus {
        let buffer_size = self.get_config_buffer_size();
        if config_data.len() != buffer_size {
            return AtcaStatus::AtcaBadParam;
        }
        AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_cmp_config_zone(config_data.as_mut_ptr(), same_config)
        })
    } // AteccDevice::cmp_config_zone()

    pub fn release(&self) -> AtcaStatus {
        if !ATECC_RESOURCE_MANAGER.lock().unwrap().release() {
            return AtcaStatus::AtcaBadParam;
        }
        AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            // Restore iface_cfg from iface_cfg_ptr for the boxed structure to be released
            // at the end.
            Box::from_raw(self.iface_cfg_ptr.ptr);
            cryptoauthlib_sys::atcab_release()
        })
    } // AteccDevice::release()

    pub fn get_config(&self, atca_slots: &mut Vec<AtcaSlot>) -> AtcaStatus {
        let mut config_data = Vec::new();
        let err = self.read_config_zone(&mut config_data);
        if AtcaStatus::AtcaSuccess != err {
            return err;
        }
        if config_data.len() != self.get_config_buffer_size() {
            return AtcaStatus::AtcaBadParam;
        }
        // Drop the input atca_slots as well as all of its contents
        // ... and create a new one
        *atca_slots = Vec::new();
        atcab_get_config_from_config_zone(&config_data, atca_slots);
        AtcaStatus::AtcaSuccess
    }
}

pub fn atca_iface_setup_i2c(
    device_type: String,
    wake_delay: u16,
    rx_retries: i32,
    // I2C salve address
    slave_address: Option<u8>,
    // I2C bus number
    bus: Option<u8>,
    // I2C baud rate
    baud: Option<u32>,
) -> Result<AtcaIfaceCfg, String> {
    let atca_iface_cfg = AtcaIfaceCfg {
        iface_type: AtcaIfaceType::AtcaI2cIface,
        devtype: match device_type.as_str() {
            "atecc608a" => AtcaDeviceType::ATECC608A,
            "atecc508a" => AtcaDeviceType::ATECC508A,
            _ => {
                let e = "Unsupported device type ".to_owned() + device_type.as_str();
                return Err(e);
            }
        },
        iface: AtcaIface {
            atcai2c: AtcaIfaceI2c {
                // unwrap_or_else_return()?
                slave_address: match slave_address {
                    Some(x) => x,
                    _ => return Err("missing i2c slave address".to_owned()),
                },
                bus: match bus {
                    Some(x) => x,
                    _ => return Err("missing i2c bus".to_owned()),
                },
                baud: match baud {
                    Some(x) => x,
                    _ => return Err("missing i2c baud rate".to_owned()),
                },
            },
        },
        rx_retries,
        wake_delay,
    };
    Ok(atca_iface_cfg)
}

fn atcab_get_bit_value(byte: u8, bit_pos: u8) -> bool {
    if bit_pos < 8 {
        ((byte >> bit_pos) & 1) != 0
    } else {
        false
    }
}

fn atcab_get_write_config(data: u8) -> WriteConfig {
    match data & 0b00001111 {
        0 => WriteConfig::Always,
        1 => WriteConfig::PubInvalid,
        2..=3 => WriteConfig::Never,
        4..=7 => WriteConfig::Encrypt,
        8..=11 => WriteConfig::Never,
        _ => WriteConfig::Encrypt,
    }
}

fn atcab_get_key_type(data: u8) -> KeyType {
    match data & 0b00000111 {
        4 => KeyType::P256EccKey,
        6 => KeyType::Aes,
        7 => KeyType::ShaOrText,
        _ => KeyType::Rfu,
    }
}

fn atcab_get_config_from_config_zone(config_data: &[u8], atca_slots: &mut Vec<AtcaSlot>) {
    const IDX_SLOT_LOCKED: usize = 88;
    const IDX_SLOT_CONFIG: usize = 20;
    const IDX_KEY_CONFIG: usize = 96;
    for idx in 0..ATCA_ATECC_SLOTS_COUNT {
        let slot_cfg_pos = IDX_SLOT_CONFIG + (idx * 2) as usize;
        let key_cfg_pos = IDX_KEY_CONFIG + (idx * 2) as usize;
        let read_key_struct = ReadKey {
            encrypt_read: atcab_get_bit_value(config_data[slot_cfg_pos], 6),
            slot_number: config_data[slot_cfg_pos] & 0b00001111,
        };
        let ecc_key_attr_struct = EccKeyAttr {
            is_private: atcab_get_bit_value(config_data[key_cfg_pos], 0),
            ext_sign: atcab_get_bit_value(config_data[slot_cfg_pos], 0),
            int_sign: atcab_get_bit_value(config_data[slot_cfg_pos], 1),
            ecdh_operation: atcab_get_bit_value(config_data[slot_cfg_pos], 2),
            ecdh_secret_out: atcab_get_bit_value(config_data[slot_cfg_pos], 3),
        };
        let config_struct = SlotConfig {
            write_config: atcab_get_write_config(config_data[slot_cfg_pos + 1] >> 4),
            key_type: atcab_get_key_type(config_data[key_cfg_pos] >> 2),
            read_key: read_key_struct,
            ecc_key_attr: ecc_key_attr_struct,
            x509id: (config_data[key_cfg_pos + 1] >> 6) & 0b00000011,
            auth_key: config_data[key_cfg_pos + 1] & 0b00001111,
            write_key: config_data[slot_cfg_pos + 1] & 0b00001111,
            is_secret: atcab_get_bit_value(config_data[slot_cfg_pos], 7),
            limited_use: atcab_get_bit_value(config_data[slot_cfg_pos], 5),
            no_mac: atcab_get_bit_value(config_data[slot_cfg_pos], 4),
            persistent_disable: atcab_get_bit_value(config_data[key_cfg_pos + 1], 4),
            req_auth: atcab_get_bit_value(config_data[key_cfg_pos], 7),
            req_random: atcab_get_bit_value(config_data[key_cfg_pos], 6),
            lockable: atcab_get_bit_value(config_data[key_cfg_pos], 5),
            pub_info: atcab_get_bit_value(config_data[key_cfg_pos], 1),
        };
        let slot = AtcaSlot {
            id: idx,
            is_locked: {
                let index = IDX_SLOT_LOCKED + (idx / 8) as usize;
                let bit_position = idx % 8;
                let bit_value = (config_data[index] >> bit_position) & 1;
                bit_value != 1
            },
            config: config_struct,
        };
        atca_slots.push(slot);
    }
}
