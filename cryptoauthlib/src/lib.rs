mod c2rust;
mod rust2c;
#[cfg(test)]
mod unit_tests;
use std::convert::TryFrom;
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
        let iface_cfg = Box::new(match rust2c::r2c_atca_iface_cfg(r_iface_cfg) {
            Some(x) => x,
            None => {
                ATECC_RESOURCE_MANAGER.lock().unwrap().release();
                return Err(AtcaStatus::AtcaBadParam.to_string());
            }
        });
        let iface_cfg_raw_ptr: *mut cryptoauthlib_sys::ATCAIfaceCfg = Box::into_raw(iface_cfg);
        // From now on iface_cfg is consumed and iface_cfg_ptr must be stored to be released
        // when no longer needed.
        let init_status =
            c2rust::c2r_enum_status(unsafe { cryptoauthlib_sys::atcab_init(iface_cfg_raw_ptr) });
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
        c2rust::c2r_enum_status(unsafe {
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
        c2rust::c2r_enum_status(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_random(rand_out.as_mut_ptr())
        })
    } // AteccDevice::random()

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
        c2rust::c2r_enum_devtype(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_get_device_type()
        })
    } // AteccDevice::get_device_type()

    fn is_locked(&self, zone: u8, is_locked: *mut bool) -> AtcaStatus {
        c2rust::c2r_enum_status(unsafe {
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
        c2rust::c2r_enum_status(unsafe {
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
        c2rust::c2r_enum_status(unsafe {
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
        c2rust::c2r_enum_status(unsafe {
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
    for _id in 0..ATCA_ATECC_SLOTS {
        let _slot_cfg_pos = IDX_SLOT_CONFIG + (_id * 2) as usize;
        let _key_cfg_pos = IDX_KEY_CONFIG + (_id * 2) as usize;
        let _read_key = ReadKey {
            encrypt_read: atcab_get_bit_value(config_data[_slot_cfg_pos], 6),
            slot_number: config_data[_slot_cfg_pos] & 0b00001111,
        };
        let _ecc_key_attr = EccKeyAttr {
            is_private: atcab_get_bit_value(config_data[_key_cfg_pos], 0),
            ext_sign: atcab_get_bit_value(config_data[_slot_cfg_pos], 0),
            int_sign: atcab_get_bit_value(config_data[_slot_cfg_pos], 1),
            ecdh_operation: atcab_get_bit_value(config_data[_slot_cfg_pos], 2),
            ecdh_secret_out: atcab_get_bit_value(config_data[_slot_cfg_pos], 3),
        };
        let _config = SlotConfig {
            write_config: atcab_get_write_config(config_data[_slot_cfg_pos + 1] >> 4),
            key_type: atcab_get_key_type(config_data[_key_cfg_pos] >> 2),
            read_key: _read_key,
            ecc_key_attr: _ecc_key_attr,
            x509id: (config_data[_key_cfg_pos + 1] >> 6) & 0b00000011,
            auth_key: config_data[_key_cfg_pos + 1] & 0b00001111,
            write_key: config_data[_slot_cfg_pos + 1] & 0b00001111,
            is_secret: atcab_get_bit_value(config_data[_slot_cfg_pos], 7),
            limited_use: atcab_get_bit_value(config_data[_slot_cfg_pos], 5),
            no_mac: atcab_get_bit_value(config_data[_slot_cfg_pos], 4),
            persistent_disable: atcab_get_bit_value(config_data[_key_cfg_pos + 1], 4),
            req_auth: atcab_get_bit_value(config_data[_key_cfg_pos], 7),
            req_random: atcab_get_bit_value(config_data[_key_cfg_pos], 6),
            lockable: atcab_get_bit_value(config_data[_key_cfg_pos], 5),
            pub_info: atcab_get_bit_value(config_data[_key_cfg_pos], 1),
        };
        let slot = AtcaSlot {
            id: _id,
            is_locked: {
                let _index = IDX_SLOT_LOCKED + (_id / 8) as usize;
                let _bit_position = _id % 8;
                let _bit_value = (config_data[_index] >> _bit_position) & 1;
                _bit_value != 1
            },
            config: _config,
        };
        atca_slots.push(slot);
    }
}

//
// Obsolete section - everything below will be gone soon
//

// Unfortunately cryptoauthlib takes ATCAIfaceCfg pointer as a field inside
// _gDevice->mIface->mIfaceCFG, so it _must_ be taken from heap.bool
// It adds several lines of code to implement it...
static mut GLOBAL_IFACE_CFG_PTR: *mut cryptoauthlib_sys::ATCAIfaceCfg =
    0 as *mut cryptoauthlib_sys::ATCAIfaceCfg;

/// Creates a global ATCADevice object used by Basic API.
pub fn atcab_init(r_iface_cfg: AtcaIfaceCfg) -> AtcaStatus {
    let mut iface_cfg_ptr;
    let allow_allocation: bool =
        unsafe { GLOBAL_IFACE_CFG_PTR == std::ptr::null_mut::<cryptoauthlib_sys::ATCAIfaceCfg>() };
    if allow_allocation {
        iface_cfg_ptr = Box::new(match rust2c::r2c_atca_iface_cfg(r_iface_cfg) {
            Some(x) => x,
            None => return AtcaStatus::AtcaBadParam,
        });
        unsafe { GLOBAL_IFACE_CFG_PTR = &mut *iface_cfg_ptr };
        std::mem::forget(iface_cfg_ptr);
    }

    c2rust::c2r_enum_status(unsafe { cryptoauthlib_sys::atcab_init(GLOBAL_IFACE_CFG_PTR) })
}

/// Use the SHA command to compute a SHA-256 digest.
pub fn atcab_sha(message: Vec<u8>, digest: &mut Vec<u8>) -> AtcaStatus {
    let length: u16 = match u16::try_from(message.len()) {
        Ok(val) => val,
        Err(_) => return AtcaStatus::AtcaBadParam,
    };

    let digest_size: usize = cryptoauthlib_sys::ATCA_SHA2_256_DIGEST_SIZE as usize;

    if digest.len() != digest_size {
        digest.resize(digest_size, 0);
    }

    c2rust::c2r_enum_status(unsafe {
        cryptoauthlib_sys::atcab_sha(length, message.as_ptr(), digest.as_mut_ptr())
    })
}

/// Get the global device object
pub fn atcab_get_device() -> AtcaDevice {
    AtcaDevice {
        dev: unsafe { cryptoauthlib_sys::atcab_get_device() },
    }
}

pub fn atcab_get_device_type() -> AtcaDeviceType {
    c2rust::c2r_enum_devtype(unsafe { cryptoauthlib_sys::atcab_get_device_type() })
}

pub fn atcab_random(rand_out: &mut Vec<u8>) -> AtcaStatus {
    if rand_out.len() != ATCA_RANDOM_BUFFER_SIZE {
        rand_out.resize(ATCA_RANDOM_BUFFER_SIZE, 0);
    }

    c2rust::c2r_enum_status(unsafe { cryptoauthlib_sys::atcab_random(rand_out.as_mut_ptr()) })
}

fn atcab_is_locked(zone: u8, is_locked: *mut bool) -> AtcaStatus {
    c2rust::c2r_enum_status(unsafe { cryptoauthlib_sys::atcab_is_locked(zone, is_locked) })
}

pub fn atcab_configuration_is_locked(is_locked: &mut bool) -> AtcaStatus {
    atcab_is_locked(ATCA_ZONE_CONFIG, is_locked)
}

fn atcab_get_config_buffer_size() -> usize {
    let device_type = atcab_get_device_type();
    match device_type {
        AtcaDeviceType::ATECC508A | AtcaDeviceType::ATECC608A | AtcaDeviceType::ATECC108A => {
            ATCA_ATECC_CONFIG_BUFFER_SIZE
        }
        _ => ATCA_ATSHA_CONFIG_BUFFER_SIZE,
    }
}

pub fn atcab_read_config_zone(config_data: &mut Vec<u8>) -> AtcaStatus {
    let buffer_size = atcab_get_config_buffer_size();
    if config_data.len() != buffer_size {
        config_data.resize(buffer_size, 0);
    }
    c2rust::c2r_enum_status(unsafe {
        cryptoauthlib_sys::atcab_read_config_zone(config_data.as_mut_ptr())
    })
}

pub fn atcab_cmp_config_zone(config_data: &mut Vec<u8>, same_config: &mut bool) -> AtcaStatus {
    let buffer_size = atcab_get_config_buffer_size();
    if config_data.len() != buffer_size {
        return AtcaStatus::AtcaBadParam;
    }
    c2rust::c2r_enum_status(unsafe {
        cryptoauthlib_sys::atcab_cmp_config_zone(config_data.as_mut_ptr(), same_config)
    })
}

pub fn atcab_get_config(config_data: &[u8], atca_slots: &mut Vec<AtcaSlot>) -> AtcaStatus {
    const IDX_SLOT_LOCKED: usize = 88;
    const IDX_SLOT_CONFIG: usize = 20;
    const IDX_KEY_CONFIG: usize = 96;
    if config_data.len() != atcab_get_config_buffer_size() {
        return AtcaStatus::AtcaBadParam;
    }
    *atca_slots = Vec::new();
    for _id in 0..ATCA_ATECC_SLOTS {
        let _slot_cfg_pos = IDX_SLOT_CONFIG + (_id * 2) as usize;
        let _key_cfg_pos = IDX_KEY_CONFIG + (_id * 2) as usize;
        let _read_key = ReadKey {
            encrypt_read: atcab_get_bit_value(config_data[_slot_cfg_pos], 6),
            slot_number: config_data[_slot_cfg_pos] & 0b00001111,
        };
        let _ecc_key_attr = EccKeyAttr {
            is_private: atcab_get_bit_value(config_data[_key_cfg_pos], 0),
            ext_sign: atcab_get_bit_value(config_data[_slot_cfg_pos], 0),
            int_sign: atcab_get_bit_value(config_data[_slot_cfg_pos], 1),
            ecdh_operation: atcab_get_bit_value(config_data[_slot_cfg_pos], 2),
            ecdh_secret_out: atcab_get_bit_value(config_data[_slot_cfg_pos], 3),
        };
        let _config = SlotConfig {
            write_config: atcab_get_write_config(config_data[_slot_cfg_pos + 1] >> 4),
            key_type: atcab_get_key_type(config_data[_key_cfg_pos] >> 2),
            read_key: _read_key,
            ecc_key_attr: _ecc_key_attr,
            x509id: (config_data[_key_cfg_pos + 1] >> 6) & 0b00000011,
            auth_key: config_data[_key_cfg_pos + 1] & 0b00001111,
            write_key: config_data[_slot_cfg_pos + 1] & 0b00001111,
            is_secret: atcab_get_bit_value(config_data[_slot_cfg_pos], 7),
            limited_use: atcab_get_bit_value(config_data[_slot_cfg_pos], 5),
            no_mac: atcab_get_bit_value(config_data[_slot_cfg_pos], 4),
            persistent_disable: atcab_get_bit_value(config_data[_key_cfg_pos + 1], 4),
            req_auth: atcab_get_bit_value(config_data[_key_cfg_pos], 7),
            req_random: atcab_get_bit_value(config_data[_key_cfg_pos], 6),
            lockable: atcab_get_bit_value(config_data[_key_cfg_pos], 5),
            pub_info: atcab_get_bit_value(config_data[_key_cfg_pos], 1),
        };
        let slot = AtcaSlot {
            id: _id,
            is_locked: {
                let _index = IDX_SLOT_LOCKED + (_id / 8) as usize;
                let _bit_position = _id % 8;
                let _bit_value = (config_data[_index] >> _bit_position) & 1;
                _bit_value != 1
            },
            config: _config,
        };
        atca_slots.push(slot);
    }
    AtcaStatus::AtcaSuccess
}

pub fn atcab_release() -> AtcaStatus {
    c2rust::c2r_enum_status(unsafe { cryptoauthlib_sys::atcab_release() })
}
