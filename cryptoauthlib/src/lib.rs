mod c2rust;
mod rust2c;
#[cfg(test)]
mod unit_tests;
use std::convert::{From, TryFrom};
use std::ptr;
use std::sync::Mutex;
#[macro_use]
extern crate lazy_static;

include!("./types.rs");
include!("./constants.rs");

struct AteccResourceManager {
    ref_counter: u8,
}

lazy_static! {
    static ref ATECC_RESOURCE_MANAGER: Mutex<AteccResourceManager> =
        Mutex::new(AteccResourceManager { ref_counter: 0 });
}

impl AteccResourceManager {
    // Aquire an acceptance to create an ATECC instance
    fn acquire(&mut self) -> bool {
        if self.ref_counter == 0 {
            self.ref_counter = 1;
            true
        } else {
            false
        }
    }

    // Release a reservation of an ATECC instance
    fn release(&mut self) -> bool {
        if self.ref_counter == 1 {
            self.ref_counter = 0;
            true
        } else {
            false
        }
    }
}

/// An ATECC cryptochip context holder.
#[derive(Debug)]
pub struct AteccDevice {
    /// Interface configuration to be stored on a heap to avoid side effects of
    /// Rust and C interoperability
    iface_cfg_ptr: AtcaIfaceCfgPtrWrapper,
    /// A mutex to ensure a mutual access from different threads to an ATECC instance
    api_mutex: Mutex<()>,
    serial_number: [u8; ATCA_SERIAL_NUM_SIZE],
    aes_enabled: bool,
    slots: Vec<AtcaSlot>,
}

impl Default for AteccDevice {
    fn default() -> AteccDevice {
        AteccDevice {
            iface_cfg_ptr: AtcaIfaceCfgPtrWrapper {
                ptr: std::ptr::null_mut(),
            },
            api_mutex: Mutex::new(()),
            serial_number: [0; ATCA_SERIAL_NUM_SIZE],
            aes_enabled: false,
            slots: Vec::new(),
        }
    }
}

/// Implementation of CryptoAuth Library API Rust wrapper calls
impl AteccDevice {
    /// ATECC device instance constructor
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
        let mut atecc_device = AteccDevice::default();

        let iface_cfg_raw_ptr: *mut cryptoauthlib_sys::ATCAIfaceCfg = Box::into_raw(iface_cfg);
        // From now on iface_cfg is consumed and iface_cfg_ptr must be stored to be released
        // when no longer needed.

        let init_status = AtcaStatus::from(unsafe {
            let _guard = atecc_device
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_init(iface_cfg_raw_ptr)
        });

        atecc_device.iface_cfg_ptr = match init_status {
            AtcaStatus::AtcaSuccess => AtcaIfaceCfgPtrWrapper {
                ptr: iface_cfg_raw_ptr,
            },
            _ => {
                // Here init failed so no need to call a proper release
                ATECC_RESOURCE_MANAGER.lock().unwrap().release();
                unsafe { Box::from_raw(iface_cfg_raw_ptr) };
                return Err(init_status.to_string());
            }
        };

        // atecc_device.api_mutex is already initialized
        // from now on it is safe to call atecc_device.release();

        atecc_device.serial_number = {
            let mut number: [u8; ATCA_SERIAL_NUM_SIZE] = [0; ATCA_SERIAL_NUM_SIZE];
            let err = atecc_device.read_serial_number(&mut number);
            match err {
                AtcaStatus::AtcaSuccess => number,
                _ => {
                    atecc_device.release();
                    return Err(init_status.to_string());
                }
            }
        };

        atecc_device.aes_enabled = match atecc_device.get_aes_status_from_chip() {
            Ok(val) => val,
            Err(err) => {
                atecc_device.release();
                return Err(err.to_string());
            }
        };

        atecc_device.slots = {
            let mut atca_slots = Vec::new();
            let err = atecc_device.get_config_from_chip(&mut atca_slots);
            match err {
                AtcaStatus::AtcaSuccess => atca_slots,
                _ => {
                    atecc_device.release();
                    return Err(err.to_string());
                }
            }
        };

        Ok(atecc_device)
    } // AteccDevice::new()

    /// Request ATECC to compute a message hash (SHA256)
    pub fn sha(&self, message: Vec<u8>, digest: &mut Vec<u8>) -> AtcaStatus {
        let length: u16 = match u16::try_from(message.len()) {
            Ok(val) => val,
            Err(_) => return AtcaStatus::AtcaBadParam,
        };

        let digest_size: usize = ATCA_SHA2_256_DIGEST_SIZE;

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

    /// Request ATECC to generate a vector of random bytes
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

    /// Execute a Nonce command in pass-through mode to load one of the
    /// device's internal buffers with a fixed value.
    /// For the ATECC608A, available targets are TempKey (32 or 64 bytes), Message
    /// Digest Buffer (32 or 64 bytes), or the Alternate Key Buffer (32 bytes). For
    /// all other devices, only TempKey (32 bytes) is available.
    pub fn nonce(&self, target: NonceTarget, data: &[u8]) -> AtcaStatus {
        if (self.get_device_type() != AtcaDeviceType::ATECC608A)
            & (target != NonceTarget::TempKey)
            & (data.len() != ATCA_NONCE_SIZE)
        {
            return AtcaStatus::AtcaBadParam;
        }
        AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_nonce_load(target as u8, data.as_ptr(), data.len() as u16)
        })
    }

    /// Execute a Nonce command to generate a random nonce combining a host
    /// nonce and a device random number.
    pub fn nonce_rand(&self, host_nonce: &[u8], rand_out: &mut Vec<u8>) -> AtcaStatus {
        if host_nonce.len() != ATCA_NONCE_NUMIN_SIZE {
            return AtcaStatus::AtcaInvalidSize;
        }
        if rand_out.len() != ATCA_RANDOM_BUFFER_SIZE {
            rand_out.resize(ATCA_RANDOM_BUFFER_SIZE, 0);
        }
        AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_nonce_rand(host_nonce.as_ptr(), rand_out.as_mut_ptr())
        })
    }

    /// Request ATECC to generate a cryptographic key
    pub fn gen_key(&self, key_type: KeyType, slot_number: u8) -> AtcaStatus {
        if let Err(err) = self.check_input_parameters(key_type, slot_number) {
            return err;
        }

        let slot = match slot_number {
            ATCA_ATECC_SLOTS_COUNT => ATCA_ATECC_TEMPKEY_KEYID,
            _ => slot_number as u16,
        };

        match key_type {
            KeyType::P256EccKey => {
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
                if key.len() < ATCA_BLOCK_SIZE {
                    key.resize(ATCA_BLOCK_SIZE, 0);
                }
                if slot != ATCA_ATECC_TEMPKEY_KEYID {
                    const BLOCK_IDX: u8 = 0;
                    const OFFSET: u8 = 0;
                    match self.slots[slot_number as usize].config.write_config {
                        WriteConfig::Always => self.write_zone(
                            ATCA_ZONE_DATA,
                            slot,
                            BLOCK_IDX,
                            OFFSET,
                            &mut key,
                            ATCA_BLOCK_SIZE as u8,
                        ),
                        WriteConfig::Encrypt => AtcaStatus::AtcaUnimplemented, // TODO
                        _ => AtcaStatus::AtcaBadParam,
                    }
                } else {
                    AtcaStatus::AtcaUnimplemented // TODO
                }
            }
            _ => AtcaStatus::AtcaBadParam,
        }
    } // AteccDevice::gen_key()

    /// Request ATECC to import a cryptographic key
    pub fn import_key(&self, key_type: KeyType, key_data: &[u8], slot_number: u8) -> AtcaStatus {
        if let Err(err) = self.check_input_parameters(key_type, slot_number) {
            return err;
        }

        if ((key_type == KeyType::Aes) & (key_data.len() != ATCA_AES_KEY_SIZE))
            | ((key_type == KeyType::P256EccKey)
                & !((key_data.len() == ATCA_ATECC_PRIV_KEY_SIZE)
                    | (key_data.len() == ATCA_ATECC_PUB_KEY_SIZE)))
        {
            return AtcaStatus::AtcaInvalidSize;
        }

        let slot = match slot_number {
            ATCA_ATECC_SLOTS_COUNT => ATCA_ATECC_TEMPKEY_KEYID,
            _ => slot_number as u16,
        };

        match key_type {
            KeyType::P256EccKey => match key_data.len() {
                ATCA_ATECC_PUB_KEY_SIZE => {
                    if slot_number < ATCA_ATECC_MIN_SLOT_IDX_FOR_PUB_KEY {
                        return AtcaStatus::AtcaInvalidId;
                    }

                    return AtcaStatus::from(unsafe {
                        let _guard = self
                            .api_mutex
                            .lock()
                            .expect("Could not lock atcab API mutex");
                        cryptoauthlib_sys::atcab_write_pubkey(slot, key_data.as_ptr())
                    });
                }
                _ => {
                    let mut temp_key: Vec<u8> = vec![0; 4];
                    temp_key.extend_from_slice(key_data);
                    let mut write_key: [u8; 32] = [0; 32];
                    let mut write_key_ptr: *mut u8 = ptr::null_mut();
                    let write_key_id: u16 = self.slots[slot as usize].config.write_key as u16;
                    let mut num_in: [u8; ATCA_NONCE_NUMIN_SIZE] = [0; ATCA_NONCE_NUMIN_SIZE];

                    match self.data_zone_is_locked() {
                        Err(err) => return err,
                        Ok(val) => {
                            if val {
                                write_key_ptr = write_key.as_mut_ptr();
                                if self.slots[slot as usize].config.write_config
                                    != WriteConfig::Encrypt
                                {
                                    return AtcaStatus::AtcaBadParam;
                                }
                            }
                        }
                    };

                    return AtcaStatus::from(unsafe {
                        let _guard = self
                            .api_mutex
                            .lock()
                            .expect("Could not lock atcab API mutex");
                        cryptoauthlib_sys::atcab_priv_write(
                            slot,
                            temp_key.as_ptr(),
                            write_key_id,
                            write_key_ptr,
                            num_in.as_mut_ptr(),
                        )
                    });
                }
            },
            KeyType::Aes => {
                let mut temp_key: Vec<u8> = key_data.to_vec();
                if temp_key.len() != ATCA_BLOCK_SIZE {
                    temp_key.resize(ATCA_BLOCK_SIZE, 0);
                };
                if slot != ATCA_ATECC_TEMPKEY_KEYID {
                    const BLOCK_IDX: u8 = 0;
                    const OFFSET: u8 = 0;
                    let mut temp_key: Vec<u8> = key_data.to_vec();
                    if temp_key.len() != ATCA_BLOCK_SIZE {
                        temp_key.resize(ATCA_BLOCK_SIZE, 0);
                    }
                    match self.slots[slot as usize].config.write_config {
                        WriteConfig::Always => self.write_zone(
                            ATCA_ZONE_DATA,
                            slot,
                            BLOCK_IDX,
                            OFFSET,
                            &mut temp_key,
                            ATCA_BLOCK_SIZE as u8,
                        ),
                        WriteConfig::Encrypt => AtcaStatus::AtcaUnimplemented, // TODO
                        _ => AtcaStatus::AtcaBadParam,
                    }
                } else {
                    self.nonce(NonceTarget::TempKey, &temp_key)
                }
            }
            _ => AtcaStatus::AtcaBadParam,
        }
    } // AteccDevice::import_key()

    #[allow(deprecated)]
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

    /// Request ATECC to return own device type
    pub fn get_device_type(&self) -> AtcaDeviceType {
        AtcaDeviceType::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_get_device_type()
        })
    } // AteccDevice::get_device_type()

    /// Request ATECC to check if its configuration is locked.
    /// If true, a chip can be used for cryptographic operations
    pub fn configuration_is_locked(&self) -> Result<bool, AtcaStatus> {
        let mut is_locked: bool = false;
        let result = self.is_locked(ATCA_LOCK_ZONE_CONFIG, &mut is_locked);
        match result {
            AtcaStatus::AtcaSuccess => Ok(is_locked),
            _ => Err(result),
        }
    } // AteccDevice::configuration_is_locked()

    /// Request ATECC to check if its Data Zone is locked.
    /// If true, a chip can be used for cryptographic operations
    pub fn data_zone_is_locked(&self) -> Result<bool, AtcaStatus> {
        let mut is_locked: bool = false;
        let result = self.is_locked(ATCA_LOCK_ZONE_DATA, &mut is_locked);
        match result {
            AtcaStatus::AtcaSuccess => Ok(is_locked),
            _ => Err(result),
        }
    } // AteccDevice::configuration_is_locked()

    /// Request ATECC to read and return own configuration zone.
    /// Note: this function returns raw data, function get_config(..) implements a more
    /// structured return value.
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

    /// Compare internal config zone contents vs. config_data.
    /// Diagnostic function.
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

    /// Returns a structure containing configuration data read from ATECC
    /// during initialization of the AteccDevice object.
    pub fn get_config(&self, atca_slots: &mut Vec<AtcaSlot>) -> AtcaStatus {
        atca_slots.clear();
        for idx in 0..self.slots.len() {
            atca_slots.push(self.slots[idx])
        }
        AtcaStatus::AtcaSuccess
    } // AteccDevice::get_config()

    /// ATECC device instance destructor
    // Requests:
    // 1. Internal rust-cryptoauthlib resource manager to release structure instance
    // 2. The structure itself to free the heap allocacted data
    // 3. CryptoAuthLib to release the ATECC device
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

    // ---------------------------------------------------------------
    // Private functions
    // ---------------------------------------------------------------

    #[allow(dead_code)]
    fn info_cmd(&self, command: InfoCmdType) -> Result<Vec<u8>, AtcaStatus> {
        let mut out_data: Vec<u8> = vec![0; 4];
        let param2 = 0;
        match command {
            InfoCmdType::Revision => (),
            InfoCmdType::State => (),
            _ => return Err(AtcaStatus::AtcaUnimplemented),
        }
        let result = AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_info_base(command as u8, param2, out_data.as_mut_ptr())
        });
        match result {
            AtcaStatus::AtcaSuccess => Ok(out_data),
            _ => Err(result),
        }
    }

    fn check_input_parameters(&self, key_type: KeyType, slot_number: u8) -> Result<(), AtcaStatus> {
        if slot_number > ATCA_ATECC_SLOTS_COUNT {
            return Err(AtcaStatus::AtcaInvalidId);
        }
        // First condition is a special situation when
        // an AES key can be generated in an ATECC TempKey slot.
        if ((slot_number == ATCA_ATECC_SLOTS_COUNT) & (key_type != KeyType::Aes))
            | ((key_type == KeyType::Aes) & !self.aes_enabled)
        {
            return Err(AtcaStatus::AtcaBadParam);
        }
        Ok(())
    } // AteccDevice::check_input_parameters()

    fn is_locked(&self, zone: u8, is_locked: *mut bool) -> AtcaStatus {
        AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_is_locked(zone, is_locked)
        })
    } // AteccDevice::is_locked()

    fn get_aes_status_from_chip(&self) -> Result<bool, AtcaStatus> {
        const LEN: u8 = 4;
        const OFFSET: u8 = 3;
        const INDEX_OF_AES_BYTE: usize = 1;

        let mut data: Vec<u8> = vec![0; LEN as usize];
        let read_status = self.read_zone(ATCA_ZONE_CONFIG, 0, 0, OFFSET, &mut data, LEN);

        match read_status {
            AtcaStatus::AtcaSuccess => Ok((data[INDEX_OF_AES_BYTE] & 1) != 0),
            _ => Err(read_status),
        }
    } // AteccDevice::get_aes_status_from_chip()

    /// Request ATECC to read the configuration zone data and return it in a structure
    fn get_config_from_chip(&self, atca_slots: &mut Vec<AtcaSlot>) -> AtcaStatus {
        let mut config_data = Vec::new();
        let err = self.read_config_zone(&mut config_data);
        if AtcaStatus::AtcaSuccess != err {
            return err;
        }
        if config_data.len() != self.get_config_buffer_size() {
            return AtcaStatus::AtcaBadParam;
        }
        atca_slots.clear();
        atcab_get_config_from_config_zone(&config_data, atca_slots);
        AtcaStatus::AtcaSuccess
    } // AteccDevice::get_config_from_chip()

    fn get_config_buffer_size(&self) -> usize {
        let device_type = self.get_device_type();
        match device_type {
            AtcaDeviceType::ATECC508A | AtcaDeviceType::ATECC608A | AtcaDeviceType::ATECC108A => {
                ATCA_ATECC_CONFIG_BUFFER_SIZE
            }
            _ => ATCA_ATSHA_CONFIG_BUFFER_SIZE,
        }
    } // AteccDevice::get_config_buffer_size()

    fn read_serial_number(&self, number: &mut [u8; ATCA_SERIAL_NUM_SIZE]) -> AtcaStatus {
        AtcaStatus::from(unsafe {
            let _guard = self
                .api_mutex
                .lock()
                .expect("Could not lock atcab API mutex");
            cryptoauthlib_sys::atcab_read_serial_number(number.as_mut_ptr())
        })
    } // AteccDevice::read_serial_number()

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
    } // AteccDevice::write_zone()

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
}

// ---------------------------------------------------------------
// Free Auxiliary Functions
// ---------------------------------------------------------------

/// Setup an ATECC interface configuration (AtcaIfaceCfg)
/// based on a device type and I2C parameters.
/// This is a helper function, created for I2C exclusively.
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
