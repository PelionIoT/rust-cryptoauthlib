// Types
#[allow(unused_imports)]
use super::{AteccDevice, AtcaStatus, AtcaIfaceCfg, AtcaIface, AtcaIfaceI2c, KeyType, NonceTarget, SignEcdsaParam, VerifyEcdsaParam, 
    SignMode, VerifyMode, AtcaDeviceType, AtcaSlot, InfoCmdType};
// Constants
#[allow(unused_imports)]
use super::{ATCA_ZONE_CONFIG, ATCA_ATECC_SLOTS_COUNT, ATCA_NONCE_NUMIN_SIZE, ATCA_RANDOM_BUFFER_SIZE, ATCA_ATECC_PUB_KEY_SIZE, ATCA_SIG_SIZE,
    ATCA_ATECC_CONFIG_BUFFER_SIZE};
// Functions
#[allow(unused_imports)]
use super::create_atecc_device;
// Modules
#[allow(unused_imports)]
use super::hw_impl;

#[cfg(not(feature="software-backend"))]
mod hw_backend;
#[cfg(feature="software-backend")]
mod sw_backend;

// The placeholder for tests that can be easily switched between the backends.
