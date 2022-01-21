use super::{AtcaDeviceType, AtcaIface, AtcaIfaceCfg, AtcaIfaceI2c, AtcaIfaceType};
use log::error;

impl Default for AtcaIfaceCfg {
    fn default() -> AtcaIfaceCfg {
        AtcaIfaceCfg {
            iface_type: AtcaIfaceType::AtcaUnknownIface,
            devtype: AtcaDeviceType::AtcaDevUnknown,
            iface: None,
            wake_delay: 0u16,
            rx_retries: 0i32,
        }
    }
}

impl Default for AtcaIface {
    fn default() -> AtcaIface {
        AtcaIface {
            atcai2c: AtcaIfaceI2c::default(),
        }
    }
}

impl AtcaIfaceCfg {
    pub fn set_iface_type(mut self, iface_type: String) -> AtcaIfaceCfg {
        self.iface_type = match iface_type.as_str() {
            "i2c" => AtcaIfaceType::AtcaI2cIface,
            "test-interface" => AtcaIfaceType::AtcaTestIface,
            _ => {
                error!("Unsupported ATCA interface type {}", iface_type);
                AtcaIfaceType::AtcaUnknownIface
            }
        };
        self
    }
    pub fn set_devtype(mut self, devtype: String) -> AtcaIfaceCfg {
        self.devtype = match devtype.as_str() {
            "atecc608a" => AtcaDeviceType::ATECC608A,
            "atecc508a" => AtcaDeviceType::ATECC508A,
            "always-fail" => AtcaDeviceType::AtcaTestDevFail,
            "always-success" => AtcaDeviceType::AtcaTestDevSuccess,
            "unimplemented-fail" => AtcaDeviceType::AtcaTestDevFailUnimplemented,
            _ => {
                error!("Unsupported ATCA device type {}", devtype);
                AtcaDeviceType::AtcaDevUnknown
            }
        };
        self
    }
    pub fn set_wake_delay(mut self, wake_delay: u16) -> AtcaIfaceCfg {
        self.wake_delay = wake_delay;
        self
    }
    pub fn set_rx_retries(mut self, rx_retries: i32) -> AtcaIfaceCfg {
        self.rx_retries = rx_retries;
        self
    }
    pub fn set_iface(mut self, iface: AtcaIface) -> AtcaIfaceCfg {
        self.iface = Some(iface);
        self
    }
}

impl AtcaIface {
    pub fn set_atcai2c(mut self, atcai2c: AtcaIfaceI2c) -> AtcaIface {
        self.atcai2c = atcai2c;
        self
    }
}

impl AtcaIfaceI2c {
    pub fn set_slave_address(mut self, slave_address: u8) -> AtcaIfaceI2c {
        self.slave_address = slave_address;
        self
    }
    pub fn set_bus(mut self, bus: u8) -> AtcaIfaceI2c {
        self.bus = bus;
        self
    }
    pub fn set_baud(mut self, baud: u32) -> AtcaIfaceI2c {
        self.baud = baud;
        self
    }
}
