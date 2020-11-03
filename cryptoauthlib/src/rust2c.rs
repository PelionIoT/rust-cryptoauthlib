use cryptoauthlib_sys;

pub fn r2c_atca_iface_cfg(rust_iface_cfg: super::AtcaIfaceCfg) -> Option<cryptoauthlib_sys::ATCAIfaceCfg> {
    let atca_iface: cryptoauthlib_sys::ATCAIfaceCfg__bindgen_ty_1 = match rust_iface_cfg.iface_type {
        super::AtcaIfaceType::AtcaI2cIface =>  
                cryptoauthlib_sys::ATCAIfaceCfg__bindgen_ty_1 {
                    atcai2c: cryptoauthlib_sys::ATCAIfaceCfg__bindgen_ty_1__bindgen_ty_1 {
                        slave_address: unsafe {rust_iface_cfg.iface.atcai2c.slave_address },
                        bus: unsafe {rust_iface_cfg.iface.atcai2c.bus },
                        baud: unsafe {rust_iface_cfg.iface.atcai2c.baud },
                    },
                },
        _ => return None,
        }; // match rust_iface_cfg.iface_type
    return Some( 
        cryptoauthlib_sys::ATCAIfaceCfg {
            iface_type: r2c_atcaiface_type(rust_iface_cfg.iface_type),
            devtype: r2c_atcaiface_devtype(rust_iface_cfg.devtype),
            __bindgen_anon_1: atca_iface,
            wake_delay: rust_iface_cfg.wake_delay,
            rx_retries: rust_iface_cfg.rx_retries,
            cfg_data: std::ptr::null_mut(),
        } 
    ); // return Some
} // pub fn r2c_atca_iface_cfg

fn r2c_atcaiface_type(rust_iface_type: super::AtcaIfaceType) -> cryptoauthlib_sys::ATCAIfaceType {
    return match rust_iface_type {
        super::AtcaIfaceType::AtcaI2cIface => cryptoauthlib_sys::ATCAIfaceType_ATCA_I2C_IFACE,
        super::AtcaIfaceType::AtcaSwiIface => cryptoauthlib_sys::ATCAIfaceType_ATCA_SWI_IFACE,
        super::AtcaIfaceType::AtcaUartIface => cryptoauthlib_sys::ATCAIfaceType_ATCA_UART_IFACE,
        super::AtcaIfaceType::AtcaSpiIface => cryptoauthlib_sys::ATCAIfaceType_ATCA_SPI_IFACE,
        super::AtcaIfaceType::AtcaHidIface => cryptoauthlib_sys::ATCAIfaceType_ATCA_HID_IFACE,
        super::AtcaIfaceType::AtcaCustomIface => cryptoauthlib_sys::ATCAIfaceType_ATCA_CUSTOM_IFACE,
        _ => cryptoauthlib_sys::ATCAIfaceType_ATCA_UNKNOWN_IFACE,
    }
}

fn r2c_atcaiface_devtype(rust_iface_devtype: super::AtcaDeviceType) -> cryptoauthlib_sys::ATCADeviceType {
    return match rust_iface_devtype {
        super::AtcaDeviceType::ATSHA204A => cryptoauthlib_sys::ATCADeviceType_ATSHA204A,
        super::AtcaDeviceType::ATECC108A => cryptoauthlib_sys::ATCADeviceType_ATECC108A,
        super::AtcaDeviceType::ATECC508A => cryptoauthlib_sys::ATCADeviceType_ATECC508A,
        super::AtcaDeviceType::ATECC608A => cryptoauthlib_sys::ATCADeviceType_ATECC608A,
        super::AtcaDeviceType::ATSHA206A => cryptoauthlib_sys::ATCADeviceType_ATSHA206A,
        _ => cryptoauthlib_sys::ATCADeviceType_ATCA_DEV_UNKNOWN,
    }
}
