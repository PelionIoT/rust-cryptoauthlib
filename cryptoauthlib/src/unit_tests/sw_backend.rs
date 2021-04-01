pub fn test_setup(default_result: String) -> super::AteccDevice {
    let iface_cfg = super::AtcaIfaceCfg::default();
    super::setup_atecc_device(
        iface_cfg
            .set_iface_type("test-interface".to_owned())
            .set_devtype(default_result),
    )
    .unwrap()
}
