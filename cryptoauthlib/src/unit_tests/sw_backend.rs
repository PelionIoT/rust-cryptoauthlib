fn software_test_setup(default_result: String) -> super::AteccDevice {
    let iface_cfg = super::AtcaIfaceCfg::default();
    super::create_atecc_device(iface_cfg
        .set_iface_type("test-interface".to_owned())
        .set_devtype(default_result.to_owned())
    ).unwrap()
}

#[test]
fn random() {
    {
        let device = software_test_setup("device-success".to_owned());
        let mut rand_out = Vec::new();
        let device_random = device.random(&mut rand_out);

        assert_eq!(rand_out.len(), super::ATCA_RANDOM_BUFFER_SIZE);
        assert_eq!(device.release().to_string(), "AtcaSuccess");
        assert_eq!(device_random.to_string(), "AtcaSuccess");
    }
    {
        let device = software_test_setup("device-fail".to_owned());
        let mut rand_out = Vec::new();
        let device_random = device.random(&mut rand_out);

        assert_eq!(rand_out.len(), super::ATCA_RANDOM_BUFFER_SIZE);
        assert_ne!(device.release().to_string(), "AtcaSuccess");
        assert_ne!(device_random.to_string(), "AtcaSuccess");
    }
}
