
pub async fn persist_connection_config() {
    let fs = crate::FS.0.lock().await;
    if let Some(config) = crate::CONNECTION_CONFIG.try_get() {
        let data = rasn::uper::encode(&config).unwrap();
        unsafe { fs.assume_init_ref() }.write( littlefs2::path!("/config"), &data).unwrap();
    } else {
        if unsafe { fs.assume_init_ref() }.exists( littlefs2::path!("/config")) {
            unsafe { fs.assume_init_ref() }.remove(littlefs2::path!("/config")).unwrap();
        }
    }
}

pub async fn get_connection_config() -> Option<crate::asn::tappybara_config::ConnectionConfig> {
    let fs = crate::FS.0.lock().await;
    if unsafe { fs.assume_init_ref() }.exists( littlefs2::path!("/config")) {
        if let Ok(data) = unsafe { fs.assume_init_ref() }.read::<256>( littlefs2::path!("/config")) {
            if let Ok(config) = rasn::uper::decode(&data) {
                return Some(config);
            }
        }
    }
    None
}

pub fn default_connection_config() -> crate::asn::tappybara_config::ConnectionConfig {
    crate::asn::tappybara_config::ConnectionConfig {
        networks: vec![],
        server_public_key_identity: rasn::types::OctetString::from_static(&[0u8; 32]),
    }
}

pub async fn get_identity() -> crate::ecc::PrivateKey {
    let fs = crate::FS.0.lock().await;
    if unsafe { fs.assume_init_ref() }.exists( littlefs2::path!("/identity")) {
        if let Ok(data) = unsafe { fs.assume_init_ref() }.read::<256>( littlefs2::path!("/identity")) {
            if let Ok(identity) = rasn::uper::decode::<crate::asn::tappybara_config::Identity>(&data) {
                return crate::ecc::PrivateKey::from_bytes(identity.private_key.as_ref().try_into().unwrap());
            }
        }
    }

    info!("Generating long term identity");
    let private_key = crate::ecc::PrivateKey::new();
    let identity = crate::asn::tappybara_config::Identity {
        private_key: rasn::types::OctetString::from(private_key.private_bytes()),
    };
    let identity_bytes = rasn::uper::encode(&identity).unwrap();
    unsafe { fs.assume_init_ref() }.write( littlefs2::path!("/identity"), &identity_bytes).unwrap();
    private_key
}