use rand_chacha::rand_core::RngCore;
use crate::vas::google::data;

#[derive(Debug)]
pub struct Session {
    reader_nonce: [u8; 32],
    device_nonce: [u8; 32],
    config: alloc::sync::Arc<super::TerminalConfig>,
    reader_ephemeral_key: crate::ecc::PrivateKey,
    kdf_info: Option<alloc::vec::Vec<u8>>,
}

impl Session {
    pub async fn new(
        device_nonce: [u8; 32],
        reader_ephemeral_key: crate::ecc::PrivateKey,
        config: alloc::sync::Arc<super::TerminalConfig>
    ) -> Self {
        let mut r_n = [0u8; 32];
        let mut r = crate::RAND.lock().await;
        unsafe { r.assume_init_mut() }.fill_bytes(&mut r_n);
        drop(r);

        Self {
            reader_nonce: r_n,
            device_nonce,
            config,
            reader_ephemeral_key,
            kdf_info: None,
        }
    }

    pub async fn generate_crypto_params(&mut self) -> data::CryptoParams {
        let mut tbs_data = alloc::vec::Vec::new();
        tbs_data.extend_from_slice(&self.reader_nonce);
        tbs_data.extend_from_slice(&self.device_nonce);
        tbs_data.extend_from_slice(&self.config.collector_id.to_be_bytes());
        tbs_data.extend(self.reader_ephemeral_key.public_key().public_compressed_point());
        let mut hash_device = crate::SHA.lock().await;
        let mut hasher = unsafe { hash_device.assume_init_mut().start::<esp_hal::sha::Sha256>() };
        let mut tbs_data_ref = tbs_data.as_slice();
        while !tbs_data_ref.is_empty() {
            tbs_data_ref = hasher.update(&tbs_data_ref).unwrap();
        }
        let mut tbs_digest = [0u8; 32];
        hasher.finish(&mut tbs_digest).unwrap();
        drop(hash_device);
        let nsc_signature = self.config.private_key.sign(&tbs_digest);
        let mut kdf_info = alloc::vec::Vec::new();
        kdf_info.extend_from_slice(&tbs_data);
        kdf_info.extend_from_slice(&nsc_signature);
        self.kdf_info = Some(kdf_info);
        data::CryptoParams {
            reader_nonce: self.reader_nonce,
            auth_flag: 1,
            reader_ephemeral_public_key: self.reader_ephemeral_key.public_key(),
            key_version: self.config.key_version,
            collector_id: self.config.collector_id,
            reader_signature: crate::ecc::signature_to_der(&nsc_signature)
        }
    }

    pub fn shared_secret(&self, peer_key: &crate::ecc::PublicKey) -> [u8; 32] {
        self.reader_ephemeral_key.shared_secret(peer_key)
    }

    pub fn kdf_info(&self) -> &[u8] {
        self.kdf_info.as_deref().unwrap_or(&[])
    }
}