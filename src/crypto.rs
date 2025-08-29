use ghash::universal_hash::{KeyInit, UniversalHash};

pub async fn hkdf_sha256(ikm: &[u8], salt: &[u8], shared_info: &[u8], output_len: usize) -> alloc::vec::Vec<u8> {
    let prk = hmac_sha256(salt, ikm).await;
    let n = (output_len + 31) / 32;
    let mut t = alloc::vec::Vec::with_capacity(n * 32);
    let mut t_n = None;
    for i in 0..n {
        let mut input = alloc::vec::Vec::with_capacity(32 + shared_info.len() + 1);
        if let Some(t_n) = &t_n {
            input.extend(t_n);
        }
        input.extend(shared_info);
        input.push((i + 1) as u8);
        let nt_n = hmac_sha256(&prk, &input).await;
        t.extend(nt_n);
        t_n = Some(nt_n);
    }
    t.truncate(output_len);
    t
}

pub async fn x963_kdf_sha256(shared_secret: &[u8], shared_info: &[u8], output_len: usize) -> alloc::vec::Vec<u8> {
    let n = (output_len + 31) / 32;
    let mut t = alloc::vec::Vec::with_capacity(n * 32);
    for i in 0..n {
        let mut input = alloc::vec::Vec::with_capacity(shared_secret.len() + 4 + shared_info.len());
        input.extend(shared_secret);
        input.extend(((i + 1) as u32).to_be_bytes());
        input.extend(shared_info);
        t.extend(sha256(&input).await);
    }
    t.truncate(output_len);
    t
}

pub async fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5Cu8; 64];
    let key = if key.len() > 64 {
        &sha256(key).await
    } else {
        key
    };
    for (i, v) in key.iter().enumerate() {
        ipad[i] = ipad[i] ^ *v;
        opad[i] = opad[i] ^ *v;
    }
    let mut h1_data = alloc::vec::Vec::with_capacity(64 + data.len());
    h1_data.extend(ipad);
    h1_data.extend(data);
    let h1 = sha256(&h1_data).await;
    let mut h2_data = alloc::vec::Vec::with_capacity(64 + 32);
    h2_data.extend(opad);
    h2_data.extend(h1);
    sha256(&h2_data).await
}

pub async fn sha256(mut data: &[u8]) -> [u8; 32] {
    let mut hash_device = crate::SHA.lock().await;
    let mut hasher = unsafe { hash_device.assume_init_mut() }.start::<esp_hal::sha::Sha256>();
    while !data.is_empty() {
        data = hasher.update(&data).unwrap();
    }
    let mut digest = [0u8; 32];
    hasher.finish(&mut digest).unwrap();
    digest
}

pub async fn aes_128_ctr(data: &mut [u8], key: [u8; 16], iv: [u8; 12]) {
    let mut aes_device = crate::AES.lock().await;
    for (ctr, chunk) in data.chunks_mut(16).enumerate() {
        let ctr = ctr as u32;
        let mut ctr_block = [0u8; 16];
        for (i, v) in iv.iter().enumerate() {
            ctr_block[i] = *v;
        }
        for (i, v) in ctr.to_be_bytes().iter().enumerate() {
            ctr_block[12 + i] = *v;
        }
        unsafe { aes_device.assume_init_mut() }.process(&mut ctr_block, esp_hal::aes::Mode::Encryption128, key);
        for (i, v) in chunk.iter_mut().enumerate() {
            *v = ctr_block[i] ^ *v;
        }
    }
}

pub async fn aes_256_gcm_decrypt(data: &mut [u8], key: [u8; 32], iv: &[u8], additional_data: &[u8]) -> bool {
    if data.len() < 16 {
        return false;
    }
    let tag_pos = data.len() - 16;
    let (msg, tag) = data.split_at_mut(tag_pos);
    let tag: [u8; 16] = tag.try_into().unwrap();

    let mut aes_device = crate::AES.lock().await;
    let mut hash_key = [0u8; 16];
    unsafe { aes_device.assume_init_mut() }.process(&mut hash_key, esp_hal::aes::Mode::Encryption256, key);

    let mut j0 = aes_gcm_init_counter(hash_key, iv);
    let mut ctr = j0;
    let mut s_ghash = ghash::GHash::new((&hash_key).into());
    s_ghash.update_padded(&additional_data);
    s_ghash.update_padded(&msg);
    let mut s_block = ghash::Block::default();
    s_block[0..8].copy_from_slice(&((additional_data.len() * 8) as u64).to_be_bytes());
    s_block[8..16].copy_from_slice(&((msg.len() * 8) as u64).to_be_bytes());
    s_ghash.update(&[s_block]);
    let mut s: [u8; 16] = s_ghash.finalize().try_into().unwrap();

    unsafe { aes_device.assume_init_mut() }.process(&mut j0, esp_hal::aes::Mode::Encryption256, key);
    for (i, v) in s.iter_mut().enumerate() {
        *v = j0[i] ^ *v;
    }

    if s != tag {
        return false;
    }

    for chunk in msg.chunks_mut(16) {
        aes_gcm_inc_counter(&mut ctr);
        let mut k = ctr;
        unsafe { aes_device.assume_init_mut() }.process(&mut k, esp_hal::aes::Mode::Encryption256, key);
        for (i, v) in chunk.iter_mut().enumerate() {
            *v = k[i] ^ *v;
        }
    }

    true
}

fn aes_gcm_init_counter(hash_key: [u8; 16], iv: &[u8]) -> [u8; 16] {
    if iv.len() == 12 {
        let mut block = ghash::Block::default();
        block[..12].copy_from_slice(iv);
        block[15] = 1;
        block.try_into().unwrap()
    } else {
        let mut ghash = ghash::GHash::new((&hash_key).into());
        ghash.update_padded(&iv);

        let mut block = ghash::Block::default();
        let iv_bits = (iv.len() * 8) as u64;
        block[8..].copy_from_slice(&iv_bits.to_be_bytes());
        ghash.update(&[block]);
        ghash.finalize().try_into().unwrap()
    }
}

fn aes_gcm_inc_counter(ctr: &mut [u8; 16]) {
    let mut j = u32::from_be_bytes((&ctr[12..16]).try_into().unwrap());
    j += 1;
    for (i, v) in j.to_be_bytes().iter().enumerate() {
        ctr[12 + i] = *v;
    }
}