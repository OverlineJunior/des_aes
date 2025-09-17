use easydes::easydes;

use crate::crypto::random_utf8_key;

pub const KEY_BYTES: usize = 8;
const IV_BYTES: usize = 8;

pub fn encrypt(text: &[u8]) -> (Vec<u8>, [u8; KEY_BYTES]) {
    let key: [u8; KEY_BYTES] = random_utf8_key(KEY_BYTES).try_into().unwrap();

    let mut iv = [0u8; IV_BYTES];
    rand::fill(&mut iv);

    let encrypted = easydes::des_cbc(&key, &iv, &mut text.to_vec(), easydes::Des::Encrypt);

    let mut cipher = iv.to_vec();
    cipher.extend(encrypted);
    (cipher, key)
}

pub fn decrypt(cipher: &[u8], key: &[u8; KEY_BYTES]) -> String {
    let (iv, cipher) = cipher.split_at(IV_BYTES);

	// EasyDES seems to add null bytes, which makes the output hard to read, so we filter them out.
    let decrypted = easydes::des_cbc(key, iv, &mut cipher.to_vec(), easydes::Des::Decrypt)
        .into_iter()
        .filter(|&b| b != 0x00)
		.collect();

    String::from_utf8(decrypted).unwrap()
}
