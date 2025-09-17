use soft_aes::aes::aes_enc_cbc;

use crate::crypto::random_utf8_key;

pub const KEY_BYTES: usize = 32;
const IV_BYTES: usize = 16;
const PADDING: Option<&str> = Some("PKCS7");

pub fn encrypt(text: &[u8]) -> (Vec<u8>, [u8; KEY_BYTES]) {
    let key: [u8; KEY_BYTES] = random_utf8_key(KEY_BYTES).try_into().unwrap();

    let mut iv = [0u8; IV_BYTES];
    rand::fill(&mut iv);

    let encrypted = aes_enc_cbc(text, &key, &iv, PADDING).unwrap();

    let mut cipher = iv.to_vec();
    cipher.extend(encrypted);
    (cipher, key)
}

pub fn decrypt(cipher: &[u8], key: &[u8; KEY_BYTES]) -> String {
    let (iv, cipher) = cipher.split_at(IV_BYTES);

    let decrypted =
        soft_aes::aes::aes_dec_cbc(cipher, key, iv.try_into().unwrap(), PADDING).unwrap();

    String::from_utf8(decrypted).unwrap()
}
