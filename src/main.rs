mod cli;
mod crypto;

use std::io;
use crate::cli::{Action, Algorithm, run_cli};
use crypto::{des, aes};

fn run_algorithms(action: Action, algorithm: Algorithm, input: Vec<u8>, decryption_key: Option<Vec<u8>>) {
    match (action, algorithm) {
        (Action::Encrypt, Algorithm::Des) => {
            let (cipher, key) = des::encrypt(&input);
            std::fs::write("criptografado.bin", &cipher).unwrap();
            std::fs::write("chave.txt", key).unwrap();
        }
        (Action::Decrypt, Algorithm::Des) => {
            let cipher = std::fs::read("criptografado.bin").unwrap();
            let key_bytes = decryption_key.unwrap();
            let key: [u8; des::KEY_BYTES] = key_bytes.try_into().unwrap();
            let decrypted = des::decrypt(&cipher, &key);
            std::fs::write("descriptografado.txt", decrypted).unwrap();
        }
        (Action::Encrypt, Algorithm::Aes) => {
            let (cipher, key) = aes::encrypt(&input);
            std::fs::write("criptografado.bin", &cipher).unwrap();
            std::fs::write("chave.txt", key).unwrap();
        }
        (Action::Decrypt, Algorithm::Aes) => {
            let cipher = std::fs::read("criptografado.bin").unwrap();
            let key_bytes = decryption_key.unwrap();
            let key: [u8; aes::KEY_BYTES] = key_bytes.try_into().unwrap();
            let decrypted = aes::decrypt(&cipher, &key);
            std::fs::write("descriptografado.txt", decrypted).unwrap();
        }
    }
}

fn main() -> io::Result<()> {
    run_cli(run_algorithms)
}
