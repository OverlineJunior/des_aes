use crate::crypto::{aes, des};
use std::{fs, io, path::Path};

#[derive(Clone, PartialEq, Eq)]
pub enum Action {
    Encrypt,
    Decrypt,
}

#[derive(Clone, PartialEq, Eq)]
pub enum Algorithm {
    Des,
    Aes,
}

type Program = fn(Action, Algorithm, Vec<u8>, Option<Vec<u8>>) -> ();

pub fn run_cli(program: Program) -> io::Result<()> {
    cliclack::clear_screen()?;

    cliclack::intro("des_aes")?;

    let action = read_action()?;
    let algorithm = read_algorithm()?;
    let input = read_input()?;

    let decryption_key = match action {
        Action::Encrypt => None,
        Action::Decrypt => Some(read_decryption_key(algorithm.clone())?),
    };

    let (pending_msg, completed_msg) = match action {
        Action::Encrypt => ("Criptografando...", "Arquivo criptografado!"),
        Action::Decrypt => ("Descriptografando...", "Arquivo descriptografado!"),
    };

    let spinner = cliclack::spinner();
    spinner.start(pending_msg);

    program(action, algorithm, input, decryption_key);

    spinner.stop("");

    cliclack::outro(completed_msg)?;

    Ok(())
}

fn read_action() -> io::Result<Action> {
    let action = cliclack::select("O que deseja fazer?")
        .item(Action::Encrypt, "Criptografar um arquivo", "")
        .item(Action::Decrypt, "Descriptografar um arquivo", "")
        .interact()?;

    Ok(action)
}

fn read_algorithm() -> io::Result<Algorithm> {
    let algorithm = cliclack::select("Qual algoritmo deseja usar?")
        .item(Algorithm::Des, "DES", "Data Encryption Standard")
        .item(Algorithm::Aes, "AES", "Advanced Encryption Standard")
        .interact()?;

    Ok(algorithm)
}

fn read_input() -> io::Result<Vec<u8>> {
    let path: String = cliclack::input("Aonde está o arquivo?")
        .placeholder("Caminho do arquivo a ser criptografado")
        .validate(|input: &String| {
            let path = Path::new(input);

            if !path.exists() {
                Err("Arquivo não encontrado")
            } else if !path.is_file() {
                Err("Caminho não leva para um arquivo")
            } else {
                Ok(())
            }
        })
        .interact()?;

    fs::read(&path)
}

fn read_decryption_key(algorithm: Algorithm) -> io::Result<Vec<u8>> {
    let placeholder = format!(
        "Chave de {} caracteres",
        match algorithm {
            Algorithm::Des => des::KEY_BYTES,
            Algorithm::Aes => aes::KEY_BYTES,
        },
    );

    let key: String = cliclack::input("Qual a chave de descriptografia?")
        .placeholder(&placeholder)
        .validate(move |input: &String| {
            let valid_len = match algorithm {
                Algorithm::Des => des::KEY_BYTES,
                Algorithm::Aes => aes::KEY_BYTES,
            };

            if input.len() != valid_len {
                Err(format!(
                    "A chave deve ter exatamente {} caracteres",
                    valid_len
                ))
            } else {
                Ok(())
            }
        })
        .interact()?;

    Ok(key.as_bytes().to_vec())
}
