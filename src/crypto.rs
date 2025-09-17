use rand::Rng;

pub mod aes;
pub mod des;

// Keys are UTF-8 only so it's easier to copy/paste them.
fn random_utf8_key(bytes: usize) -> Vec<u8> {
	let mut key = Vec::new();
	let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
					abcdefghijklmnopqrstuvwxyz\
					0123456789";
	let mut rng = rand::rng();

	for _ in 0..bytes {
		key.push(charset[rng.random_range(0..charset.len())]);
	}

	key
}
