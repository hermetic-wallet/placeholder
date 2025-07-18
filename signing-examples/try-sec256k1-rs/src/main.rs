use hex_literal::hex;
use secp256k1::hashes::sha256;
use secp256k1::{Message, PublicKey, SecretKey, SECP256K1};

fn main() {
    let secret_key = SecretKey::from_slice(&hex!(
        "0100000000000000000000000000000000000000000000000000000000000000"
    ))
    .unwrap();

    let public_key = PublicKey::from_secret_key(&SECP256K1, &secret_key);

    //let message = Message::from_hashed_data::<sha256::Hash>("Hello World!".as_bytes());
    let message = Message::from_slice(&hex!(
        "52fbb559a867af2f7613fd01b0a59e1363d3403830551c22f65622ccf93e7db3"
    ))
    .unwrap();
    println!("message = {message}");

    let sig = secret_key.sign_ecdsa(message);
    println!("signature = {sig}");

    assert!(sig.verify(&message, &public_key).is_ok());
}
