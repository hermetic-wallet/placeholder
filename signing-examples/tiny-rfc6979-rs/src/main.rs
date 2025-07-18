fn print_hex_arr(tag: &str, arr: &[u8]) {
    print!("{} = ", tag);
    for e in arr {
        print!("{:02x}", e);
    }
    println!("");
}

fn main() {
    let h = hmac_sha256::HMAC::mac(b"hello", b"key");
    print_hex_arr(" mac", &h);
    let h = hmac_sha256::Hash::hash(b"hello");
    print_hex_arr("hash", &h);
}
