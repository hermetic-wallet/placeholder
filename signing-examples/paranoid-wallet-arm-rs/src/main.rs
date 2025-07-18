//! Prints "Hello, world!" on the host console using semihosting

#![no_main]
#![no_std]

use panic_halt as _;

use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};

use noble_secp256k1::awint::{inlawi, Bits, InlAwi};
use noble_secp256k1::Curve;

/*
fn print_hex_str_arr(tag: &str, arr: &[u8]) {
    hprint!("{} = ", tag).unwrap();
    for x in arr {
        hprint!("{}", *x as char).unwrap();
    }
    hprintln!("").unwrap();
}
*/

use cortex_m_semihosting::hprint;
fn print_hex_arr(tag: &str, arr: &[u8]) {
    hprint!("{} = ", tag).unwrap();
    for x in arr.iter().rev() {
        hprint!("{:02x}", *x).unwrap();
    }
    hprintln!("").unwrap();
}

#[entry]
fn main() -> ! {
    hprintln!("Hello, world!").unwrap();

    let curve = Curve::secp256k1();

    let mut private_key =
        inlawi!(0x0000000000000000000000000000000000000000000000000000000000000002_u512);
    let _public_key = curve.multiply_simple(&mut private_key);

    let mut buf: [u8; 32] = [0; 32];
    _public_key.x.to_u8_slice(&mut buf);
    print_hex_arr("x:", &buf);
    _public_key.y.to_u8_slice(&mut buf);
    print_hex_arr("y:", &buf);

    // exit QEMU
    // NOTE do not run this on hardware; it can corrupt OpenOCD state
    debug::exit(debug::EXIT_SUCCESS);

    loop {}
}
