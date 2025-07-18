#![no_std]
#![no_main]

use panic_halt as _;

use arduino_hal::prelude::*;

use core::fmt::Debug;
use ufmt::uWrite;

/*
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // disable interrupts - firmware has panicked so no ISRs should continue running
    avr_device::interrupt::disable();

    // get the peripherals so we can access serial and the LED.
    //
    // SAFETY: Because main() already has references to the peripherals this is an unsafe
    // operation - but because no other code can run after the panic handler was called,
    // we know it is okay.
    let dp = unsafe { arduino_hal::Peripherals::steal() };
    let pins = arduino_hal::pins!(dp);
    let mut serial = arduino_hal::default_serial!(dp, pins, 57600);

    // Print out panic location
    //ufmt::uwriteln!(&mut serial, "Firmware panic!\r").void_unwrap();
    if let Some(loc) = info.location() {
        ufmt::uwriteln!(
            &mut serial,
            "  At {}:{}:{}\r",
            loc.file(),
            loc.line(),
            loc.column(),
        )
        .void_unwrap();
    }

    // Blink LED rapidly
    let mut led = pins.d13.into_output();
    loop {
        led.toggle();
        arduino_hal::delay_ms(100);
    }
}
*/

/*
*/
fn print_hex_arr<S>(tag: &str, serial: &mut S, arr: &[u8])
where
    S: uWrite,
    <S as uWrite>::Error: Debug,
{
    ufmt::uwrite!(serial, "{} = ", tag).unwrap();
    for e in arr.iter() {
        ufmt::uwrite!(serial, "{:02x}", *e).unwrap();
    }
    ufmt::uwrite!(serial, "\r\n").unwrap();
}

fn print_hex_arr_rev<S>(tag: &str, serial: &mut S, arr: &[u8])
where
    S: uWrite,
    <S as uWrite>::Error: Debug,
{
    ufmt::uwrite!(serial, "{} = ", tag).unwrap();
    for e in arr.iter().rev() {
        ufmt::uwrite!(serial, "{:02x}", *e).unwrap();
    }
    ufmt::uwrite!(serial, "\r\n").unwrap();
}

#[arduino_hal::entry]
fn main() -> ! {
    let dp = arduino_hal::Peripherals::take().unwrap();
    let pins = arduino_hal::pins!(dp);
    let mut serial = arduino_hal::default_serial!(dp, pins, 57600);

    /*
     */
    // WORKING
    use noble_secp256k1::awint::{cc, inlawi, inlawi_ty, Bits, InlAwi};
    use noble_secp256k1::{BigNum, Curve};

    {
        let h = hmac_sha256::HMAC::mac(b"hello", b"key");
        print_hex_arr(" mac", &mut serial, &h);
        let h = hmac_sha256::Hash::hash(b"hello");
        print_hex_arr("hash", &mut serial, &h);
        //}
        //{
        let h = hmac_sha256::HMAC::mac(b"hello", b"key");
        print_hex_arr(" mac", &mut serial, &h);
        //let h = hmac_sha256::Hash::hash(b"hello");
        //print_hex_arr("hash", &mut serial, &h);
    }

    let mut private_key = inlawi!(0x02_u257);
    let curve = Curve::secp256k1();
    //
    // 0x01
    // 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    // 483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    //
    // 0x02
    // c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
    // 1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a
    //
    let public_key = curve.multiply_simple(&mut private_key);

    let mut buf = [0; 32];
    public_key.x.to_u8_slice(&mut buf);
    print_hex_arr_rev("x", &mut serial, &buf);
    public_key.y.to_u8_slice(&mut buf);
    print_hex_arr_rev("y", &mut serial, &buf);

    /*
    use lhash::sha256;
    use lhash::Sha256;

    let mut hasher = Sha256::new();
    hasher.update(b"hello");
    let res = hasher.result();
    */

    /*
    use hmac::Hmac;
    use hmac::Mac;
    use sha2::Digest;
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(b"key").unwrap();
    mac.update(b"hello");
    let result = mac.finalize();

    // create a Sha256 object
    let mut hasher = Sha256::new();
    // write input message
    hasher.update(b"hello");
    // read hash digest and consume hasher
    let result = hasher.finalize();
    */

    /*

    let mut pad = inlawi!(0u512);
    let mut x1_copy = inlawi!(x1; ..512).unwrap();
    x1_copy.mul_assign(&x1, &mut pad).unwrap();
    // just renaming, this is zero cost if we don't use x1_copy later
    let x1_squared = x1_copy;
    let mut int0 = inlawi!(0u512);
    Bits::udivide(&mut pad, &mut int0, &x1_squared, &p).unwrap();
    let mut buf: [u8; 32] = [0; 32];
    int0.to_u8_slice(&mut buf);
    print_hex_arr("int0:", &mut serial, &buf);
    */

    //ufmt::uwriteln!(&mut serial, "Hello from Arduino!\r").void_unwrap();

    loop {
        // Read a byte from the serial connection
        //let b = nb::block!(serial.read()).void_unwrap();

        // Answer
        //ufmt::uwriteln!(&mut serial, "Got {}!\r", b).void_unwrap();
    }
}
