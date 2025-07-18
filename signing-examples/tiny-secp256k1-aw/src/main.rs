/* // enable for benchs:
#![feature(test)]
extern crate test;
*/

use awint::{inlawi, Bits, InlAwi};

use noble_secp256k1::Curve;

fn main() {
    let start = std::time::Instant::now();

    let curve = Curve::secp256k1();

    println!("curve.G = {}", curve.G);

    let mut private_key =
        inlawi!(0x0000000000000000000000000000000000000000000000000000000000000002_u257);
    //inlawi!(0x0100000000000000000000000000000000000000000000000000000000000000_u512);
    println!("privat_key = {}", private_key);

    let public_key = curve.multiply_simple(&mut private_key);
    println!("public_key = {}", public_key);

    /*
    let mut private_key = BigNum::from_str_radix(
        "0000000000000000000000000000000000000000000000000000000000000001",
        //"0200000000000000000000000000000000000000000000000000000000000000",
        16,
    )
    .unwrap();

    let public_key = curve.multiply_simple(&mut private_key);

    println!("pub-of-01..00 = {}", public_key);

    let mut buf: [u8; 128] = [0; 128];
    public_key.as_hex(&mut buf);

    print!("pub-of-01..00 = ");
    for c in buf {
        print!("{}", c as char);
    }
    println!("");
    */

    println!("time elapsed = {:?}", start.elapsed());
}

#[cfg(test)]
mod tests {
    use super::*;

    use noble_secp256k1::as_hex;

    #[test]
    fn test_public_key() {
        let curve = Curve::secp256k1();
        let private_key = BigNum::from_str_radix(
            "0100000000000000000000000000000000000000000000000000000000000000",
            16,
        )
        .unwrap();
        let public_key = curve.multiply(private_key);

        assert_eq!(public_key.to_string(), "{ x: 8c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa, y: 40a30463a3305193378fedf31f7cc0eb7ae784f0451cb9459e71dc73cbef9482 }");

        /*
        assert_eq!(
            as_hex(public_key.x),
            "8c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa"
        );

        assert_eq!(
            as_hex(public_key.y),
            "40a30463a3305193378fedf31f7cc0eb7ae784f0451cb9459e71dc73cbef9482"
        );
        */
    }

    #[test]
    fn test_sig() {
        let curve = Curve::secp256k1();
        let private_key = BigNum::from_str_radix(
            "0100000000000000000000000000000000000000000000000000000000000000",
            16,
        )
        .unwrap();
        let m = BigNum::from_str_radix(
            "52fbb559a867af2f7613fd01b0a59e1363d3403830551c22f65622ccf93e7db3",
            16,
        )
        .unwrap();
        let k = BigNum::from_str_radix(
            "15d0e55777f4273726bbb347f77b09ad0af372b6e82d5d66b2b6c683cef55c42",
            16,
        )
        .unwrap();

        // sign(m,d,k)
        // (m)sg = 52fbb559a867af2f7613fd01b0a59e1363d3403830551c22f65622ccf93e7db3
        // (d)   = private_key
        // (k)   = 15d0e55777f4273726bbb347f77b09ad0af372b6e82d5d66b2b6c683cef55c42
        let sig = curve.sign_canonical(m, private_key, k);

        assert_eq!(sig.to_string(), "{ x: 71f498f5d9a05e83599a65e31febd4fb07451127031cf069c05c55ce586f248b, y: 247be206cff797fe03223673560c431cf2f94a02ebbb09fda8e4a7b03c2f353 }");

        /*
        assert_eq!(
            as_hex(sig.x),
            "71f498f5d9a05e83599a65e31febd4fb07451127031cf069c05c55ce586f248b"
        );

        assert_eq!(
            as_hex(sig.y),
            "247be206cff797fe03223673560c431cf2f94a02ebbb09fda8e4a7b03c2f353"
        );
        */
    }

    /*
    #[bench]
    fn bench_public_key(b: &mut test::Bencher) {
        let curve = Curve::secp256k1();
        let private_key = BigNum::from_str_radix(
            "0100000000000000000000000000000000000000000000000000000000000000",
            16,
        )
        .unwrap();

        b.iter(|| curve.multiply(private_key));
    }

    #[bench]
    fn bench_bignum_multiply_simple(b: &mut test::Bencher) {
        let p = BigNum::from_str_radix(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            16,
        )
        .unwrap();
        let x = BigNum::from_str_radix(
            "0100000000000000000000000000000000000000000000000000000000000000",
            16,
        )
        .unwrap();
        let y = BigNum::from_str_radix(
            "0100000000000000000000000000000000000000000000000000000000000000",
            16,
        )
        .unwrap();

        let p1 = noble_secp256k1::Point { x, y };

        b.iter(|| p1.multiply_DA(x, p));
    }
    */
}
