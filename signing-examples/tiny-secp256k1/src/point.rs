use fixed_bigint::num_integer::Integer;
use fixed_bigint::num_traits::{FromPrimitive, One, Zero};

use crate::BigNum;

#[derive(Clone)]
pub struct Point {
    pub x: BigNum,
    pub y: BigNum,
}

#[allow(dead_code)]
impl Point {
    #[inline]
    fn zero() -> Point {
        Point {
            x: BigNum::zero(),
            y: BigNum::zero(),
        }
    }

    fn double(&self, P: &BigNum) -> Point {
        let X1 = self.x;
        let Y1 = self.y;

        let two = BigNum::from_u8(2).unwrap();
        let three = BigNum::from_u8(3).unwrap();

        //println!("> lam");

        //println!("3 x X1 x X1 = {}", as_hex(three * X1 * X1));
        //print!("mod_inverse = ");
        //print!("{}\n", as_hex(Self::invert(two * Y1, P)));
        //let tmp_inv = (two * Y1) ^ Bn::from_i8(-1).unwrap();
        //print!("{}\n", as_hex(((two * Y1) ^ Bn::from_i8(-1).unwrap()) % P));
        //print!("{}\n", as_hex(two * Y1));

        //println!("lam[..] = {}", as_hex(three * X1 % P * X1 % P));
        let lam = ((three * ((X1 * X1) % P)) % P) * Self::invert(&(two * Y1), P) % P;
        //println!("lam = {}", as_hex(lam));
        //println!("< lam");

        //println!("> x3");
        let X3 = (lam * lam - two * X1) % P;
        //println!("< x3");
        //println!("> y3");
        //print!("X1 {} - X3 {} = ", as_hex(X1), as_hex(X3));
        //println!("{}", as_hex(X1 + P - X3));
        let X1 = if X1 < X3 { X1 + P } else { X1 };
        let Y3 = (lam * (X1 - X3) - Y1) % P;
        //println!("< y3");

        Point { x: X3, y: Y3 }
    }

    #[inline]
    fn double_assign_mod(&mut self, P: &BigNum, one: &BigNum) {
        //let X1 = self.x.clone();
        let X1 = &self.x;
        //let Y1 = self.y.clone();
        let Y1 = &self.y;

        let two = BigNum::from_u8(2).unwrap();
        let three = BigNum::from_u8(3).unwrap();
        //let three = BigNum::from_le_bytes(&[
        //    3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        //    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        //    0, 0, 0, 0, 0, 0,
        //]);

        //let mut three = BigNum::from_le_bytes(&[
        //    3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        //    0, 0, 0,
        //]);

        let lam = ((three * ((*X1 * *X1) % P)) % P) * Self::invert(&(two * Y1), P) % P;

        let X3 = (lam * lam - two * X1) % P;
        let Y3 = if *X1 < X3 {
            (lam * (*P + X1 - X3) - Y1) % P
        } else {
            (lam * (*X1 - X3) - Y1) % P
        };

        self.x = X3;
        self.y = Y3;
    }

    fn add(&self, other: Point, P: &BigNum) -> Point {
        let X1 = self.x;
        let Y1 = self.y;
        let X2 = other.x;
        let Y2 = other.y;

        if X1.is_zero() || Y1.is_zero() {
            return other;
        }

        if X2.is_zero() || Y2.is_zero() {
            return self.clone();
        }

        if X1 == X2 && Y1 == Y2 {
            return self.double(P);
        }

        if X1 == X2 && Y1 == BigNum::from_i8(-1).unwrap() * Y2 {
            return Self::zero();
        }

        let lam = ((Y2 - Y1) - Self::invert(&(X2 - X1), P)) % P;

        let X3 = (lam * lam - X1 - X2) % P;
        let Y3 = (lam * (X1 - X3) - Y1) % P;

        Point { x: X3, y: Y3 }
    }

    #[inline]
    fn add_assign_mod(&mut self, other: &Point, P: &BigNum, one: &BigNum) {
        let X1 = &self.x;
        let Y1 = &self.y;
        let X2 = &other.x;
        let Y2 = &other.y;

        if X1.is_zero() || Y1.is_zero() {
            self.x = *X2;
            self.y = *Y2;
            return;
        }

        if X2.is_zero() || Y2.is_zero() {
            return;
        }

        if X1 == X2 && Y1 == Y2 {
            //let double = self.double(P);
            //self.x = double.x;
            //self.y = double.y;
            self.double_assign_mod(P, one);
            return;
        }

        if X1 == X2 && *Y1 == BigNum::from_i8(-1).unwrap() * Y2 {
            self.x = BigNum::zero();
            self.y = BigNum::zero();
            return;
        }

        //let lam = ((*Y2 - Y1) - Self::invert_one(&mut (*X2 - X1), P, one)) % P;
        let lam = ((*Y2 - Y1) - Self::invert(&mut (*X2 - X1), P)) % P;

        let X3 = (lam * lam - X1 - X2) % P;
        let Y3 = (lam * (*X1 - X3) - Y1) % P;

        self.x = X3;
        self.y = Y3;
    }

    #[inline]
    pub fn invert(num: &BigNum, modulo: &BigNum) -> BigNum {
        let two = BigNum::from_u8(2).unwrap();

        power_modulo(num, &mut (*modulo - two), modulo) % modulo
    }

    #[inline]
    pub fn multiply_DA(&self, n: &mut BigNum, P: &BigNum) -> Point {
        let mut p = Self::zero();
        let mut d = self.clone();

        let one = BigNum::one();

        while !n.is_zero() {
            if !(*n & one).is_zero() {
                //if !(*n >> n.bit_length() - 1).is_zero() {
                //1. og
                //p = p.add(d.clone(), P);
                //2.
                //p = p.add(&d, P);

                p.add_assign_mod(&d, &P, &one);
            }

            //let d_d = d.double(P);
            //d = d_d;
            // OR
            d.double_assign_mod(&P, &one);

            *n >>= 1_usize;
        }

        p
    }

    #[inline]
    pub fn multiply_DA_self(&mut self, n: &mut BigNum, P: &BigNum) {
        let mut d = self.clone();
        let one = BigNum::one();

        while !n.is_zero() {
            if !(*n >> n.bit_length() - 1).is_zero() {
                //1. og
                //p = p.add(d.clone(), P);
                //2.
                //p = p.add(&d, P);

                self.add_assign_mod(&d, &P, &one);
            }

            //let d_d = d.double(P);
            //d = d_d;

            d.double_assign_mod(&P, &one);
            *n >>= 1_usize;
        }
    }

    pub fn multiply_JDA(&self, mut n: BigNum, P: &BigNum) -> Point {
        use crate::jacobian::JacobianPoint;

        let mut p = JacobianPoint::zero();
        let mut d = JacobianPoint::from_affine(self.clone());

        while !n.is_zero() {
            if n & BigNum::one() > BigNum::zero() {
                p = p.add(d.clone(), P);
            }
            let d_d = d.double(P);
            d = d_d;
            n >>= 1_usize;
        }

        //println!("to affine");

        p.to_affine(P)
    }

    pub fn as_hex(&self, buf: &mut [u8; 128]) {
        self.x.to_hex_str(&mut buf[0..64]).unwrap();
        self.y.to_hex_str(&mut buf[64..128]).unwrap();
    }
}

#[cfg(feature = "std")]
impl core::fmt::Display for Point {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let mut buf = [0u8; 128];

        let _ = write!(f, "{{");
        let _ = write!(f, " x: {},", self.x.to_hex_str(&mut buf).unwrap());
        let _ = write!(f, " y: {} ", self.y.to_hex_str(&mut buf).unwrap());
        let _ = write!(f, "}}");

        Ok(())
    }
}

// calculates num ^ power % modulo, faster than naive way
#[inline]
fn power_modulo(num_: &BigNum, power: &mut BigNum, modulo: &BigNum) -> BigNum {
    //println!("num {:?}", std::str::from_utf8(&crate::as_hex(*num_)));
    //println!("pwr {:?}", std::str::from_utf8(&crate::as_hex(*power)));
    let one = BigNum::one();

    let mut result = one;
    let mut num = *num_;

    loop {
        // NOTE: is_even() shaves 0.3sec from 1.75s vs. is_multiple_of(&two)
        while power.is_even() {
            *power >>= 1_usize;
            //println!(
            //    ">> pwr = {:?}",
            //    std::str::from_utf8(&crate::as_hex(*power)[64..]).unwrap()
            //);
            num = (num % modulo) * (num % modulo);
            //println!(
            //    ">> num = {:?}",
            //    std::str::from_utf8(&crate::as_hex(num)[64..]).unwrap()
            //);
        }

        if !power.is_zero() {
            result = num % modulo * result % modulo;
            *power -= one;
        }

        if power.is_zero() {
            break;
        }
    }

    //println!("res {:?}", std::str::from_utf8(&crate::as_hex(result)));
    result
}

// calculates num ^ power % modulo, faster than naive way
#[inline]
fn power_modulo_one(num: &mut BigNum, power: &mut BigNum, modulo: &BigNum, one: &BigNum) -> BigNum {
    let mut result = *one;

    loop {
        // NOTE: is_even() shaves 0.3sec from 1.75s vs. is_multiple_of(&two)
        while power.is_even() {
            *power >>= 1_usize;
            *num = (*num % modulo) * (*num % modulo);
            //*num %= modulo;
            //*num *= *num;
        }

        if !power.is_zero() {
            result = *num % modulo * result % modulo;
            *power -= one;
        }

        if power.is_zero() {
            break;
        }
    }

    result
}
