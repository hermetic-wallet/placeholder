use fixed_bigint::num_traits::{FromPrimitive, One, PrimInt, Zero};

use crate::{BigNum, Point};

#[derive(Clone)]
pub struct JacobianPoint {
    x: BigNum,
    y: BigNum,
    z: BigNum,
}

impl JacobianPoint {
    pub fn zero() -> JacobianPoint {
        JacobianPoint {
            x: BigNum::zero(),
            y: BigNum::zero(),
            z: BigNum::zero(),
        }
    }

    pub fn from_affine(p: Point) -> JacobianPoint {
        JacobianPoint {
            x: p.x,
            y: p.y,
            z: BigNum::one(),
        }
    }

    pub fn to_affine(&self, P: &BigNum) -> Point {
        let inv_z = Point::invert(&self.z, P);
        //println!("to_affine::inv_z = {}", as_hex(inv_z));

        let inv_z_2 = inv_z.pow(2) % P;
        let inv_z_3 = inv_z * inv_z_2 % P;

        let x = self.x % P * inv_z_2 % P;
        //println!("to_affine::1");
        let y = ((self.y % P) * (inv_z_3)) % P;

        Point { x, y }
    }

    ///
    ///    Fast algo for adding 2 Jacobian Points when curve's a=0.
    ///    http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-1998-cmo-2
    ///    Cost: 12M + 4S + 6add + 1*2.
    ///    Note: 2007 Bernstein-Lange (11M + 5S + 9add + 4*2) is actually *slower*. No idea why.
    ///
    pub fn add(&self, other: JacobianPoint, P: &BigNum) -> JacobianPoint {
        //println!("add::");
        let two = BigNum::from_u8(2).unwrap();

        let X1 = self.x;
        let Y1 = self.y;
        let Z1 = self.z;

        let X2 = other.x;
        let Y2 = other.y;
        let Z2 = other.z;

        if X2.is_zero() || Y2.is_zero() {
            return self.clone();
        }

        if X1.is_zero() || Y1.is_zero() {
            return other;
        }

        //println!("add::1");
        let Z1Z1 = Z1 * Z1 % P;
        let Z2Z2 = Z2 * Z2 % P;

        //println!("add::2");
        let U1 = X1 * Z2Z2 % P;
        let U2 = X2 * Z1Z1 % P;

        //println!("add::3");
        let S1 = Y1 * (Z2 * Z2Z2 % P) % P;
        //println!("add::3.1");
        let S2 = Y2 * (Z1 * Z1Z1 % P) % P;

        //println!("add::4");
        let H = (*P + U2 - U1) % P;
        //println!("add::4.1");
        let r = (*P + S2 - S1) % P;

        if H.is_zero() {
            if r.is_zero() {
                return self.double(P);
            } else {
                return Self::zero();
            }
        }

        //println!("add::5");
        let HH = (H * H) % P;
        let HHH = (H * HH) % P;
        let V = U1 * HH % P;

        //println!("add::6");
        let X3 = (r.pow(2) - HHH - two * V) % P;
        //println!("add::6.1");
        //let Y3 = (r * (V - X3) - S1 * HHH) % P;
        //let Y3 = (r * (V - X3) - S1 * HHH) % P;
        let Y3_p1 = (r * ((*P + V - X3) % P)) % P;

        //println!("add::6.2");
        let Y3_p2 = S1 * HHH % P;
        //println!("add::6.3");

        let Y3 = (*P + Y3_p1 - Y3_p2) % P;

        //println!("add::6.4");
        let Z3 = ((Z1 * Z2 % P) * H) % P;
        //println!("add::99");

        JacobianPoint {
            x: X3,
            y: Y3,
            z: Z3,
        }
    }

    ///    Fast algo for doubling 2 Jacobian Points when curve's a=0.
    ///    From: http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
    ///    Cost: 2M + 5S + 6add + 3*2 + 1*3 + 1*8.
    pub fn double(&self, P: &BigNum) -> JacobianPoint {
        //println!("double::");
        let two = BigNum::from_u8(2).unwrap();
        let three = BigNum::from_u8(3).unwrap();
        let eight = BigNum::from_u8(8).unwrap();

        let X1 = self.x;
        let Y1 = self.y;
        let Z1 = self.z;

        let A = X1 * X1 % P;
        let B = Y1 * Y1 % P;
        let C = B * B % P;
        //println!("double::10::");

        //let D = (two * ((X1 + B).pow(2) - A - C)) % P;
        //println!("running D");
        let mut D = (two * ((((X1 + B) % P).pow(2) - A - C) % P)) % P;
        let E = three * A % P;
        let mut F = E.pow(2) % P;

        //println!("double::20::");
        //println!("F {} - two * D {}", as_hex(F), as_hex(two * D));
        // fix for X3 line
        while F < two * D {
            F += P;
        }
        let X3 = (F - two * D) % P;
        //println!("D - X3");
        if D < X3 {
            D += P;
        }
        let _ = D - X3;
        //println!("D - X3");

        let Y3 = (E * (D - X3) - eight * C) % P;
        //println!("double::88::");
        let Z3 = (two * ((Y1 * Z1) % P)) % P;
        //println!("double::99::");

        JacobianPoint {
            x: X3,
            y: Y3,
            z: Z3,
        }
    }
}

#[cfg(feature = "std")]
impl core::fmt::Display for JacobianPoint {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let mut buf = [0u8; 128];

        let _ = write!(f, "{{");
        let _ = write!(f, " x: {},", self.x.to_hex_str(&mut buf).unwrap());
        let _ = write!(f, " y: {},", self.y.to_hex_str(&mut buf).unwrap());
        let _ = write!(f, " z: {} ", self.z.to_hex_str(&mut buf).unwrap());
        let _ = write!(f, "}}");

        Ok(())
    }
}
