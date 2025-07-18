use hex_literal::hex;
use k256::ecdsa::signature::DigestSigner;
use k256::ecdsa::{SigningKey, VerifyingKey};
//use k256::ecdsa::recoverable::Signature;
use k256::ecdsa::Signature; // for 0.12

//use k256::sha2::{Digest, Sha256};
use sha3::{Digest, Keccak256};

use k256::ecdsa::hazmat::SignPrimitive;
use k256::ecdsa::signature::digest::generic_array::GenericArray;
use k256::ecdsa::signature::digest::{
    core_api::BlockSizeUser, FixedOutput, FixedOutputReset, HashMarker, Output, OutputSizeUser,
    Reset, Update,
};

fn main() {
    let signing_key = SigningKey::from_bytes(&hex!(
        "0100000000000000000000000000000000000000000000000000000000000000"
    ))
    .unwrap();

    /*
    let msg = hex!("52fbb559a867af2f7613fd01b0a59e1363d3403830551c22f65622ccf93e7db3");
    let digest = Keccak256::digest(msg);
    let (sig, recid) = signing_key
        .as_nonzero_scalar()
        .try_sign_prehashed_rfc6979::<k256::sha2::Sha256>(digest, b"")
        .unwrap();
    */

    let msg = hex!("52fbb559a867af2f7613fd01b0a59e1363d3403830551c22f65622ccf93e7db3");
    let (sig, recid) = signing_key
        .as_nonzero_scalar()
        .try_sign_prehashed_rfc6979::<k256::sha2::Sha256>(*GenericArray::from_slice(&msg), b"")
        .unwrap();

    /*
    let msg = Keccak256::new_with_prefix(hex!(
        "52fbb559a867af2f7613fd01b0a59e1363d3403830551c22f65622ccf93e7db3"
    ));
    let (sig, recid) = signing_key.sign_digest_recoverable(msg).unwrap();
    */

    println!("{sig}");

    /*
    let recid = recid.unwrap();
    let recovered_key =
        VerifyingKey::recover_from_digest(Keccak256::new_with_prefix(msg), &sig, recid).unwrap();
    let expected_key = signing_key.verifying_key();

    assert_eq!(recovered_key, *expected_key);
    */
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use k256::EncodedPoint;
    use sha3::{Digest, Keccak256};

    const VK: [u8; 33] = hex!("028c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa");

    #[test]
    fn test_sig_k256_signed() {
        let msg = hex!("52fbb559a867af2f7613fd01b0a59e1363d3403830551c22f65622ccf93e7db3");
        let digest = Keccak256::new_with_prefix(msg);

        let sig = hex!("3B90D82888D0E5A8428FC8F0956E2368150E292074082128611CEC323D6D37447DB3E5D98E1EBDB20250AC88701EF92C1596DBD30F0DDF0E1160E73E9025CA4F");
        let sig = Signature::try_from(&sig[..]).unwrap();

        let recid = RecoveryId::new(false, false);
        let pk = VerifyingKey::recover_from_digest(digest, &sig, recid).unwrap();

        assert_eq!(VK, EncodedPoint::from(&pk).as_bytes(),);
    }

    #[test]
    fn test_sig_uECC_signed() {
        let msg = hex!("52fbb559a867af2f7613fd01b0a59e1363d3403830551c22f65622ccf93e7db3");
        let digest = Keccak256::new_with_prefix(msg);

        let sig = hex!("f8f4a8dd90f010ed7b5348054ce43dbb1e71839143b1c1f13942c2289cec73c251a673eb714f337e3039619fb9b7e81af0e8b1177f811de0fd42b5dcefe4469c");
        let sig = Signature::try_from(&sig[..]).unwrap();

        let recid = RecoveryId::new(false, false);
        let pk = VerifyingKey::recover_from_digest(digest, &sig, recid).unwrap();

        assert_eq!(VK, EncodedPoint::from(&pk).as_bytes(),);
    }

    #[test]
    fn test_sig_geth_signed() {
        let msg = hex!("52fbb559a867af2f7613fd01b0a59e1363d3403830551c22f65622ccf93e7db3");
        let digest = Keccak256::new_with_prefix(msg);

        let sig = hex!("71f498f5d9a05e83599a65e31febd4fb07451127031cf069c05c55ce586f248b0247be206cff797fe03223673560c431cf2f94a02ebbb09fda8e4a7b03c2f353");
        let sig = Signature::try_from(&sig[..]).unwrap();

        let recid = RecoveryId::new(false, false);
        let pk = VerifyingKey::recover_from_digest(digest, &sig, recid).unwrap();

        assert_eq!(VK, EncodedPoint::from(&pk).as_bytes(),);
    }
}
