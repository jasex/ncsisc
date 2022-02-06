pub mod kleptographic {
    pub use curv::arithmetic::Converter;
    pub use curv::elliptic::curves::{Point, Scalar, Secp256k1};
    pub use curv::BigInt;
    pub use openssl::hash::{Hasher, MessageDigest};
    pub use rand::thread_rng;
    use rand::{AsByteSliceMut, Rng};
    use serde::{Deserialize, Serialize};
    use sha3::{Digest, Keccak256};
    use std::env;
    use std::fs::File;
    use std::io::Write;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Param {
        a: Scalar<Secp256k1>,
        b: Scalar<Secp256k1>,
        h: Scalar<Secp256k1>,
        e: Scalar<Secp256k1>,
    }

    #[derive(Clone, Debug)]
    pub struct Signature {
        pub r: Scalar<Secp256k1>,
        pub s: Scalar<Secp256k1>,
        pub v: BigInt,
    }

    #[derive(Clone, Debug)]
    pub struct KeyPair {
        pub private: Scalar<Secp256k1>,
        pub public: Point<Secp256k1>,
    }

    impl KeyPair {
        pub fn new(private: Scalar<Secp256k1>) -> Self {
            KeyPair {
                private: private.clone(),
                public: private * Point::generator(),
            }
        }
        pub fn fingerprint(&self) -> String {
            let bytes = self.public.to_bytes(false);
            base64::encode(&*bytes)
        }
        pub fn save(&self) -> std::io::Result<()> {
            let mut base_path = env::current_dir()?;
            base_path.push("keys");
            let mut path1 = base_path.clone();
            path1.push("server_host_key");
            let mut path2 = base_path.clone();
            path2.push("server_host_key");
            path2.set_extension("pub");

            let private_key = self.private.to_bigint().to_bytes();
            let mut public_key = self.public.to_bytes(false);

            if let Ok(mut file) = File::create(path1.clone()) {
                file.write(&private_key)?;
            }

            if let Ok(mut file) = File::create(path2.clone()) {
                file.write(&public_key)?;
            }

            Ok(())
        }
    }
    impl Signature {
        pub fn new() -> Self {
            let r: Scalar<Secp256k1> = Scalar::from(0);
            let s: Scalar<Secp256k1> = Scalar::from(0);
            let v = BigInt::from(0);
            Signature { r, s, v }
        }
    }

    impl Param {
        pub fn new() -> Self {
            Param {
                a: Scalar::random(),
                b: Scalar::random(),
                h: Scalar::random(),
                e: Scalar::random(),
            }
        }
    }

    pub fn sign(message: String, keypair: KeyPair, k: Scalar<Secp256k1>) -> Option<Signature> {
        let mut hasher = Hasher::new(MessageDigest::sha256()).expect("Init hasher error");
        hasher.update(message.as_bytes()).expect("Hash error");
        let m: Scalar<Secp256k1> = Scalar::from_bytes(hasher.finish().unwrap().as_ref()).unwrap();
        let signature_point = k.clone() * Point::generator();

        let mut v = signature_point.y_coord().unwrap() & BigInt::from(1 as u16);

        let r: Scalar<Secp256k1> = Scalar::from_bigint(&signature_point.x_coord().unwrap());
        let s: Scalar<Secp256k1> =
            k.clone().invert().unwrap() * (m.clone() + r.clone() * keypair.private.clone());

        let n = Scalar::<Secp256k1>::group_order();
        if s.clone().to_bigint() > n / 2 {
            v = v ^ BigInt::from(1 as u16);
        }

        Some(Signature { r, s, v })
    }
    pub fn sign_hash(hash: Vec<u8>, keypair: KeyPair, k: Scalar<Secp256k1>) -> Option<Signature> {
        let m: Scalar<Secp256k1> = Scalar::from_bytes(&hash).unwrap();
        let signature_point = k.clone() * Point::generator();

        let mut v = signature_point.y_coord().unwrap() & BigInt::from(1 as u16);

        let r: Scalar<Secp256k1> = Scalar::from_bigint(&signature_point.x_coord().unwrap());
        let s: Scalar<Secp256k1> =
            k.clone().invert().unwrap() * (m.clone() + r.clone() * keypair.private.clone());

        let n = Scalar::<Secp256k1>::group_order();
        if s.clone().to_bigint() > n / 2 {
            v = v ^ BigInt::from(1 as u16);
        }
        Some(Signature { r, s, v })
    }
    pub fn mal_sign(
        message1: String,
        message2: String,
        param: Param,
        user_key_pair: KeyPair,
        attacker_key_pair: KeyPair,
    ) -> Option<[Signature; 2]> {
        let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();

        let k1: Scalar<Secp256k1> = Scalar::random();
        let sign1 = sign(message1.clone(), user_key_pair.clone(), k1.clone()).unwrap();

        let mut rng = thread_rng();
        let u: Scalar<Secp256k1> = Scalar::from(rng.gen::<u16>() % 2);
        let j: Scalar<Secp256k1> = Scalar::from(rng.gen::<u16>() % 2);
        let z = k1.clone() * param.a.clone() * Point::generator()
            + param.b.clone() * k1.clone() * attacker_key_pair.public.clone()
            + j.clone() * param.h.clone() * Point::generator()
            + u.clone() * param.e.clone() * attacker_key_pair.public.clone();
        let zx = z.x_coord().unwrap();
        hasher.update(&zx.to_bytes()).expect("Hash error");
        let k2: Scalar<Secp256k1> = Scalar::from_bytes(hasher.finish().unwrap().as_ref()).unwrap();
        let sign2 = sign(message2.clone(), user_key_pair.clone(), k2.clone()).unwrap();

        return Some([sign1, sign2]);
    }
    pub fn mal_sign_hash(
        hash1: Vec<u8>,
        hash2: Vec<u8>,
        param: Param,
        user_key_pair: KeyPair,
        attacker_key_pair: KeyPair,
    ) -> Option<[Signature; 2]> {
        let k1: Scalar<Secp256k1> = Scalar::random();
        let sign1 = sign_hash(hash1.clone(), user_key_pair.clone(), k1.clone()).unwrap();

        let mut rng = thread_rng();
        let u: Scalar<Secp256k1> = Scalar::from(rng.gen::<u16>() % 2);
        let j: Scalar<Secp256k1> = Scalar::from(rng.gen::<u16>() % 2);
        let z = k1.clone() * param.a.clone() * Point::generator()
            + param.b.clone() * k1.clone() * attacker_key_pair.public.clone()
            + j.clone() * param.h.clone() * Point::generator()
            + u.clone() * param.e.clone() * attacker_key_pair.public.clone();
        let zx = z.x_coord().unwrap();

        let mut hasher = Keccak256::new();
        Digest::update(&mut hasher, &zx.to_bytes());
        let k2: Scalar<Secp256k1> = Scalar::from_bytes(hasher.finalize().as_ref()).unwrap();
        let sign2 = sign_hash(hash2.clone(), user_key_pair.clone(), k2.clone()).unwrap();
        return Some([sign1, sign2]);
    }

    pub fn verify(message: String, sign: Signature, public: Point<Secp256k1>) -> Result<(), ()> {
        let mut hasher = Hasher::new(MessageDigest::sha256()).unwrap();
        hasher.update(message.as_bytes()).unwrap();
        let m1: Scalar<Secp256k1> = Scalar::from_bytes(hasher.finish().unwrap().as_ref()).unwrap();
        let w = sign.s.invert().unwrap();
        let u1 = m1.clone() * w.clone();
        let u2 = sign.r.clone() * w.clone();
        let verify_point = u1.clone() * Point::generator() + u2.clone() * public.clone();
        if sign.r.to_bigint() == verify_point.x_coord().unwrap() {
            Ok(())
        } else {
            Err(())
        }
    }
    pub fn verify_hash(hash: Vec<u8>, sign: Signature, public: Point<Secp256k1>) -> Result<(), ()> {
        let m1: Scalar<Secp256k1> = Scalar::from_bytes(&hash).unwrap();
        let w = sign.s.invert().unwrap();
        let u1 = m1.clone() * w.clone();
        let u2 = sign.r.clone() * w.clone();
        let verify_point = u1.clone() * Point::generator() + u2.clone() * public.clone();
        if sign.r.to_bigint() == verify_point.x_coord().unwrap() {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn extract_users_private_key(
        message1: String,
        message2: String,
        param: Param,
        sign1: Signature,
        sign2: Signature,
        attackers_private: Scalar<Secp256k1>,
        attackers_public: Point<Secp256k1>,
        user_public: Point<Secp256k1>,
    ) -> Option<Scalar<Secp256k1>> {
        let mut hasher = Hasher::new(MessageDigest::sha256()).expect("Unable to initial hasher");
        // calculate the hash of message1
        hasher.update(message1.as_bytes()).expect("Hash error");
        let m1: Scalar<Secp256k1> = Scalar::from_bytes(hasher.finish().unwrap().as_ref()).unwrap();
        // calculate the hash of message2
        hasher.update(message2.as_bytes()).expect("Hash error");
        let m2: Scalar<Secp256k1> = Scalar::from_bytes(hasher.finish().unwrap().as_ref()).unwrap();

        let w = sign1.s.invert().unwrap();
        let u1 = m1.clone() * w.clone();
        let u2 = sign1.r.clone() * w.clone();

        let verify_point = u1.clone() * Point::generator() + u2.clone() * user_public.clone();
        let z1 = verify_point.clone() * param.a.clone()
            + (verify_point.clone() * param.b.clone() * attackers_private.clone());

        for u in 0..=1 {
            for j in 0..=1 {
                let z2 = z1.clone()
                    + Scalar::from(j) * param.h.clone() * Point::generator()
                    + Scalar::from(u) * param.e.clone() * attackers_public.clone();
                let zx: Scalar<Secp256k1> = Scalar::from_bigint(&z2.x_coord().unwrap());
                hasher
                    .update(&zx.to_bigint().to_bytes())
                    .expect("Hash error");
                let hash: Scalar<Secp256k1> =
                    Scalar::from_bytes(hasher.finish().unwrap().as_ref()).unwrap();

                let k_candidate = hash.clone();
                let verify_point_candidate = k_candidate.clone() * Point::generator();
                let r_candidate = verify_point_candidate.x_coord().unwrap();
                if r_candidate == sign2.r.to_bigint() {
                    return Some(
                        (sign2.s.clone() * k_candidate.clone() - m2) * (sign2.r.invert().unwrap()),
                    );
                }
            }
        }
        None
    }
    pub fn extract_users_private_key_hash(
        hash1: Vec<u8>,
        hash2: Vec<u8>,
        param: Param,
        sign1: Signature,
        sign2: Signature,
        attacker_keypair: KeyPair,
        user_public: Point<Secp256k1>,
    ) -> Option<Scalar<Secp256k1>> {
        let m1: Scalar<Secp256k1> = Scalar::from_bytes(&hash1).unwrap();
        let m2: Scalar<Secp256k1> = Scalar::from_bytes(&hash2).unwrap();

        let w = sign1.s.invert().unwrap();
        let u1 = m1.clone() * w.clone();
        let u2 = sign1.r.clone() * w.clone();

        let verify_point = u1.clone() * Point::generator() + u2.clone() * user_public.clone();
        let z1 = verify_point.clone() * param.a.clone()
            + (verify_point.clone() * param.b.clone() * attacker_keypair.private.clone());

        for u in 0..=1 {
            for j in 0..=1 {
                let mut hasher = Keccak256::new();
                let z2 = z1.clone()
                    + Scalar::from(j) * param.h.clone() * Point::generator()
                    + Scalar::from(u) * param.e.clone() * attacker_keypair.public.clone();
                let zx: Scalar<Secp256k1> = Scalar::from_bigint(&z2.x_coord().unwrap());
                Digest::update(&mut hasher, zx.to_bigint().to_bytes());
                // hasher
                //     .update(&zx.to_bigint().to_bytes())
                //     .expect("Hash error");
                let hash: Scalar<Secp256k1> =
                    Scalar::from_bytes(hasher.finalize().as_ref()).unwrap();

                let k_candidate = hash.clone();
                let verify_point_candidate = k_candidate.clone() * Point::generator();
                let r_candidate = verify_point_candidate.x_coord().unwrap();
                if r_candidate == sign2.r.to_bigint() {
                    return Some(
                        (sign2.s.clone() * k_candidate.clone() - m2) * (sign2.r.invert().unwrap()),
                    );
                }
            }
        }
        None
    }
}
#[cfg(test)]
mod tests {
    use crate::kleptographic::*;
    use sha3::{Digest, Keccak256};

    #[test]
    fn test_extract_users_private_key() {
        let message1 = String::from("first message");
        let message2 = String::from("second message");
        let param = Param::new();
        let user_keypair = KeyPair::new(Scalar::random());
        let attacker_keypair = KeyPair::new(Scalar::random());
        let signs = mal_sign(
            message1.clone(),
            message2.clone(),
            param.clone(),
            user_keypair.clone(),
            attacker_keypair.clone(),
        )
        .unwrap();
        let temp = extract_users_private_key(
            message1.clone(),
            message2.clone(),
            param.clone(),
            signs[0].clone(),
            signs[1].clone(),
            attacker_keypair.private.clone(),
            attacker_keypair.public.clone(),
            user_keypair.public.clone(),
        )
        .unwrap();
        assert_eq!(temp.to_bigint(), user_keypair.private.to_bigint());
    }
    #[test]
    fn test_extract_users_private_key_hash() {
        let mut hasher = Keccak256::new();

        let message1 = String::from("hello");
        let message2 = String::from("hello, again");
        let param = Param::new();
        let user_keypair = KeyPair::new(Scalar::random());
        let attacker_keypair = KeyPair::new(Scalar::random());
        Digest::update(&mut hasher, message1.as_bytes());
        let hash1 = hasher.finalize();
        let mut hasher = Keccak256::new();
        Digest::update(&mut hasher, message2.as_bytes());
        let hash2 = hasher.finalize();

        let [sign1, sign2] = mal_sign_hash(
            hash1.clone().to_vec(),
            hash2.clone().to_vec(),
            param.clone(),
            user_keypair.clone(),
            attacker_keypair.clone(),
        )
        .unwrap();

        let recover = extract_users_private_key_hash(
            hash1.clone().to_vec(),
            hash2.clone().to_vec(),
            param.clone(),
            sign1.clone(),
            sign2.clone(),
            attacker_keypair.clone(),
            user_keypair.public.clone(),
        )
        .unwrap();
        assert_eq!(
            user_keypair.private.clone().to_bigint(),
            recover.to_bigint()
        );
    }

    #[test]
    fn sign_and_verify() {
        let message1 = String::from("i'm first message");
        let keypair = KeyPair::new(Scalar::random());
        let sig = sign(message1.clone(), keypair.clone(), Scalar::random()).unwrap();
        assert_eq!(
            verify(message1.clone(), sig.clone(), keypair.public.clone()),
            Ok(())
        );
    }
    #[test]
    fn sign_and_verify_hash() {
        let message1 = String::from("i'm first message");
        let mut hasher = Keccak256::new();
        Digest::update(&mut hasher, message1.as_bytes());
        let result = hasher.finalize();
        let keypair = KeyPair::new(Scalar::random());
        let sign1 = sign_hash(result.clone().to_vec(), keypair.clone(), Scalar::random()).unwrap();
        let out = verify_hash(
            result.clone().to_vec(),
            sign1.clone(),
            keypair.public.clone(),
        );
        assert_eq!(out, Ok(()));
    }
    #[test]
    fn test_save() {
        use std::fs::File;
        use std::io::prelude::*;
        use std::io::BufReader;
        let keypair = KeyPair::new(Scalar::random());
        let out = keypair.save();
        println!("{:?}", out);
        let mut f1 =
            File::open("/home/zj/Documents/ncsisc/library/ncsisc/keys/server_host_key").unwrap();
        let mut f2 =
            File::open("/home/zj/Documents/ncsisc/library/ncsisc/keys/server_host_key.pub")
                .unwrap();
        let mut reader1 = BufReader::new(f1);
        let mut reader2 = BufReader::new(f2);
        let mut buffer1 = Vec::new();
        let mut buffer2 = Vec::new();
        reader1.read_to_end(&mut buffer1);
        reader2.read_to_end(&mut buffer2);
        let check1: Scalar<Secp256k1> = Scalar::from_bytes(&buffer1).unwrap();
        let check2: Point<Secp256k1> = Point::from_bytes(&buffer2).unwrap();
        assert_eq!((check1, check2), (keypair.private, keypair.public))
    }
    #[test]
    fn test_fingerprint() {
        let keypair = KeyPair::new(Scalar::random());
        println!("{}", keypair.fingerprint());
    }
}
