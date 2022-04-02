pub mod kleptographic {
    pub use curv::arithmetic::Converter;
    pub use curv::elliptic::curves::{Point, Scalar, Secp256k1};
    pub use curv::BigInt;
    pub use openssl::hash::{Hasher, MessageDigest};
    pub use rand::thread_rng;
    use rand::{AsByteSliceMut, Rng};
    use serde::{Deserialize, Serialize, Serializer};
    use sha3::{Digest, Keccak256};
    use std::env;
    use std::fs::File;
    use std::io::Write;

    #[derive(Clone, Debug)]
    pub struct Param {
        a: Scalar<Secp256k1>,
        b: Scalar<Secp256k1>,
        h: Scalar<Secp256k1>,
        e: Scalar<Secp256k1>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
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
        // the fingerprint will always end with '='
        pub fn fingerprint(&self) -> String {
            let bytes = self.public.to_bytes(false);
            let hash = fast_hash(&*bytes);
            base64::encode(&hash)
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
        pub fn from(
            a: Scalar<Secp256k1>,
            b: Scalar<Secp256k1>,
            h: Scalar<Secp256k1>,
            e: Scalar<Secp256k1>,
        ) -> Self {
            Param { a, b, h, e }
        }
    }

    // fast hash function using sm3
    pub fn fast_hash(data: &[u8]) -> Vec<u8> {
        use libsm::sm3::hash::Sm3Hash;
        let mut hash = Sm3Hash::new(data);
        Vec::from(hash.get_hash())
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
        attacker_public: Point<Secp256k1>,
    ) -> Option<[Signature; 2]> {
        let k1: Scalar<Secp256k1> = Scalar::random();
        let sign1 = sign_hash(hash1.clone(), user_key_pair.clone(), k1.clone()).unwrap();

        let mut rng = thread_rng();
        let u: Scalar<Secp256k1> = Scalar::from(rng.gen::<u16>() % 2);
        let j: Scalar<Secp256k1> = Scalar::from(rng.gen::<u16>() % 2);
        let z = k1.clone() * param.a.clone() * Point::generator()
            + param.b.clone() * k1.clone() * attacker_public.clone()
            + j.clone() * param.h.clone() * Point::generator()
            + u.clone() * param.e.clone() * attacker_public.clone();
        let zx = z.x_coord().unwrap();

        let mut hasher = Keccak256::new();
        Digest::update(&mut hasher, &zx.to_bytes());
        let k2: Scalar<Secp256k1> = Scalar::from_bytes(hasher.finalize().as_ref()).unwrap();
        let sign2 = sign_hash(hash2.clone(), user_key_pair.clone(), k2.clone()).unwrap();
        return Some([sign1, sign2]);
    }

    pub fn calculate_k(
        param: Param,
        k1: Scalar<Secp256k1>,
        public: Point<Secp256k1>,
    ) -> Scalar<Secp256k1> {
        let mut rng = thread_rng();
        let u: Scalar<Secp256k1> = Scalar::from(rng.gen::<u16>() % 2);
        let j: Scalar<Secp256k1> = Scalar::from(rng.gen::<u16>() % 2);
        let z = k1.clone() * param.a.clone() * Point::generator()
            + param.b.clone() * k1.clone() * public.clone()
            + j.clone() * param.h.clone() * Point::generator()
            + u.clone() * param.e.clone() * public.clone();

        let zx = z.x_coord().unwrap();

        let mut hasher = Keccak256::new();
        Digest::update(&mut hasher, &zx.to_bytes());
        let k2: Scalar<Secp256k1> = Scalar::from_bytes(hasher.finalize().as_ref()).unwrap();
        return k2;
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

pub mod protocol {
    use crate::kleptographic::*;
    use curv::elliptic::curves::Scalar;
    use serde::{Deserialize, Serialize};
    use std::fs::read;
    // use serde_json::Result;
    use libsm::sm4::{Cipher, Mode};
    pub use rand::thread_rng;
    use rand::RngCore;
    use rand::{AsByteSliceMut, Rng};
    use sha3::digest::DynDigest;
    use std::io::BufWriter;
    use std::io::{BufRead, BufReader};
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::process::id;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Kle {
        pub public: Point<Secp256k1>,
        pub hash1: Vec<u8>,
        pub hash2: Vec<u8>,
        pub sign1: Signature,
        pub sign2: Signature,
    }

    impl Kle {
        pub fn from(
            public: Point<Secp256k1>,
            hash1: Vec<u8>,
            hash2: Vec<u8>,
            sign1: Signature,
            sign2: Signature,
        ) -> Self {
            Kle {
                public,
                hash1,
                hash2,
                sign1,
                sign2,
            }
        }
    }

    // use hash to generate Param
    pub fn generate_param(hash: Vec<u8>) -> Param {
        use curv::elliptic::curves::Scalar;
        let a = fast_hash(&hash);
        let b = fast_hash(&a);
        let h = fast_hash(&b);
        let e = fast_hash(&h);
        Param::from(
            Scalar::<Secp256k1>::from_bytes(&a).unwrap(),
            Scalar::<Secp256k1>::from_bytes(&b).unwrap(),
            Scalar::<Secp256k1>::from_bytes(&h).unwrap(),
            Scalar::<Secp256k1>::from_bytes(&e).unwrap(),
        )
    }

    // convert hex string to public key
    pub fn hex_to_public(hex: String) -> Point<Secp256k1> {
        Point::from_bytes(&hex::decode(hex).unwrap()).unwrap()
    }

    // convert public key to hex string
    pub fn public_to_hex(public: Point<Secp256k1>) -> String {
        let v = public.to_bytes(false).to_vec();
        hex::encode(&v).to_string()
    }

    // client send (A, Ck.public)
    pub fn client_step1(
        identity: String,
        public: Point<Secp256k1>,
        stream: &mut TcpStream,
    ) -> std::io::Result<()> {
        let mut bytes = Vec::from(identity.as_bytes());
        bytes.extend_from_slice(&*public.to_bytes(false));
        let mut writer = BufWriter::new(stream.try_clone().unwrap());
        writer.write(&bytes).unwrap();
        println!("client_step1: {:?}", bytes);
        writer.flush()
    }

    // server function to recover struct from clent_step1
    pub fn server_recover1(stream: &mut TcpStream) -> Vec<Vec<u8>> {
        use bstr::ByteSlice;
        let mut buffer: [u8; 1024] = [0; 1024];
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        println!(
            "Server read {} bytes on step1",
            reader.read(&mut buffer).unwrap()
        );
        let buffer: Vec<u8> = buffer
            .to_vec()
            .into_iter()
            .filter(|&byte| byte != 0)
            .collect();
        println!("server recover 1: {:?}", buffer);
        let pattern: [u8; 1] = [61];
        let mut result: Vec<Vec<u8>> = buffer.split_str(&pattern).map(|x| x.to_vec()).collect();
        let public_string = result.pop().unwrap();
        let mut a_identity_string = result.pop().unwrap();
        a_identity_string.push(61);
        vec![a_identity_string, public_string]
    }

    // server send B, Kle_bk, SIGB(kle_bk,A)
    pub fn server_step1(
        param: Param,
        identity_a: String,
        identity_b: String,
        stream: &mut TcpStream,
        server_identity_keypair: KeyPair,
        session_keypair: KeyPair,
        public: Point<Secp256k1>,
    ) -> std::io::Result<()> {
        let hash1 = Vec::from(rand_block());
        let hash2 = fast_hash(&hash1);
        let [sign1, sign2] = mal_sign_hash(
            hash1.clone(),
            hash2.clone(),
            param,
            session_keypair.clone(),
            public.clone(),
        )
        .unwrap();
        let kle = Kle::from(session_keypair.public.clone(), hash1, hash2, sign1, sign2);
        let kle_string = serde_json::to_string(&kle).unwrap();
        let mut bytes_to_be_hash: Vec<u8> = Vec::from(kle_string.as_bytes());
        bytes_to_be_hash.extend_from_slice(identity_a.as_bytes());
        let sign = sign_hash(
            fast_hash(&bytes_to_be_hash),
            server_identity_keypair,
            Scalar::random(),
        )
        .unwrap();

        let mut bytes_to_send = Vec::new();
        bytes_to_send.extend_from_slice(identity_b.as_bytes());
        bytes_to_send.extend_from_slice(kle_string.as_bytes());
        bytes_to_send.extend_from_slice(serde_json::to_string(&sign).unwrap().as_bytes());
        let mut writer = BufWriter::new(stream.try_clone().unwrap());
        writer.write(&bytes_to_send);
        println!("server step 1: {:?}", bytes_to_send);
        writer.flush()
    }

    // function or client to recover message from server
    pub fn client_recover1(stream: &mut TcpStream) -> Vec<Vec<u8>> {
        use bstr::ByteSlice;
        let mut buffer: [u8; 1024] = [0; 1024];
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        println!(
            "Client read {} bytes on step1",
            reader.read(&mut buffer).unwrap()
        );
        let mut buffer: Vec<u8> = buffer
            .to_vec()
            .into_iter()
            .filter(|&byte| byte != 0)
            .collect();
        println!("client recover 1: {:?}", buffer);
        let pattern: Vec<u8> = vec![125, 123];
        let mut result: Vec<Vec<u8>> = buffer.split_str(&pattern).map(|x| x.to_vec()).collect();

        let mut sign_string = result.pop().unwrap();
        sign_string.insert(0, 123);
        let mut first_string = result.pop().unwrap();
        first_string.push(125);

        let pattern: [u8; 1] = [61];
        let mut result: Vec<Vec<u8>> = first_string
            .split_str(&pattern)
            .map(|x| x.to_vec())
            .collect();
        let mut kle_string = result.pop().unwrap();
        let mut b_identity_string = result.pop().unwrap();
        b_identity_string.push(61);
        vec![b_identity_string, kle_string, sign_string]
    }

    // client send SIGA(kle, B)
    pub fn client_step2(
        b_identity: String,
        kle_string: String,
        client_identity_keypair: KeyPair,
        stream: &mut TcpStream,
    ) -> std::io::Result<()> {
        let mut bytes_to_be_hashed: Vec<u8> = Vec::from(b_identity.as_bytes());
        bytes_to_be_hashed.extend_from_slice(kle_string.as_bytes());
        let hash = fast_hash(&bytes_to_be_hashed);
        let sign = sign_hash(hash, client_identity_keypair, Scalar::random()).unwrap();

        let mut writer = BufWriter::new(stream.try_clone().unwrap());
        writer.write(serde_json::to_string(&sign).unwrap().as_bytes());
        println!(
            "client step 2: {:?}",
            serde_json::to_string(&sign).unwrap().as_bytes()
        );
        writer.flush()
    }

    // server recover final signature from stream
    pub fn server_recover2(stream: &mut TcpStream) -> Vec<u8> {
        let mut buffer: [u8; 1024] = [0; 1024];
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        println!(
            "Server read {} bytes on step1",
            reader.read(&mut buffer).unwrap()
        );
        println!("server_recover 2: {:?}", buffer);
        buffer
            .to_vec()
            .into_iter()
            .filter(|&byte| byte != 0)
            .collect()
    }

    pub fn rand_block() -> [u8; 32] {
        let mut rng = rand::thread_rng();
        let mut block: [u8; 32] = [0; 32];
        rng.fill_bytes(&mut block[..]);
        block
    }

    // encrypt message using sm4
    pub fn encrypt(key: &[u8; 16], iv: &[u8; 16], plain_text: &[u8]) -> Vec<u8> {
        let cipher = Cipher::new(key, Mode::Cfb);

        // Encryption
        cipher.encrypt(plain_text, iv)
    }

    // decrypt cipher using sm4
    pub fn decrypt(key: &[u8; 16], iv: &[u8; 16], cipher_text: &[u8]) -> Vec<u8> {
        let cipher = Cipher::new(key, Mode::Cfb);
        // Decryption
        cipher.decrypt(&cipher_text[..], iv)
    }
}
#[cfg(test)]
mod tests {
    use crate::kleptographic::*;
    use crate::protocol::{generate_param, public_to_hex, rand_block, Kle};
    use rand::RngCore;
    use sha3::digest::DynDigest;
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
            attacker_keypair.public.clone(),
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
    #[test]
    fn test_new_time() {
        let mut hasher = Keccak256::new();

        let message1 = String::from("hello");
        let message2 = String::from("hello, again");
        let message3 = String::from("good bye");

        let param = Param::new();
        let user_keypair = KeyPair::new(Scalar::random());
        let attacker_keypair = KeyPair::new(Scalar::random());
        Digest::update(&mut hasher, message1.as_bytes());
        let hash1 = hasher.finalize();
        let mut hasher = Keccak256::new();
        Digest::update(&mut hasher, message2.as_bytes());
        let hash2 = hasher.finalize();
        let mut hasher = Keccak256::new();
        Digest::update(&mut hasher, message3.as_bytes());
        let hash3 = hasher.finalize();

        for i in 0..255 {
            let sign = sign_hash(
                hash3.clone().to_vec(),
                user_keypair.clone(),
                Scalar::random(),
            )
            .unwrap();
            verify_hash(hash3.clone().to_vec(), sign, user_keypair.public.clone());

            let [sign1, sign2] = mal_sign_hash(
                hash1.clone().to_vec(),
                hash2.clone().to_vec(),
                param.clone(),
                user_keypair.clone(),
                attacker_keypair.public.clone(),
            )
            .unwrap();
            verify_hash(
                hash1.clone().to_vec(),
                sign1.clone(),
                user_keypair.public.clone(),
            );
            verify_hash(
                hash2.clone().to_vec(),
                sign2.clone(),
                user_keypair.public.clone(),
            );

            let recover = extract_users_private_key_hash(
                hash1.clone().to_vec(),
                hash2.clone().to_vec(),
                param.clone(),
                sign1,
                sign2,
                attacker_keypair.clone(),
                user_keypair.public.clone(),
            )
            .unwrap();
        }
    }
    #[test]
    fn test_old_time() {
        let message1 = "hello";
        let message2 = "hello, again";
        let mut hasher = Keccak256::new();
        let param = Param::new();
        let user_keypair = KeyPair::new(Scalar::random());
        let attacker_keypair = KeyPair::new(Scalar::random());
        Digest::update(&mut hasher, message1.as_bytes());
        let hash1 = hasher.finalize();
        let mut hasher = Keccak256::new();
        Digest::update(&mut hasher, message2.as_bytes());
        let hash2 = hasher.finalize();

        for i in 0..255 {
            let sign1 = sign_hash(
                hash1.clone().to_vec(),
                user_keypair.clone(),
                Scalar::random(),
            )
            .unwrap();
            let sign2 = sign_hash(
                hash2.clone().to_vec(),
                user_keypair.clone(),
                Scalar::random(),
            )
            .unwrap();
            verify_hash(hash1.clone().to_vec(), sign1, user_keypair.public.clone());
            verify_hash(hash1.clone().to_vec(), sign2, user_keypair.public.clone());
        }
    }
    #[test]
    fn test_message_string() {
        let hash1 = Vec::from(rand_block());
        let hash2 = fast_hash(&hash1);
        let param = generate_param(hash1.clone());
        let keypair1 = KeyPair::new(Scalar::random());
        let keypair2 = KeyPair::new(Scalar::random());
        let [sign1, sign2] = mal_sign_hash(
            hash1.clone(),
            hash2.clone(),
            param,
            keypair1.clone(),
            keypair2.public.clone(),
        )
        .unwrap();
        let kle = Kle::from(keypair1.public.clone(), hash1, hash2, sign1.clone(), sign2);
        let mut string = serde_json::to_string(&kle).unwrap();
        string.push_str(&serde_json::to_string(&sign1).unwrap());
        println!("{}", string);
    }
}
