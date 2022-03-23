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
        pub fn from(
            a: Scalar<Secp256k1>,
            b: Scalar<Secp256k1>,
            h: Scalar<Secp256k1>,
            e: Scalar<Secp256k1>,
        ) -> Self {
            Param { a, b, h, e }
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

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Packet {
        hash: Vec<u8>,
        sign: Signature,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct PacketMessage {
        hash: String,
        r: String,
        s: String,
        v: String,
    }

    impl PacketMessage {
        pub fn from(packet: Packet) -> Self {
            let hash = hex::encode(&packet.hash);
            let r = packet.sign.r.to_bigint().to_hex();
            let s = packet.sign.s.to_bigint().to_hex();
            let v = packet.sign.v.to_hex();
            PacketMessage { hash, r, s, v }
        }
    }
    impl Packet {
        pub fn from(hash: Vec<u8>, sign: Signature) -> Self {
            Packet { hash, sign }
        }
    }

    // fast hash function using Keccak256
    pub fn fast_hash(data: &[u8]) -> Vec<u8> {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        Digest::update(&mut hasher, data);
        Vec::from(hasher.finalize().as_slice())
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

    // client send (ck2.public + random)
    pub fn client_step1(public: Point<Secp256k1>, stream: &mut TcpStream) -> std::io::Result<()> {
        let mut bytes = public.to_bytes(false).to_vec();
        let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
        bytes.extend_from_slice(&random_bytes);
        let mut writer = BufWriter::new(stream.try_clone().unwrap());
        writer.write(&bytes).unwrap();
        writer.flush()
    }

    // server return (sk2.public + sig(sk2.public + random))
    // sk1: const
    // sk2: dyn
    pub fn server_step1(
        stream: &mut TcpStream,
        sk1: KeyPair,
        sk2: KeyPair,
        random: [u8; 32],
    ) -> std::io::Result<()> {
        // bytes = sk2.public
        let mut bytes = sk2.public.to_bytes(false).to_vec();
        // sign_data = sk2.public+random
        let mut sign_data = bytes.clone();
        sign_data.extend_from_slice(&random);
        // sign_string = sig(sk2.public+random)
        let sign = sign_hash(fast_hash(&sign_data), sk1, Scalar::random()).unwrap();
        let sign_string = serde_json::to_string(&sign).unwrap();

        let mut writer = BufWriter::new(stream.try_clone().unwrap());
        writer.write(&bytes).unwrap();
        writer.write(sign_string.as_bytes()).unwrap();
        writer.flush()
    }

    // server send (hash1, sig1, hash2, sig2)
    // sign json string end with 92, 125
    pub fn server_step2(
        param: Param,
        stream: &mut TcpStream,
        sk2: KeyPair,
        ck2: KeyPair,
    ) -> std::io::Result<()> {
        let mut rng = rand::thread_rng();
        let mut hash1: [u8; 32] = [0; 32];
        let mut hash2: [u8; 32] = [0; 32];
        rng.fill_bytes(&mut hash1[..]);
        rng.fill_bytes(&mut hash2[..]);

        let mut buffer = Vec::new();
        buffer.extend_from_slice(&hash1);
        buffer.extend_from_slice(&hash2);

        let [sign1, sign2] = mal_sign_hash(
            Vec::from(hash1),
            Vec::from(hash2),
            param,
            sk2,
            ck2.public.clone(),
        )
        .unwrap();
        buffer.extend_from_slice(serde_json::to_string(&sign1).unwrap().as_bytes());
        buffer.extend_from_slice(serde_json::to_string(&sign2).unwrap().as_bytes());

        let mut writer = BufWriter::new(stream.try_clone().unwrap());
        writer.write(&buffer).unwrap();
        writer.flush()
    }

    pub fn rand_block() -> [u8; 16] {
        let mut rng = rand::thread_rng();
        let mut block: [u8; 16] = [0; 16];
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
    use crate::protocol::{fast_hash, PacketMessage};
    use crate::protocol::{public_to_hex, Packet};
    use rand::RngCore;
    use sha3::digest::DynDigest;
    use sha3::{Digest, Keccak256};

    #[test]
    fn test_struct() {
        let hash = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let sign = Signature::new();
        let packet = Packet::from(hash, sign);
        let packet_message = PacketMessage::from(packet);
        println!("{}", serde_json::to_string(&packet_message).unwrap());
        let G: Point<Secp256k1> = Point::generator() * Scalar::from(1);
        println!("{}", public_to_hex(G));
        let keypair = KeyPair::new(Scalar::random());
        println!("{}", public_to_hex(keypair.public));
    }
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

    use libsm::sm4::{Cipher, Mode};

    fn rand_block() -> [u8; 16] {
        let mut rng = rand::thread_rng();
        let mut block: [u8; 16] = [0; 16];
        rng.fill_bytes(&mut block[..]);
        block
    }
    #[test]
    fn test_sign_string() {
        let hash = fast_hash(&rand_block());
        let keypair = KeyPair::new(Scalar::random());
        let sign = sign_hash(Vec::from(hash), keypair, Scalar::random()).unwrap();
        println!("{}", serde_json::to_string(&sign).unwrap());
        println!("{:?}", serde_json::to_string(&sign).unwrap().as_bytes());
    }
}
