use crate::address::DogecoinAddress;
use crate::format::DogecoinFormat;
use crate::network::DogecoinNetwork;
use crate::public_key::DogecoinPublicKey;
use wagyu_model::{crypto::checksum, Address, AddressError, PrivateKey, PrivateKeyError, PublicKey};

use base58::{FromBase58, ToBase58};
use core::{fmt, fmt::Display, marker::PhantomData, str::FromStr};
use rand::Rng;
use secp256k1;

/// Represents a Dogecoin private key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DogecoinPrivateKey<N: DogecoinNetwork> {
    /// The ECDSA private key
    secret_key: secp256k1::SecretKey,
    /// If true, the private key is serialized in compressed form
    compressed: bool,
    /// PhantomData
    _network: PhantomData<N>,
}

impl<N: DogecoinNetwork> PrivateKey for DogecoinPrivateKey<N> {
    type Address = DogecoinAddress<N>;
    type Format = DogecoinFormat;
    type PublicKey = DogecoinPublicKey<N>;

    /// Returns a randomly-generated compressed Dogecoin private key.
    fn new<R: Rng>(rng: &mut R) -> Result<Self, PrivateKeyError> {
        Ok(Self {
            secret_key: secp256k1::SecretKey::random(rng),
            compressed: true,
            _network: PhantomData,
        })
    }

    /// Returns the public key of the corresponding Dogecoin private key.
    fn to_public_key(&self) -> Self::PublicKey {
        Self::PublicKey::from_private_key(self)
    }

    /// Returns the address of the corresponding Dogecoin private key.
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        Self::Address::from_private_key(self, format)
    }
}

impl<N: DogecoinNetwork> DogecoinPrivateKey<N> {
    /// Returns a private key given a secp256k1 secret key.
    pub fn from_secp256k1_secret_key(secret_key: &secp256k1::SecretKey, compressed: bool) -> Self {
        Self {
            secret_key: secret_key.clone(),
            compressed,
            _network: PhantomData,
        }
    }

    /// Returns the secp256k1 secret key of the private key.
    pub fn to_secp256k1_secret_key(&self) -> secp256k1::SecretKey {
        self.secret_key.clone()
    }

    /// Returns `true` if the private key is in compressed form.
    pub fn is_compressed(&self) -> bool {
        self.compressed
    }
}

impl<N: DogecoinNetwork> FromStr for DogecoinPrivateKey<N> {
    type Err = PrivateKeyError;

    /// Returns a Dogecoin private key from a given WIF.
    fn from_str(wif: &str) -> Result<Self, Self::Err> {
        let data = wif.from_base58()?;
        let len = data.len();
        if len != 37 && len != 38 {
            return Err(PrivateKeyError::InvalidByteLength(len));
        }

        let expected = &data[len - 4..len];
        let checksum = &checksum(&data[0..len - 4])[0..4];
        if *expected != *checksum {
            let expected = expected.to_base58();
            let found = checksum.to_base58();
            return Err(PrivateKeyError::InvalidChecksum(expected, found));
        }

        // Check that the wif prefix corresponds to the correct network.
        let _ = N::from_private_key_prefix(data[0])?;

        Ok(Self {
            secret_key: secp256k1::SecretKey::parse_slice(&data[1..33])?,
            compressed: len == 38,
            _network: PhantomData,
        })
    }
}

impl<N: DogecoinNetwork> Display for DogecoinPrivateKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut wif = [0u8; 38];
        wif[0] = N::to_private_key_prefix();
        wif[1..33].copy_from_slice(&self.secret_key.serialize());

        let output = if self.compressed {
            wif[33] = 0x01;
            let sum = &checksum(&wif[0..34])[0..4];
            wif[34..].copy_from_slice(sum);
            wif.to_base58()
        } else {
            let sum = &checksum(&wif[0..33])[0..4];
            wif[33..37].copy_from_slice(sum);
            wif[..37].to_base58()
        };

        write!(f, "{}", output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::*;

    fn test_to_public_key<N: DogecoinNetwork>(
        expected_public_key: &DogecoinPublicKey<N>,
        private_key: &DogecoinPrivateKey<N>,
    ) {
        let public_key = private_key.to_public_key();
        assert_eq!(*expected_public_key, public_key);
    }

    fn test_to_address<N: DogecoinNetwork>(
        expected_address: &DogecoinAddress<N>,
        expected_format: &DogecoinFormat,
        private_key: &DogecoinPrivateKey<N>,
    ) {
        let address = private_key.to_address(expected_format).unwrap();
        assert_eq!(*expected_address, address);
    }

    fn test_from_secp256k1_secret_key<N: DogecoinNetwork>(
        expected_wif: &str,
        expected_compressed: bool,
        expected_public_key: &str,
        expected_address: &str,
        expected_format: &DogecoinFormat,
        secret_key: secp256k1::SecretKey,
        compressed: bool,
    ) {
        let private_key = DogecoinPrivateKey::<N>::from_secp256k1_secret_key(&secret_key, compressed);
        assert_eq!(expected_wif, private_key.to_string());
        assert_eq!(secret_key, private_key.secret_key);
        assert_eq!(expected_compressed, private_key.compressed);
        assert_eq!(expected_public_key, private_key.to_public_key().to_string());
        assert_eq!(
            expected_address,
            private_key.to_address(expected_format).unwrap().to_string()
        );
    }

    fn test_from_str<N: DogecoinNetwork>(
        expected_secret_key: &secp256k1::SecretKey,
        expected_compressed: bool,
        expected_public_key: &str,
        expected_address: &str,
        expected_format: &DogecoinFormat,
        wif: &str,
    ) {
        let private_key = DogecoinPrivateKey::<N>::from_str(wif).unwrap();
        assert_eq!(wif, private_key.to_string());
        assert_eq!(*expected_secret_key, private_key.secret_key);
        assert_eq!(expected_compressed, private_key.compressed);
        assert_eq!(expected_public_key, private_key.to_public_key().to_string());
        assert_eq!(
            expected_address,
            private_key.to_address(expected_format).unwrap().to_string()
        );
    }

    fn test_to_str<N: DogecoinNetwork>(expected_private_key: &str, private_key: &DogecoinPrivateKey<N>) {
        assert_eq!(expected_private_key, private_key.to_string());
    }

    mod p2pkh_mainnet_compressed {
        use super::*;

        type N = Mainnet;
        const KEYPAIRS: [(&str, &str, &str); 5] = [
            (
                "L5hax5dZaByC3kJ4aLrZgnMXGSQReqRDYNqM1VAeXpqDRkRjX42H",
                "039ed714bf521e96e3f3609b74da898e44d0fb64ba68c62c57852470ffc28e3db5",
                "1uNM6oivjCJU2RcsNbfooVwcPjDRhjW7U",
            ),
            (
                "L4uNhZS86VLiKKGZZGNxwP7s67EfYfQ7S9bNnVfVbU9GBVVo2xoD",
                "03a385ac59a31841764d55e7c8a243482a89073785524f0c45335afcf425d567b1",
                "16sz5SMFeRfwaqY6wKzkiufwPmF1J7RhAx",
            ),
            (
                "KyH2BrThuUnzSXxDrDxQbpK277HxZfwPxVaCs5cwbzDEVNno2nts",
                "028fa046ccfbb4ff134a5e0e8969d8085c6e2a1a52d793d351d4ddf02cd43d64b2",
                "17QAwDwsLpehmCqSQXdHZb8vpsYVDnX7ic",
            ),
            (
                "KxEqpgCMencSHwiCG6xix9teUrB7JQNy2c7LKU56fZKZtP46nEca",
                "02f7fb7e7d5dc97a5e1cd36b1ea3218234649f98f32cf08f45f8cd742860f676bf",
                "1ESGcxbb96gQmJuEQsSapdk1jH6JaEnbU9",
            ),
            (
                "L2gCQPMpS5PqGvcBFMtYRT5S5jAo6WaNL1aPLvY2JkykkKSkqtm5",
                "02aad3c8ee3dc6753a5284c97124f0047b2af0b91ba256b6262e07fcc2630f6b7f",
                "1MRCogND3SKqa4xRZNpSC6iQxtwCpvmzfE",
            ),
        ];

        #[test]
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = DogecoinPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(private_key, _, address)| {
                let address = DogecoinAddress::<N>::from_str(address).unwrap();
                let private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_address(&address, &DogecoinFormat::P2PKH, &private_key);
            });
        }

        #[test]
        fn from_secp256k1_secret_key() {
            KEYPAIRS
                .iter()
                .for_each(|(expected_private_key, expected_public_key, expected_address)| {
                    let private_key = DogecoinPrivateKey::<N>::from_str(&expected_private_key).unwrap();
                    test_from_secp256k1_secret_key::<N>(
                        expected_private_key,
                        true,
                        expected_public_key,
                        expected_address,
                        &DogecoinFormat::P2PKH,
                        private_key.secret_key,
                        true,
                    );
                });
        }

        #[test]
        fn from_str() {
            KEYPAIRS
                .iter()
                .for_each(|(private_key, expected_public_key, expected_address)| {
                    let expected_private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                    test_from_str::<N>(
                        &expected_private_key.secret_key,
                        true,
                        expected_public_key,
                        expected_address,
                        &DogecoinFormat::P2PKH,
                        &private_key,
                    );
                });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(expected_private_key, _, _)| {
                let private_key = DogecoinPrivateKey::<N>::from_str(expected_private_key).unwrap();
                test_to_str(expected_private_key, &private_key);
            });
        }

        #[test]
        fn test_invalid() {
            // Invalid WIF length

            let private_key = "L";
            assert!(DogecoinPrivateKey::<N>::from_str(private_key).is_err());

            let private_key = "L5hax5dZaByC3kJ4aLrZgnMXGSQReq";
            assert!(DogecoinPrivateKey::<N>::from_str(private_key).is_err());

            let private_key = "L5hax5dZaByC3kJ4aLrZgnMXGSQReqRDYNqM1VAeXpqDRkRjX42";
            assert!(DogecoinPrivateKey::<N>::from_str(private_key).is_err());

            let private_key = "L5hax5dZaByC3kJ4aLrZgnMXGSQReqRDYNqM1VAeXpqDRkRjX42HL5hax5dZaByC3kJ4aLrZgnMXGSQ";
            assert!(DogecoinPrivateKey::<N>::from_str(private_key).is_err());

            let private_key = "L5hax5dZaByC3kJ4aLrZgnMXGSQReqRDYNqM1VAeXpqDRkRjX42HL5hax5dZaByC3kJ4aLrZgnMXGSQReqRDYNqM1VAeXpqDRkRjX42H";
            assert!(DogecoinPrivateKey::<N>::from_str(private_key).is_err());
        }
    }

    mod p2pkh_mainnet_uncompressed {
        use super::*;

        type N = Mainnet;
        const KEYPAIRS: [(&str, &str, &str); 5] = [
            (
                "5KV26gjX4sYAkXvDnqZZuEyFUh1DKjgZ8wTKL7Fpm4ppJ8kpZQu",
                "0489efe59c51e542f4cc7e2464ba3835d0a1a3daf351e70db57053c4712aca58796a933d1331078c364b94dd53aba2357a01f446c22efedcea8ebce2167a9e1df8",
                "1KGHasyEpQZSHLea2GV3taTFZcw3uP7AAJ"
            ),
            (
                "5JUfnMYvM4g94psa1p2MUfQptbiouXYbb5oskjY7mZ151rXDFTi",
                "04cf0ead0ea5df0700a4f063edf40397b377147d99f8f9404606e80dd931c819d2b571ab64754d27e69de5226f316e2dcab9f8b3b706d08104bcfe06f0e6dc7ff3",
                "1Ja8ReiHyPwNdWHZdJZVN9ZV6cNzC8DbTy"
            ),
            (
                "5K2enrnWqJcQuHLeijT76YEqDagWo3cQLnPYk2CezrJ7A61QG5y",
                "04a215f5764beef937296f6797407e51b8823eb418c3d65f48c0950ee775504c3539ca06ef419c7c70cbdf30930c25b5abb8040a89e089b786363c2bd78a07f464",
                "1PvWPvCZV4mQACqXp3AsFvQHtyfq2eZG9c"
            ),
            (
                "5JnV7DtVZvwbVeRLvXQSzyg5WxMYJMEQbJk8VoYhzDTz4tawudY",
                "04005e271fa3305bac32c5951fb84b35303b1231817e538aa5af6b145faae409a01f9e8c0330f4901577aacd43682fe2af39e69dcfaa7cff7390c006b3b66e90ad",
                "1FCHrsTrzxJy3sq1pQKLBQojuvYyMBzs4g"
            ),
            (
                "5KVeWqioENjhaYZqXZX4nEfwEysJjXEvYfaeQx4pM2HK51ZW7Ur",
                "04b6c8c8a6e9ad27366d8e6a0fa6c11f15ad7a8f15ac0c1d38c714df1f6b00b102773c7ebb0d718fc93808fdaf6c6b4ff6213909d50a94d5d6c8b472a9d1f30d99",
                "1Hb6umXZs26hUZMt59nbkTAAfMpsmTkCBs"
            )
        ];

        #[test]
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = DogecoinPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(private_key, _, address)| {
                let address = DogecoinAddress::<N>::from_str(address).unwrap();
                let private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_address(&address, &DogecoinFormat::P2PKH, &private_key);
            });
        }

        #[test]
        fn from_secp256k1_secret_key() {
            KEYPAIRS
                .iter()
                .for_each(|(expected_private_key, expected_public_key, expected_address)| {
                    let private_key = DogecoinPrivateKey::<N>::from_str(&expected_private_key).unwrap();
                    test_from_secp256k1_secret_key::<N>(
                        expected_private_key,
                        false,
                        expected_public_key,
                        expected_address,
                        &DogecoinFormat::P2PKH,
                        private_key.secret_key,
                        false,
                    );
                });
        }

        #[test]
        fn from_str() {
            KEYPAIRS
                .iter()
                .for_each(|(private_key, expected_public_key, expected_address)| {
                    let expected_private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                    test_from_str::<N>(
                        &expected_private_key.secret_key,
                        false,
                        expected_public_key,
                        expected_address,
                        &DogecoinFormat::P2PKH,
                        &private_key,
                    );
                });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(expected_private_key, _, _)| {
                let private_key = DogecoinPrivateKey::<N>::from_str(expected_private_key).unwrap();
                test_to_str(expected_private_key, &private_key);
            });
        }
    }

    mod p2pkh_testnet_compressed {
        use super::*;

        type N = Testnet;
        const KEYPAIRS: [(&str, &str, &str); 5] = [
            (
                "cNB6GpygWSZNRG5hotKjdAaNfgrzx984QYb2uj9rHpaCDkyy2aAz",
                "02bc25a326a8fa59edd1a2adff51956ea3c61f404cff6e926225b3fe3b303561ac",
                "mkerhifaLqJgAgrAjLomUStznPgVewNkka",
            ),
            (
                "cW4GQXEykwWJHVfRH8u25MzpzaU5XQDekdpdQbj9f9V7PLm25m4n",
                "02e21263a700b22c16088dc45fb10d38cc8c4ebb4cdcb612e6551d972b60aa2446",
                "n3NUsMjN3D6EWZ5nKZLvHnVwaAxfybQDq9",
            ),
            (
                "cSA6Mo1PYYK2uaDH22KoreQZdkSLobcrxZwnLcotDiYocCSjCVXy",
                "0355210590fbe6dcb663c6166cd5cb169169e0d4bac76ce78d4ac29ddf683b2541",
                "mzt1DhTJMzXarvJukPUxnfA1syVhDuZapf",
            ),
            (
                "cUVDoLpgXFYZGmjoyMusNEZJ174wk8ggjyH2Uo7L5nB1w5werAjX",
                "0259b863ba239379d6ebee4074b6f9c9f7f23a581ff529aa8d1431d94cb2f3cd99",
                "mxe1oRLS21dEqt6H77GPGUx59Zj4ucUBbc",
            ),
            (
                "cRhBWs3Bg9oXERSEY8GLaZjN7eb1FmkCnRdmwjCG2pVXVPUqXNiT",
                "02826afccd44e32a9542f72a3a7753b99dbaf4a800bb70b6155510b1ce7a4bf607",
                "mpvYGW4UNjYRaQ1adpE8ThYNXCVkWjhAPb",
            ),
        ];

        #[test]
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = DogecoinPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(private_key, _, address)| {
                let address = DogecoinAddress::<N>::from_str(address).unwrap();
                let private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_address(&address, &DogecoinFormat::P2PKH, &private_key);
            });
        }

        #[test]
        fn from_secp256k1_secret_key() {
            KEYPAIRS
                .iter()
                .for_each(|(expected_private_key, expected_public_key, expected_address)| {
                    let private_key = DogecoinPrivateKey::<N>::from_str(&expected_private_key).unwrap();
                    test_from_secp256k1_secret_key::<N>(
                        expected_private_key,
                        true,
                        expected_public_key,
                        expected_address,
                        &DogecoinFormat::P2PKH,
                        private_key.secret_key,
                        true,
                    );
                });
        }

        #[test]
        fn from_str() {
            KEYPAIRS
                .iter()
                .for_each(|(private_key, expected_public_key, expected_address)| {
                    let expected_private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                    test_from_str::<N>(
                        &expected_private_key.secret_key,
                        true,
                        expected_public_key,
                        expected_address,
                        &DogecoinFormat::P2PKH,
                        &private_key,
                    );
                });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(expected_private_key, _, _)| {
                let private_key = DogecoinPrivateKey::<N>::from_str(expected_private_key).unwrap();
                test_to_str(expected_private_key, &private_key);
            });
        }
    }

    mod p2pkh_testnet_uncompressed {
        use super::*;

        type N = Testnet;
        const KEYPAIRS: [(&str, &str, &str); 5] = [
            (
                "93W1kMkD1kAfevtDQ3LWortt8zjKqSSqonLxPvWFqg57arcwUru",
                "048bb370869871417660abdacebf25f786e69c6e861b1c11346071cc9ad69690c2dc19fd3965455afc9a662feef3432b88cc99e31fa30ba93993ca21322e43e894",
                "n4jx6NanXkXu7XSZrXBMKsFccxcp35UtJv"
            ),
            (
                "92FshhFbVnbtpbvpdzGmKEnNkToJnvm6L45LhDQqn1Kxjp8d4oR",
                "04092301037dc083952053ccd320b5e12b30839fa0380d8a2c27547de4a527806962c5d1efc9e748cf6003fcc7ff0784caee9fa36d9b7ea330a613e4b71f8df0f9",
                "n47WkmoSwebNXyvbkRdubZmFbGm5SbKh1A"
            ),
            (
                "92PbnSrnyLzS2HBNy4Vh2zg9hkVrztdxxDFihz92rBDyX25xF8N",
                "043e8f6512364e73a695f2b14b284a1c58ca9cbac2d8dd7dcf15f135260e87f1d0f89270f5a8d76b4e611861d68c955dc1524df4c20bb080bf0c0f536383379f91",
                "n3TWdpM742F8mxkcWQw8h2cifxyy82V2ov"
            ),
            (
                "92SbtaaCwUuHmzYGdi9xp5GbfUivbLHTAkqxeWaX88E1Q9HZJfs",
                "0402acd5144558b5e779dead4c9e9b733e00b6e0554a243433bfccc730923a0beacd93f2b73c75f67d65fb830bde1cf101a8daea12ee3b659ef31fa274f52435d0",
                "muFcYctkUkfWW55n2GMUafkw71kbZuduNv"
            ),
            (
                "91sSacE166SmPMoysEfZrQmM9aHgSfZbEfjmMf6nY8qBgvQMB1i",
                "04c8d1e7d88969b4345c874f50af41b8d310dd666c0a3df52c46c238a345fbda73165fccdedffb67390e87e81040bff8415b8d7c5a6bbc441c89841cb74012501d",
                "mwSgCKvDt3SoBxa3RZB1kXbxzX3oMvXxvT"
            )
        ];

        #[test]
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = DogecoinPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(private_key, _, address)| {
                let address = DogecoinAddress::<N>::from_str(address).unwrap();
                let private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_address(&address, &DogecoinFormat::P2PKH, &private_key);
            });
        }

        #[test]
        fn from_secp256k1_secret_key() {
            KEYPAIRS
                .iter()
                .for_each(|(expected_private_key, expected_public_key, expected_address)| {
                    let private_key = DogecoinPrivateKey::<N>::from_str(&expected_private_key).unwrap();
                    test_from_secp256k1_secret_key::<N>(
                        expected_private_key,
                        false,
                        expected_public_key,
                        expected_address,
                        &DogecoinFormat::P2PKH,
                        private_key.secret_key,
                        false,
                    );
                });
        }

        #[test]
        fn from_str() {
            KEYPAIRS
                .iter()
                .for_each(|(private_key, expected_public_key, expected_address)| {
                    let expected_private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                    test_from_str::<N>(
                        &expected_private_key.secret_key,
                        false,
                        expected_public_key,
                        expected_address,
                        &DogecoinFormat::P2PKH,
                        &private_key,
                    );
                });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(expected_private_key, _, _)| {
                let private_key = DogecoinPrivateKey::<N>::from_str(expected_private_key).unwrap();
                test_to_str(expected_private_key, &private_key);
            });
        }
    }

    mod p2sh_p2wpkh_mainnet {
        use super::*;

        type N = Mainnet;
        const KEYPAIRS: [(&str, &str, &str); 5] = [
            (
                "KyTx39W9vjeGRRjvZna5bbFGEpuih9pG5KBnxUJN7bChpGHHZuJN",
                "02468791fee1444df3a6e786e2f9da79198f8902387e1fa5a2c051950c4df51ab4",
                "3QKTruktKRSmY3QfhoijwT1BU1npSGMQPG",
            ),
            (
                "L4EYurAwjsXiQrZ9XWdWdf5LDVAGAwGW58LtgZhGtR1cXUjS8oWD",
                "024a185e896e5cf4cb0b441a18b5eac1a682e1848731449a5bb4c4a55c6d0fac3f",
                "3JU5wvE4YrpZ5CgwpALBJB1C4YJjuZjXhj",
            ),
            (
                "KyMSREGeHw2fnaRhTn1Cq9HYot9QR9AyUX6z8RbRF5Zr98qdmTjJ",
                "0337893947d9738d6d026bd5fa86d3c563ebc5840916d0ea50b143a83db7ef9de7",
                "3NzBJJPE3gaq5T9bmLJR4iHhmSHTgJdus4",
            ),
            (
                "L5DtYc8LkDBQWWUAsWcgQZZqpVfUYCLyHZveGXKGT2hCS4pnnmqp",
                "03eb86647457f2dfda66e7574d26cc4a6ecca472bc2ff331f333eb21614a0c58ee",
                "3JUHwBJu1Figs4FesZPCgfBQKJC4GHjwPa",
            ),
            (
                "L4GoufTyWZoy1WDzRDacywokD28C7amVH9Jyfsyr8XZpR8Pog7gK",
                "025195d4c21c7001103649f0bfb37f61a0da1e345e5847b005dbd10f0b7b7f9e6f",
                "3L6rBuHhf3MzY1qEXMxeyY18bo8H8uKb4D",
            ),
        ];

        #[test]
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = DogecoinPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(private_key, _, address)| {
                let address = DogecoinAddress::<N>::from_str(address).unwrap();
                let private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_address(&address, &DogecoinFormat::P2SH_P2WPKH, &private_key);
            });
        }

        #[test]
        fn from_secp256k1_secret_key() {
            KEYPAIRS
                .iter()
                .for_each(|(expected_private_key, expected_public_key, expected_address)| {
                    let private_key = DogecoinPrivateKey::<N>::from_str(&expected_private_key).unwrap();
                    test_from_secp256k1_secret_key::<N>(
                        expected_private_key,
                        true,
                        expected_public_key,
                        expected_address,
                        &DogecoinFormat::P2SH_P2WPKH,
                        private_key.secret_key,
                        true,
                    );
                });
        }

        #[test]
        fn from_str() {
            KEYPAIRS
                .iter()
                .for_each(|(private_key, expected_public_key, expected_address)| {
                    let expected_private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                    test_from_str::<N>(
                        &expected_private_key.secret_key,
                        true,
                        expected_public_key,
                        expected_address,
                        &DogecoinFormat::P2SH_P2WPKH,
                        &private_key,
                    );
                });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(expected_private_key, _, _)| {
                let private_key = DogecoinPrivateKey::<N>::from_str(expected_private_key).unwrap();
                test_to_str(expected_private_key, &private_key);
            });
        }

        #[test]
        fn test_invalid() {
            // Invalid WIF length

            let private_key = "K";
            assert!(DogecoinPrivateKey::<N>::from_str(private_key).is_err());

            let private_key = "KyTx39W9vjeGRRjvZna5bbFGEpuih";
            assert!(DogecoinPrivateKey::<N>::from_str(private_key).is_err());

            let private_key = "KyTx39W9vjeGRRjvZna5bbFGEpuih9pG5KBnxUJN7bChpGHHZuJ";
            assert!(DogecoinPrivateKey::<N>::from_str(private_key).is_err());

            let private_key = "KyTx39W9vjeGRRjvZna5bbFGEpuih9pG5KBnxUJN7bChpGHHZuJNKyTx39W9vjeGRRjvZna5bbFGE";
            assert!(DogecoinPrivateKey::<N>::from_str(private_key).is_err());

            let private_key = "KyTx39W9vjeGRRjvZna5bbFGEpuih9pG5KBnxUJN7bChpGHHZuJNKyTx39W9vjeGRRjvZna5bbFGEpuih9pG5KBnxUJN7bChpGHHZuJN";
            assert!(DogecoinPrivateKey::<N>::from_str(private_key).is_err());
        }
    }

    mod p2sh_p2wpkh_testnet {
        use super::*;

        type N = Testnet;
        const KEYPAIRS: [(&str, &str, &str); 5] = [
            (
                "cPYtDeoeHg3wXp7hzcZ8Bu51HtN74yNdSDtdRuXamKCyzvU2oQM2",
                "025718c5ebfbbb3566bf4757ca57822377eca9be9ace4d038052156dfe73f4c439",
                "2Mt46mJZ8i7x2eiN77MekrD4UJg6GFt9mUh",
            ),
            (
                "cMyPKTkYyhZS9cvrxkJZKFLEtqML6suBuDyZfFKXqGeHvnEPaD3x",
                "0236cd9b36cc3e08bf457ff6663b66d049ad942253d52bd5d939ea654d872bd5f3",
                "2MvRwrFLhxfwP96t6z6Th28No4Va19fogj3",
            ),
            (
                "cTWWzheif86K9fouCo5gg1G4pEdGbLRrnHbY3uRr6AmhjKwNUrGh",
                "021779b92c6a29c0bb554af8a059d51e08c900ca652fac13c1dab62da34016b722",
                "2N1STUKnC6atTS2JttzdbP1891sCrD5i6xu",
            ),
            (
                "cV2L63nMM3WZwrU9EKFFP218XAQBhsDmEQ9uTw3vhMAz25Gna9nF",
                "032a1af62e21831cc0951daf4f2e8f457bc59a4dc716e86f066b4de40020c9c8f1",
                "2N8mGnLgSL8GUyDELStD4YVGawdai52ax9q",
            ),
            (
                "cTB6EeZgiGCziMQycbUCbn25AkipGACtY1Lyd1rAhGnTPEwHSHQT",
                "027ebe9c4c3d976c490d34aad11d66558b052e6359925f8b33e51428dfdf59ad79",
                "2N2JVpNUWsnV4MZMF11ewG2BVjhHoVNkv6K",
            ),
        ];

        #[test]
        fn to_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = DogecoinPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_public_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(private_key, _, address)| {
                let address = DogecoinAddress::<N>::from_str(address).unwrap();
                let private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                test_to_address(&address, &DogecoinFormat::P2SH_P2WPKH, &private_key);
            });
        }

        #[test]
        fn from_secp256k1_secret_key() {
            KEYPAIRS
                .iter()
                .for_each(|(expected_private_key, expected_public_key, expected_address)| {
                    let private_key = DogecoinPrivateKey::<N>::from_str(&expected_private_key).unwrap();
                    test_from_secp256k1_secret_key::<N>(
                        expected_private_key,
                        true,
                        expected_public_key,
                        expected_address,
                        &DogecoinFormat::P2SH_P2WPKH,
                        private_key.secret_key,
                        true,
                    );
                });
        }

        #[test]
        fn from_str() {
            KEYPAIRS
                .iter()
                .for_each(|(private_key, expected_public_key, expected_address)| {
                    let expected_private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                    test_from_str::<N>(
                        &expected_private_key.secret_key,
                        true,
                        expected_public_key,
                        expected_address,
                        &DogecoinFormat::P2SH_P2WPKH,
                        &private_key,
                    );
                });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(expected_private_key, _, _)| {
                let private_key = DogecoinPrivateKey::<N>::from_str(expected_private_key).unwrap();
                test_to_str(expected_private_key, &private_key);
            });
        }
    }
}
