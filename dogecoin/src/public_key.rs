use crate::address::DogecoinAddress;
use crate::format::DogecoinFormat;
use crate::network::DogecoinNetwork;
use crate::private_key::DogecoinPrivateKey;
use wagyu_model::{Address, AddressError, PublicKey, PublicKeyError};

use core::{fmt, fmt::Display, marker::PhantomData, str::FromStr};
use secp256k1;

/// Represents a Dogecoin public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DogecoinPublicKey<N: DogecoinNetwork> {
    /// The ECDSA public key
    public_key: secp256k1::PublicKey,
    /// If true, the public key is serialized in compressed form
    compressed: bool,
    /// PhantomData
    _network: PhantomData<N>,
}

impl<N: DogecoinNetwork> PublicKey for DogecoinPublicKey<N> {
    type Address = DogecoinAddress<N>;
    type Format = DogecoinFormat;
    type PrivateKey = DogecoinPrivateKey<N>;

    /// Returns the address corresponding to the given public key.
    fn from_private_key(private_key: &Self::PrivateKey) -> Self {
        Self {
            public_key: secp256k1::PublicKey::from_secret_key(&private_key.to_secp256k1_secret_key()),
            compressed: private_key.is_compressed(),
            _network: PhantomData,
        }
    }

    /// Returns the address of the corresponding private key.
    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        Self::Address::from_public_key(self, format)
    }
}

impl<N: DogecoinNetwork> DogecoinPublicKey<N> {
    /// Returns a public key given a secp256k1 public key.
    pub fn from_secp256k1_public_key(public_key: secp256k1::PublicKey, compressed: bool) -> Self {
        Self {
            public_key,
            compressed,
            _network: PhantomData,
        }
    }

    /// Returns the secp256k1 public key of the public key.
    pub fn to_secp256k1_public_key(&self) -> secp256k1::PublicKey {
        self.public_key.clone()
    }

    /// Returns `true` if the public key is in compressed form.
    pub fn is_compressed(&self) -> bool {
        self.compressed
    }
}

impl<N: DogecoinNetwork> FromStr for DogecoinPublicKey<N> {
    type Err = PublicKeyError;

    fn from_str(public_key: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            public_key: secp256k1::PublicKey::parse_slice(&hex::decode(public_key)?, None)?,
            compressed: public_key.len() == 66,
            _network: PhantomData,
        })
    }
}

impl<N: DogecoinNetwork> Display for DogecoinPublicKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.compressed {
            for s in &self.public_key.serialize_compressed()[..] {
                write!(f, "{:02x}", s)?;
            }
        } else {
            for s in &self.public_key.serialize()[..] {
                write!(f, "{:02x}", s)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::*;

    fn test_from_private_key<N: DogecoinNetwork>(
        expected_public_key: &DogecoinPublicKey<N>,
        private_key: &DogecoinPrivateKey<N>,
    ) {
        let public_key = DogecoinPublicKey::from_private_key(private_key);
        assert_eq!(*expected_public_key, public_key);
    }

    fn test_to_address<N: DogecoinNetwork>(
        expected_address: &DogecoinAddress<N>,
        expected_format: &DogecoinFormat,
        public_key: &DogecoinPublicKey<N>,
    ) {
        let address = public_key.to_address(expected_format).unwrap();
        assert_eq!(*expected_address, address);
    }

    fn test_from_str<N: DogecoinNetwork>(
        expected_public_key: &str,
        expected_address: &str,
        expected_compressed: bool,
        expected_format: &DogecoinFormat,
    ) {
        let public_key = DogecoinPublicKey::<N>::from_str(expected_public_key).unwrap();
        let address = public_key.to_address(expected_format).unwrap();
        assert_eq!(expected_public_key, public_key.to_string());
        assert_eq!(expected_compressed, public_key.compressed);
        assert_eq!(expected_address, address.to_string());
        assert_eq!(*expected_format, address.format());
    }

    fn test_to_str<N: DogecoinNetwork>(expected_public_key: &str, public_key: &DogecoinPublicKey<N>) {
        assert_eq!(expected_public_key, public_key.to_string());
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
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = DogecoinPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                test_from_private_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(_, public_key, address)| {
                let address = DogecoinAddress::<N>::from_str(address).unwrap();
                let public_key = DogecoinPublicKey::<N>::from_str(&public_key).unwrap();
                test_to_address(&address, &DogecoinFormat::P2PKH, &public_key);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, expected_address)| {
                test_from_str::<N>(expected_public_key, expected_address, true, &DogecoinFormat::P2PKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, _)| {
                let public_key = DogecoinPublicKey::<N>::from_str(expected_public_key).unwrap();
                test_to_str(expected_public_key, &public_key);
            });
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
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = DogecoinPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                test_from_private_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(_, public_key, address)| {
                let address = DogecoinAddress::<N>::from_str(address).unwrap();
                let public_key = DogecoinPublicKey::<N>::from_str(&public_key).unwrap();
                test_to_address(&address, &DogecoinFormat::P2PKH, &public_key);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, expected_address)| {
                test_from_str::<N>(expected_public_key, expected_address, false, &DogecoinFormat::P2PKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, _)| {
                let public_key = DogecoinPublicKey::<N>::from_str(expected_public_key).unwrap();
                test_to_str(expected_public_key, &public_key);
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
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, public_key, _)| {
                let public_key = DogecoinPublicKey::<N>::from_str(public_key).unwrap();
                let private_key = DogecoinPrivateKey::<N>::from_str(&private_key).unwrap();
                test_from_private_key(&public_key, &private_key);
            });
        }

        #[test]
        fn to_address() {
            KEYPAIRS.iter().for_each(|(_, public_key, address)| {
                let address = DogecoinAddress::<N>::from_str(address).unwrap();
                let public_key = DogecoinPublicKey::<N>::from_str(&public_key).unwrap();
                test_to_address(&address, &DogecoinFormat::P2SH_P2WPKH, &public_key);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, expected_address)| {
                test_from_str::<N>(expected_public_key, expected_address, true, &DogecoinFormat::P2SH_P2WPKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_public_key, _)| {
                let public_key = DogecoinPublicKey::<N>::from_str(expected_public_key).unwrap();
                test_to_str(expected_public_key, &public_key);
            });
        }
    }

    #[test]
    fn test_p2pkh_invalid() {
        type N = Mainnet;

        // Invalid public key length

        let public_key = "0";
        assert!(DogecoinPublicKey::<N>::from_str(public_key).is_err());

        let public_key = "039ed714bf521e96e3f3609b74da898e44";
        assert!(DogecoinPublicKey::<N>::from_str(public_key).is_err());

        let public_key = "039ed714bf521e96e3f3609b74da898e44d0fb64ba68c62c57852470ffc28e3db";
        assert!(DogecoinPublicKey::<N>::from_str(public_key).is_err());

        let public_key =
            "039ed714bf521e96e3f3609b74da898e44d0fb64ba68c62c57852470ffc28e3db5039ed714bf521e96e3f3609b74da898e44";
        assert!(DogecoinPublicKey::<N>::from_str(public_key).is_err());

        let public_key = "039ed714bf521e96e3f3609b74da898e44d0fb64ba68c62c57852470ffc28e3db5039ed714bf521e96e3f3609b74da898e44d0fb64ba68c62c57852470ffc28e3db5";
        assert!(DogecoinPublicKey::<N>::from_str(public_key).is_err());
    }

    #[test]
    fn test_p2sh_p2wpkh_invalid() {
        type N = Mainnet;

        // Invalid public key length

        let public_key = "0";
        assert!(DogecoinPublicKey::<N>::from_str(public_key).is_err());

        let public_key = "02468791fee1444df3a6e786e2f9da79198";
        assert!(DogecoinPublicKey::<N>::from_str(public_key).is_err());

        let public_key = "02468791fee1444df3a6e786e2f9da79198f8902387e1fa5a2c051950c4df51ab";
        assert!(DogecoinPublicKey::<N>::from_str(public_key).is_err());

        let public_key =
            "02468791fee1444df3a6e786e2f9da79198f8902387e1fa5a2c051950c4df51ab402468791fee1444df3a6e786e2f9da79198";
        assert!(DogecoinPublicKey::<N>::from_str(public_key).is_err());

        let public_key = "02468791fee1444df3a6e786e2f9da79198f8902387e1fa5a2c051950c4df51ab402468791fee1444df3a6e786e2f9da79198f8902387e1fa5a2c051950c4df51ab4";
        assert!(DogecoinPublicKey::<N>::from_str(public_key).is_err());
    }
}
