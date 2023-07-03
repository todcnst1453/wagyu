use crate::format::DogecoinFormat;
use crate::network::DogecoinNetwork;
use crate::private_key::DogecoinPrivateKey;
use crate::public_key::DogecoinPublicKey;
//use crate::witness_program::WitnessProgram;
use wagyu_model::no_std::*;
use wagyu_model::{
    crypto::{checksum, hash160},
    Address, AddressError, PrivateKey,
};

use base58::{FromBase58, ToBase58};
use core::{convert::TryFrom, fmt, marker::PhantomData, str::FromStr};
//use sha2::{Digest, Sha256};

/// Represents a Dogecoin address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DogecoinAddress<N: DogecoinNetwork> {
    /// The Dogecoin address
    address: String,
    /// The format of the address
    format: DogecoinFormat,
    /// PhantomData
    _network: PhantomData<N>,
}

impl<N: DogecoinNetwork> Address for DogecoinAddress<N> {
    type Format = DogecoinFormat;
    type PrivateKey = DogecoinPrivateKey<N>;
    type PublicKey = DogecoinPublicKey<N>;

    /// Returns the address corresponding to the given Dogecoin private key.
    fn from_private_key(private_key: &Self::PrivateKey, format: &Self::Format) -> Result<Self, AddressError> {
        let public_key = private_key.to_public_key();
        match format {
            DogecoinFormat::P2PKH => Self::p2pkh(&public_key),
            DogecoinFormat::P2WSH => {
                return Err(AddressError::IncompatibleFormats(
                    String::from("non-script"),
                    String::from("p2wsh address"),
                ))
            }
            DogecoinFormat::P2SH_P2WPKH => Self::p2sh_p2wpkh(&public_key),
        }
    }

    /// Returns the address corresponding to the given Dogecoin public key.
    fn from_public_key(public_key: &Self::PublicKey, format: &Self::Format) -> Result<Self, AddressError> {
        match format {
            DogecoinFormat::P2PKH => Self::p2pkh(public_key),
            DogecoinFormat::P2WSH => {
                return Err(AddressError::IncompatibleFormats(
                    String::from("non-script"),
                    String::from("p2wsh address"),
                ))
            }
            DogecoinFormat::P2SH_P2WPKH => Self::p2sh_p2wpkh(public_key),
        }
    }
}

impl<N: DogecoinNetwork> DogecoinAddress<N> {
    /// Returns a P2PKH address from a given Dogecoin public key.
    pub fn p2pkh(public_key: &<Self as Address>::PublicKey) -> Result<Self, AddressError> {
        let public_key = match public_key.is_compressed() {
            true => public_key.to_secp256k1_public_key().serialize_compressed().to_vec(),
            false => public_key.to_secp256k1_public_key().serialize().to_vec(),
        };

        let mut address = [0u8; 25];
        address[0] = N::to_address_prefix(&DogecoinFormat::P2PKH)[0];
        address[1..21].copy_from_slice(&hash160(&public_key));

        let sum = &checksum(&address[0..21])[0..4];
        address[21..25].copy_from_slice(sum);

        Ok(Self {
            address: address.to_base58(),
            format: DogecoinFormat::P2PKH,
            _network: PhantomData,
        })
    }

    // Returns a P2WSH address in Bech32 format from a given Bitcoin script
    pub fn p2wsh(original_script: &Vec<u8>) -> Result<Self, AddressError> {
        let mut address = [0u8; 25];
        address[0] = N::to_address_prefix(&DogecoinFormat::P2SH_P2WPKH)[0];
        address[1..21].copy_from_slice(&hash160(&original_script));

        let sum = &checksum(&address[0..21])[0..4];
        address[21..25].copy_from_slice(sum);

        Ok(Self {
            address: address.to_base58(),
            format: DogecoinFormat::P2SH_P2WPKH,
            _network: PhantomData,
        })
    }

    /// Returns a P2SH_P2WPKH address from a given Dogecoin public key.
    pub fn p2sh_p2wpkh(public_key: &<Self as Address>::PublicKey) -> Result<Self, AddressError> {
        let mut address = [0u8; 25];
        address[0] = N::to_address_prefix(&DogecoinFormat::P2SH_P2WPKH)[0];
        address[1..21].copy_from_slice(&hash160(&Self::create_redeem_script(public_key)));

        let sum = &checksum(&address[0..21])[0..4];
        address[21..25].copy_from_slice(sum);

        Ok(Self {
            address: address.to_base58(),
            format: DogecoinFormat::P2SH_P2WPKH,
            _network: PhantomData,
        })
    }

    /// Returns the format of the Dogecoin address.
    pub fn format(&self) -> DogecoinFormat {
        self.format.clone()
    }

    /// Returns a redeem script for a given Dogecoin public key.
    fn create_redeem_script(public_key: &<Self as Address>::PublicKey) -> [u8; 22] {
        let mut redeem = [0u8; 22];
        redeem[1] = 0x14;
        redeem[2..].copy_from_slice(&hash160(&public_key.to_secp256k1_public_key().serialize_compressed()));
        redeem
    }
}

impl<'a, N: DogecoinNetwork> TryFrom<&'a str> for DogecoinAddress<N> {
    type Error = AddressError;

    fn try_from(address: &'a str) -> Result<Self, Self::Error> {
        Self::from_str(address)
    }
}

impl<N: DogecoinNetwork> FromStr for DogecoinAddress<N> {
    type Err = AddressError;

    fn from_str(address: &str) -> Result<Self, Self::Err> {
        if address.len() < 14 || address.len() > 74 {
            return Err(AddressError::InvalidCharacterLength(address.len()));
        }

        let data = address.from_base58()?;
        if data.len() != 25 {
            return Err(AddressError::InvalidByteLength(data.len()));
        }

        // Check that the address prefix corresponds to the correct network.
        let _ = N::from_address_prefix(&data[0..2])?;
        let format = DogecoinFormat::from_address_prefix(&data[0..2])?;

        Ok(Self {
            address: address.into(),
            format,
            _network: PhantomData,
        })
    }
}

impl<N: DogecoinNetwork> fmt::Display for DogecoinAddress<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::*;
    use wagyu_model::public_key::PublicKey;

    fn test_from_private_key<N: DogecoinNetwork>(
        expected_address: &str,
        private_key: &DogecoinPrivateKey<N>,
        format: &DogecoinFormat,
    ) {
        let address = DogecoinAddress::from_private_key(private_key, format).unwrap();
        assert_eq!(expected_address, address.to_string());
    }

    fn test_from_public_key<N: DogecoinNetwork>(
        expected_address: &str,
        public_key: &DogecoinPublicKey<N>,
        format: &DogecoinFormat,
    ) {
        let address = DogecoinAddress::from_public_key(public_key, format).unwrap();
        assert_eq!(expected_address, address.to_string());
    }

    fn test_from_str<N: DogecoinNetwork>(expected_address: &str, expected_format: &DogecoinFormat) {
        let address = DogecoinAddress::<N>::from_str(expected_address).unwrap();
        assert_eq!(expected_address, address.to_string());
        assert_eq!(*expected_format, address.format);
    }

    fn test_to_str<N: DogecoinNetwork>(expected_address: &str, address: &DogecoinAddress<N>) {
        assert_eq!(expected_address, address.to_string());
    }

    mod p2pkh_mainnet_compressed {
        use super::*;

        type N = Mainnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "QRYeXExuXMbK31Pqi3MZ3Agn4rJMUMDLgzTPbeZA9kj9q6jzmhP9",
                "D5dtypj3ZYVqJogk4Ksw9L2YGHvM4CL5F8",
            ),
            (
                "QRYeXExuXMbK31Pqi3MZ3Agn4rJMUMDLgzTPbeZA9kj9qbdXQ78D",
                "DKWHFREXu875x7jCAjmQeyrZvTxH4RuQZS",
            ),
            (
                "QRYeXExuXMbK31Pqi3MZ3Agn4rJMUMDLgzTPbeZA9kj9r6W7AREn",
                "DFRCC8fdT5CgVpmKsMCSahSoXZgsHmxubW",
            ),
            (
                "QRYeXExuXMbK31Pqi3MZ3Agn4rJMUMDLgzTPbeZA9kj9rbQymV7a",
                "DBxeEUxaUrZHTkQYNmGWcpS3zhz3Xyoc7y",
            ),
            (
                "QRYeXExuXMbK31Pqi3MZ3Agn4rJMUMDLgzTPbeZA9kj9s6Jq4MPD",
                "DTArvD2zeXyBpaxNwJ4n94uK1pyqdBaDE6",
            ),
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = DogecoinPrivateKey::<N>::from_str(private_key).unwrap();
                test_from_private_key(address, &private_key, &DogecoinFormat::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = DogecoinPrivateKey::<N>::from_str(private_key).unwrap();
                let public_key = DogecoinPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &DogecoinFormat::P2PKH);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &DogecoinFormat::P2PKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = DogecoinAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }
    }

    mod p2pkh_mainnet_uncompressed {
        use super::*;

        type N = Mainnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "6Jo93mrNR6a9coJs1Eg6SsE6E7BjFMSTDEUGzhEBEK4fFawTeP5",
                "DFG8WKcWxveeGm9TMw7g6xATr6Zd7Rd2h2",
            ),
            (
                "6Jo93mrNR6a9coJs1Eg6SsE6E7BjFMSTDEUGzhEBEK4fFhoJdFv",
                "DJDyXQpCX4GBJk8y7ejRk98MJV64W8SDEr",
            ),
            (
                "6Jo93mrNR6a9coJs1Eg6SsE6E7BjFMSTDEUGzhEBEK4fFrTCVsY",
                "DNMER6hoLSke1m2buXiBYFrzxcxKFTG9rg",
            ),
            (
                "6Jo93mrNR6a9coJs1Eg6SsE6E7BjFMSTDEUGzhEBEK4fFuMB11W",
                "DLucn31qDBEsuZgjLH3bdcPA1eGPAHqV15",
            ),
            (
                "6Jo93mrNR6a9coJs1Eg6SsE6E7BjFMSTDEUGzhEBEK4fG113D2Y",
                "D7GAAAYx8ZSbGhjP9hHAAGCnHmrExvvJvL",
            ),
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = DogecoinPrivateKey::<N>::from_str(private_key).unwrap();
                test_from_private_key(address, &private_key, &DogecoinFormat::P2PKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = DogecoinPrivateKey::<N>::from_str(private_key).unwrap();
                let public_key = DogecoinPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &DogecoinFormat::P2PKH);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &DogecoinFormat::P2PKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = DogecoinAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }

        #[test]
        fn test_invalid() {
            // Mismatched keypair

            let private_key = "6JXNthKFf7RScyB6q4dz2abzXYqFsEci2fz4CQY6xoABjd6ii1u";
            let expected_address = "DUGJGhJD9ZL3yW4JbXX6J7WFFjfLkbLhWB";

            let private_key = DogecoinPrivateKey::<N>::from_str(private_key).unwrap();
            let address = DogecoinAddress::<N>::from_private_key(&private_key, &DogecoinFormat::P2PKH).unwrap();
            assert_ne!(expected_address, address.to_string());

            let public_key = DogecoinPublicKey::<N>::from_private_key(&private_key);
            let address = DogecoinAddress::<N>::from_public_key(&public_key, &DogecoinFormat::P2PKH).unwrap();
            assert_ne!(expected_address, address.to_string());

            // Invalid address length

            let address = "D";
            assert!(DogecoinAddress::<N>::from_str(address).is_err());

            let address = "DUGJGhJD9ZL3yW4";
            assert!(DogecoinAddress::<N>::from_str(address).is_err());

            let address = "DUGJGhJD9ZL3yW4JbXX6J7WFFjfLkbLhW";
            assert!(DogecoinAddress::<N>::from_str(address).is_err());

            let address = "DUGJGhJD9ZL3yW4JbXX6J7WFFjfLkbLhWADUGJGhJD9ZL3yW4";
            assert!(DogecoinAddress::<N>::from_str(address).is_err());

            let address = "DUGJGhJD9ZL3yW4JbXX6J7WFFjfLkbLhWDUGJGhJD9ZL3yW4JbXX6J7WFFjfLkbLhW";
            assert!(DogecoinAddress::<N>::from_str(address).is_err());
        }
    }

    mod p2sh_p2wpkh_mainnet {
        use super::*;

        type N = Mainnet;

        const KEYPAIRS: [(&str, &str); 5] = [
            (
                "QTTPC6ZNkiFAbsuwuZ2R6kXnFtX7MVpcvj3V1tENdLVYm2CHuwbJ",
                "ADCsqhKhDP9AP2hDqJfFaMswnd79qKn2qT",
            ),
            (
                "QTK3eNYrVwcPTcgzzyGgb3wtHB59tqimv5KLTthqEBU3BNGzS9Mh",
                "AAHbVBVZyxwPo3jSBpCPvGF6qDc2SNBAcc",
            ),
            (
                "QTBMVQdZJKoz7bpdJ68tCrmZ3e9ddk7DBAcUk98EraKc5Mx6aEwC",
                "AECHMxszLtMjh1ZCJABqKgt7pSBSyWqgmY",
            ),
            (
                "QWBtm5p8AvGxqC6RabJWAje9k1rhWTaFKaVhHA8sCqBoFL65SXqn",
                "9s8keS1fQCgChWuY7tM32dS1ViDNcAMSJV",
            ),
            (
                "QSaFhk32qGEbLKTiSAWuxNuAuy17sVR67kgd7qFA9rqkHWLC32kJ",
                "AEQPSDexG36FobJwW7vGrkwSjMsntowYkr",
            ),
        ];

        #[test]
        fn from_private_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = DogecoinPrivateKey::<N>::from_str(private_key).unwrap();
                test_from_private_key(address, &private_key, &DogecoinFormat::P2SH_P2WPKH);
            });
        }

        #[test]
        fn from_public_key() {
            KEYPAIRS.iter().for_each(|(private_key, address)| {
                let private_key = DogecoinPrivateKey::<N>::from_str(private_key).unwrap();
                let public_key = DogecoinPublicKey::<N>::from_private_key(&private_key);
                test_from_public_key(address, &public_key, &DogecoinFormat::P2SH_P2WPKH);
            });
        }

        #[test]
        fn from_str() {
            KEYPAIRS.iter().for_each(|(_, address)| {
                test_from_str::<N>(address, &DogecoinFormat::P2SH_P2WPKH);
            });
        }

        #[test]
        fn to_str() {
            KEYPAIRS.iter().for_each(|(_, expected_address)| {
                let address = DogecoinAddress::<N>::from_str(expected_address).unwrap();
                test_to_str(expected_address, &address);
            });
        }

        #[test]
        fn test_invalid() {
            // Mismatched keypair

            let private_key = "QSaFhk32qGEbLKTiSAWuxNuAuy17sVR67kgd7qFA9rqkHWLC32kJ";
            let expected_address = "AECHMxszLtMjh1ZCJABqKgt7pSBSyWqgmY";

            let private_key = DogecoinPrivateKey::<N>::from_str(private_key).unwrap();
            let address = DogecoinAddress::<N>::from_private_key(&private_key, &DogecoinFormat::P2SH_P2WPKH).unwrap();
            assert_ne!(expected_address, address.to_string());

            let public_key = DogecoinPublicKey::<N>::from_private_key(&private_key);
            let address = DogecoinAddress::<N>::from_public_key(&public_key, &DogecoinFormat::P2SH_P2WPKH).unwrap();
            assert_ne!(expected_address, address.to_string());

            // Invalid address length

            let address = "3";
            assert!(DogecoinAddress::<N>::from_str(address).is_err());

            let address = "3Pai7Ly86pddxxwZ7";
            assert!(DogecoinAddress::<N>::from_str(address).is_err());

            let address = "3Pai7Ly86pddxxwZ7rUhXjRJwog4oKqNY";
            assert!(DogecoinAddress::<N>::from_str(address).is_err());

            let address = "3Pai7Ly86pddxxwZ7rUhXjRJwog4oKqNYK3Pai7Ly86pddxxwZ7";
            assert!(DogecoinAddress::<N>::from_str(address).is_err());

            let address = "3Pai7Ly86pddxxwZ7rUhXjRJwog4oKqNYK3Pai7Ly86pddxxwZ7rUhXjRJwog4oKqNYK";
            assert!(DogecoinAddress::<N>::from_str(address).is_err());
        }
    }
}
