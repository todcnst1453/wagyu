use crate::network::DogecoinNetwork;
use wagyu_model::derivation_path::{ChildIndex, DerivationPath, DerivationPathError};
use wagyu_model::no_std::*;

use core::{convert::TryFrom, fmt, marker::PhantomData, str::FromStr};

/// Represents a Dogecoin derivation path
#[derive(Clone, PartialEq, Eq)]
pub enum DogecoinDerivationPath<N: DogecoinNetwork> {
    /// BIP32 - Pay-to-Pubkey Hash
    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    BIP32(Vec<ChildIndex>, PhantomData<N>),
    /// BIP44 - m/44'/{0', 1'}/{account}'/{change}/{index} - Pay-to-Pubkey Hash
    /// https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
    BIP44([ChildIndex; 3]),
    /// BIP49 - m/49'/{0', 1'}/{account}'/{change}/{index} - SegWit Pay-to-Witness-Public-Key Hash
    /// https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki
    BIP49([ChildIndex; 3]),
}

impl<N: DogecoinNetwork> DerivationPath for DogecoinDerivationPath<N> {
    /// Returns a child index vector given the derivation path.
    fn to_vec(&self) -> Result<Vec<ChildIndex>, DerivationPathError> {
        match self {
            DogecoinDerivationPath::BIP32(path, _) => match path.len() < 256 {
                true => Ok(path.clone()),
                false => Err(DerivationPathError::ExpectedBIP32Path),
            },
            DogecoinDerivationPath::BIP44(path) => {
                match path[0].is_hardened() && path[1].is_normal() && path[2].is_normal() {
                    true => Ok(vec![
                        ChildIndex::Hardened(44),
                        N::HD_COIN_TYPE,
                        path[0],
                        path[1],
                        path[2],
                    ]),
                    false => Err(DerivationPathError::ExpectedBIP44Path),
                }
            }
            DogecoinDerivationPath::BIP49(path) => {
                match path[0].is_hardened() && path[1].is_normal() && path[2].is_normal() {
                    true => Ok(vec![
                        ChildIndex::Hardened(49),
                        N::HD_COIN_TYPE,
                        path[0],
                        path[1],
                        path[2],
                    ]),
                    false => Err(DerivationPathError::ExpectedBIP49Path),
                }
            }
        }
    }

    /// Returns a derivation path given the child index vector.
    fn from_vec(path: &Vec<ChildIndex>) -> Result<Self, DerivationPathError> {
        if path.len() == 5 {
            // Path length 5 - BIP44
            if path[0] == ChildIndex::Hardened(44)
                && path[1] == N::HD_COIN_TYPE
                && path[2].is_hardened()
                && path[3].is_normal()
                && path[4].is_normal()
            {
                return Ok(DogecoinDerivationPath::BIP44([path[2], path[3], path[4]]));
            }
            // Path length 5 - BIP49
            if path[0] == ChildIndex::Hardened(49)
                && path[1] == N::HD_COIN_TYPE
                && path[2].is_hardened()
                && path[3].is_normal()
                && path[4].is_normal()
            {
                return Ok(DogecoinDerivationPath::BIP49([path[2], path[3], path[4]]));
            }
            // Path length 5 - BIP32 (non-BIP44 & non-BIP49 compliant)
            return Ok(DogecoinDerivationPath::BIP32(path.to_vec(), PhantomData));
        } else {
            // Path length 0 - BIP32 root key
            // Path length i - BIP32
            Ok(DogecoinDerivationPath::BIP32(path.to_vec(), PhantomData))
        }
    }
}

impl<N: DogecoinNetwork> FromStr for DogecoinDerivationPath<N> {
    type Err = DerivationPathError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let mut parts = path.split("/");

        if parts.next().unwrap() != "m" {
            return Err(DerivationPathError::InvalidDerivationPath(path.to_string()));
        }

        let path: Result<Vec<ChildIndex>, Self::Err> = parts.map(str::parse).collect();
        Self::from_vec(&path?)
    }
}

impl<N: DogecoinNetwork> TryFrom<Vec<ChildIndex>> for DogecoinDerivationPath<N> {
    type Error = DerivationPathError;

    fn try_from(path: Vec<ChildIndex>) -> Result<Self, Self::Error> {
        Self::from_vec(&path)
    }
}

impl<'a, N: DogecoinNetwork> TryFrom<&'a [ChildIndex]> for DogecoinDerivationPath<N> {
    type Error = DerivationPathError;

    fn try_from(path: &'a [ChildIndex]) -> Result<Self, Self::Error> {
        Self::try_from(path.to_vec())
    }
}

impl<N: DogecoinNetwork> fmt::Debug for DogecoinDerivationPath<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl<N: DogecoinNetwork> fmt::Display for DogecoinDerivationPath<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.to_vec() {
            Ok(path) => {
                f.write_str("m")?;
                for index in path.iter() {
                    f.write_str("/")?;
                    fmt::Display::fmt(index, f)?;
                }
                Ok(())
            }
            Err(_) => Err(fmt::Error),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::network::*;

    use core::convert::TryInto;

    #[test]
    fn bip32() {
        use super::*;

        type N = Mainnet;

        assert_eq!(
            DogecoinDerivationPath::<N>::BIP32(vec![], PhantomData),
            DogecoinDerivationPath::<N>::from_str("m").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP32(vec![ChildIndex::Normal(0)], PhantomData),
            DogecoinDerivationPath::<N>::from_str("m/0").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP32(vec![ChildIndex::Hardened(0)], PhantomData),
            DogecoinDerivationPath::<N>::from_str("m/0'").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP32(vec![ChildIndex::Normal(0), ChildIndex::Normal(0)], PhantomData),
            DogecoinDerivationPath::<N>::from_str("m/0/0").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP32(vec![ChildIndex::Normal(0), ChildIndex::Hardened(0)], PhantomData),
            DogecoinDerivationPath::<N>::from_str("m/0/0'").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP32(
                vec![ChildIndex::Normal(0), ChildIndex::Normal(0), ChildIndex::Normal(0)],
                PhantomData
            ),
            DogecoinDerivationPath::<N>::from_str("m/0/0/0").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP32(
                vec![ChildIndex::Normal(0), ChildIndex::Normal(0), ChildIndex::Hardened(0)],
                PhantomData
            ),
            DogecoinDerivationPath::<N>::from_str("m/0/0/0'").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP32(
                vec![
                    ChildIndex::Normal(0),
                    ChildIndex::Normal(0),
                    ChildIndex::Normal(0),
                    ChildIndex::Normal(0)
                ],
                PhantomData
            ),
            DogecoinDerivationPath::<N>::from_str("m/0/0/0/0").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP32(
                vec![
                    ChildIndex::Normal(0),
                    ChildIndex::Normal(0),
                    ChildIndex::Normal(0),
                    ChildIndex::Hardened(0)
                ],
                PhantomData
            ),
            DogecoinDerivationPath::<N>::from_str("m/0/0/0/0'").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP32(
                vec![
                    ChildIndex::Normal(0),
                    ChildIndex::Normal(0),
                    ChildIndex::Normal(0),
                    ChildIndex::Normal(0),
                    ChildIndex::Normal(0)
                ],
                PhantomData
            ),
            DogecoinDerivationPath::<N>::from_str("m/0/0/0/0/0").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP32(
                vec![
                    ChildIndex::Normal(0),
                    ChildIndex::Normal(0),
                    ChildIndex::Normal(0),
                    ChildIndex::Normal(0),
                    ChildIndex::Hardened(0)
                ],
                PhantomData
            ),
            DogecoinDerivationPath::<N>::from_str("m/0/0/0/0/0'").unwrap()
        );
    }

    #[test]
    fn bip44_mainnet() {
        use super::*;

        type N = Mainnet;

        assert_eq!(
            DogecoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(0), ChildIndex::Normal(0), ChildIndex::Normal(0)]),
            DogecoinDerivationPath::<N>::from_str("m/44'/0'/0'/0/0").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(0), ChildIndex::Normal(0), ChildIndex::Normal(1)]),
            DogecoinDerivationPath::<N>::from_str("m/44'/0'/0'/0/1").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(0), ChildIndex::Normal(1), ChildIndex::Normal(0)]),
            DogecoinDerivationPath::<N>::from_str("m/44'/0'/0'/1/0").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(0), ChildIndex::Normal(1), ChildIndex::Normal(1)]),
            DogecoinDerivationPath::<N>::from_str("m/44'/0'/0'/1/1").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(1), ChildIndex::Normal(0), ChildIndex::Normal(0)]),
            DogecoinDerivationPath::<N>::from_str("m/44'/0'/1'/0/0").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(1), ChildIndex::Normal(0), ChildIndex::Normal(1)]),
            DogecoinDerivationPath::<N>::from_str("m/44'/0'/1'/0/1").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(1), ChildIndex::Normal(1), ChildIndex::Normal(0)]),
            DogecoinDerivationPath::<N>::from_str("m/44'/0'/1'/1/0").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP44([ChildIndex::Hardened(1), ChildIndex::Normal(1), ChildIndex::Normal(1)]),
            DogecoinDerivationPath::<N>::from_str("m/44'/0'/1'/1/1").unwrap()
        );
    }

    #[test]
    fn bip49_mainnet() {
        use super::*;

        type N = Mainnet;

        assert_eq!(
            DogecoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(0), ChildIndex::Normal(0), ChildIndex::Normal(0)]),
            DogecoinDerivationPath::<N>::from_str("m/49'/0'/0'/0/0").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(0), ChildIndex::Normal(0), ChildIndex::Normal(1)]),
            DogecoinDerivationPath::<N>::from_str("m/49'/0'/0'/0/1").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(0), ChildIndex::Normal(1), ChildIndex::Normal(0)]),
            DogecoinDerivationPath::<N>::from_str("m/49'/0'/0'/1/0").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(0), ChildIndex::Normal(1), ChildIndex::Normal(1)]),
            DogecoinDerivationPath::<N>::from_str("m/49'/0'/0'/1/1").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(1), ChildIndex::Normal(0), ChildIndex::Normal(0)]),
            DogecoinDerivationPath::<N>::from_str("m/49'/0'/1'/0/0").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(1), ChildIndex::Normal(0), ChildIndex::Normal(1)]),
            DogecoinDerivationPath::<N>::from_str("m/49'/0'/1'/0/1").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(1), ChildIndex::Normal(1), ChildIndex::Normal(0)]),
            DogecoinDerivationPath::<N>::from_str("m/49'/0'/1'/1/0").unwrap()
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::BIP49([ChildIndex::Hardened(1), ChildIndex::Normal(1), ChildIndex::Normal(1)]),
            DogecoinDerivationPath::<N>::from_str("m/49'/0'/1'/1/1").unwrap()
        );
    }

    #[test]
    fn valid_path() {
        use super::*;

        type N = Mainnet;

        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m"),
            Ok(vec![].try_into().unwrap())
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m/0"),
            Ok(vec![ChildIndex::normal(0).unwrap()].try_into().unwrap())
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m/0/1"),
            Ok(vec![ChildIndex::normal(0).unwrap(), ChildIndex::normal(1).unwrap()]
                .try_into()
                .unwrap())
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m/0/1/2"),
            Ok(vec![
                ChildIndex::normal(0).unwrap(),
                ChildIndex::normal(1).unwrap(),
                ChildIndex::normal(2).unwrap()
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m/0/1/2/3"),
            Ok(vec![
                ChildIndex::normal(0).unwrap(),
                ChildIndex::normal(1).unwrap(),
                ChildIndex::normal(2).unwrap(),
                ChildIndex::normal(3).unwrap()
            ]
            .try_into()
            .unwrap())
        );

        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m"),
            Ok(vec![].try_into().unwrap())
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m/0'"),
            Ok(vec![ChildIndex::hardened(0).unwrap()].try_into().unwrap())
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m/0'/1"),
            Ok(vec![ChildIndex::hardened(0).unwrap(), ChildIndex::normal(1).unwrap()]
                .try_into()
                .unwrap())
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m/0'/1/2'"),
            Ok(vec![
                ChildIndex::hardened(0).unwrap(),
                ChildIndex::normal(1).unwrap(),
                ChildIndex::hardened(2).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m/0'/1/2'/3"),
            Ok(vec![
                ChildIndex::hardened(0).unwrap(),
                ChildIndex::normal(1).unwrap(),
                ChildIndex::hardened(2).unwrap(),
                ChildIndex::normal(3).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m/0'/1/2'/3/4'"),
            Ok(vec![
                ChildIndex::hardened(0).unwrap(),
                ChildIndex::normal(1).unwrap(),
                ChildIndex::hardened(2).unwrap(),
                ChildIndex::normal(3).unwrap(),
                ChildIndex::hardened(4).unwrap(),
            ]
            .try_into()
            .unwrap())
        );

        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m"),
            Ok(vec![].try_into().unwrap())
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m/0h"),
            Ok(vec![ChildIndex::hardened(0).unwrap()].try_into().unwrap())
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m/0h/1'"),
            Ok(vec![ChildIndex::hardened(0).unwrap(), ChildIndex::hardened(1).unwrap()]
                .try_into()
                .unwrap())
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m/0'/1h/2'"),
            Ok(vec![
                ChildIndex::hardened(0).unwrap(),
                ChildIndex::hardened(1).unwrap(),
                ChildIndex::hardened(2).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m/0h/1'/2h/3'"),
            Ok(vec![
                ChildIndex::hardened(0).unwrap(),
                ChildIndex::hardened(1).unwrap(),
                ChildIndex::hardened(2).unwrap(),
                ChildIndex::hardened(3).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m/0'/1h/2'/3h/4'"),
            Ok(vec![
                ChildIndex::hardened(0).unwrap(),
                ChildIndex::hardened(1).unwrap(),
                ChildIndex::hardened(2).unwrap(),
                ChildIndex::hardened(3).unwrap(),
                ChildIndex::hardened(4).unwrap(),
            ]
            .try_into()
            .unwrap())
        );
    }

    #[test]
    fn invalid_path() {
        use super::*;

        type N = Mainnet;

        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("n"),
            Err(DerivationPathError::InvalidDerivationPath("n".into()))
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("n/0"),
            Err(DerivationPathError::InvalidDerivationPath("n/0".into()))
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("n/0/0"),
            Err(DerivationPathError::InvalidDerivationPath("n/0/0".into()))
        );

        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("1"),
            Err(DerivationPathError::InvalidDerivationPath("1".into()))
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("1/0"),
            Err(DerivationPathError::InvalidDerivationPath("1/0".into()))
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("1/0/0"),
            Err(DerivationPathError::InvalidDerivationPath("1/0/0".into()))
        );

        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m/0x"),
            Err(DerivationPathError::InvalidChildNumberFormat)
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m/0x0"),
            Err(DerivationPathError::InvalidChildNumberFormat)
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m/0x00"),
            Err(DerivationPathError::InvalidChildNumberFormat)
        );

        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("0/m"),
            Err(DerivationPathError::InvalidDerivationPath("0/m".into()))
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m//0"),
            Err(DerivationPathError::InvalidChildNumberFormat)
        );
        assert_eq!(
            DogecoinDerivationPath::<N>::from_str("m/2147483648"),
            Err(DerivationPathError::InvalidChildNumber(2147483648))
        );
    }
}
