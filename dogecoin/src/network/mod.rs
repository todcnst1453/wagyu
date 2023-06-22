use crate::format::DogecoinFormat;
use wagyu_model::no_std::*;
use wagyu_model::{
    AddressError, ChildIndex, ExtendedPrivateKeyError, ExtendedPublicKeyError, Network, PrivateKeyError,
};

pub mod mainnet;
pub use self::mainnet::*;

/// The interface for a Bitcoin network.
pub trait DogecoinNetwork: Network {
    const HD_COIN_TYPE: ChildIndex;

    /// Returns the address prefix of the given network.
    fn to_address_prefix(format: &DogecoinFormat) -> Vec<u8>;

    /// Returns the network of the given address prefix.
    fn from_address_prefix(prefix: &[u8]) -> Result<Self, AddressError>;

    /// Returns the wif prefix of the given network.
    fn to_private_key_prefix() -> u8;

    /// Returns the network of the given wif prefix.
    fn from_private_key_prefix(prefix: u8) -> Result<Self, PrivateKeyError>;

    /// Returns the extended private key version bytes of the given network.
    fn to_extended_private_key_version_bytes(format: &DogecoinFormat) -> Result<Vec<u8>, ExtendedPrivateKeyError>;

    /// Returns the network of the given extended private key version bytes.
    fn from_extended_private_key_version_bytes(prefix: &[u8]) -> Result<Self, ExtendedPrivateKeyError>;

    /// Returns the extended public key version bytes of the given network.
    fn to_extended_public_key_version_bytes(format: &DogecoinFormat) -> Result<Vec<u8>, ExtendedPublicKeyError>;

    /// Returns the network of the given extended public key version bytes.
    fn from_extended_public_key_version_bytes(prefix: &[u8]) -> Result<Self, ExtendedPublicKeyError>;
}
