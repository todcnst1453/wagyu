use crate::address::DogecoinAddress;
use crate::amount::DogecoinAmount;
use crate::format::DogecoinFormat;
use crate::network::DogecoinNetwork;
use crate::private_key::DogecoinPrivateKey;
use crate::public_key::DogecoinPublicKey;
//use crate::witness_program::WitnessProgram;
use wagyu_model::no_std::{io::Read, *};
use wagyu_model::{PrivateKey, Transaction, TransactionError, TransactionId};

use base58::FromBase58;
use bech32::{Bech32, FromBase32};
use core::{fmt, str::FromStr};
use secp256k1;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Returns the variable length integer of the given value.
/// https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
pub fn variable_length_integer(value: u64) -> Result<Vec<u8>, TransactionError> {
    match value {
        // bounded by u8::max_value()
        0..=252 => Ok(vec![value as u8]),
        // bounded by u16::max_value()
        253..=65535 => Ok([vec![0xfd], (value as u16).to_le_bytes().to_vec()].concat()),
        // bounded by u32::max_value()
        65536..=4294967295 => Ok([vec![0xfe], (value as u32).to_le_bytes().to_vec()].concat()),
        // bounded by u64::max_value()
        _ => Ok([vec![0xff], value.to_le_bytes().to_vec()].concat()),
    }
}

/// Decode the value of a variable length integer.
/// https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
pub fn read_variable_length_integer<R: Read>(mut reader: R) -> Result<usize, TransactionError> {
    let mut flag = [0u8; 1];
    reader.read(&mut flag)?;

    match flag[0] {
        0..=252 => Ok(flag[0] as usize),
        0xfd => {
            let mut size = [0u8; 2];
            reader.read(&mut size)?;
            match u16::from_le_bytes(size) {
                s if s < 253 => return Err(TransactionError::InvalidVariableSizeInteger(s as usize)),
                s => Ok(s as usize),
            }
        }
        0xfe => {
            let mut size = [0u8; 4];
            reader.read(&mut size)?;
            match u32::from_le_bytes(size) {
                s if s < 65536 => return Err(TransactionError::InvalidVariableSizeInteger(s as usize)),
                s => Ok(s as usize),
            }
        }
        _ => {
            let mut size = [0u8; 8];
            reader.read(&mut size)?;
            match u64::from_le_bytes(size) {
                s if s < 4294967296 => return Err(TransactionError::InvalidVariableSizeInteger(s as usize)),
                s => Ok(s as usize),
            }
        }
    }
}

pub struct DogecoinVector;

impl DogecoinVector {
    /// Read and output a vector with a variable length integer
    pub fn read<R: Read, E, F>(mut reader: R, func: F) -> Result<Vec<E>, TransactionError>
    where
        F: Fn(&mut R) -> Result<E, TransactionError>,
    {
        let count = read_variable_length_integer(&mut reader)?;
        (0..count).map(|_| func(&mut reader)).collect()
    }

    /// Read and output a vector with a variable length integer and the integer itself
    pub fn read_witness<R: Read, E, F>(
        mut reader: R,
        func: F,
    ) -> Result<(usize, Result<Vec<E>, TransactionError>), TransactionError>
    where
        F: Fn(&mut R) -> Result<E, TransactionError>,
    {
        let count = read_variable_length_integer(&mut reader)?;
        Ok((count, (0..count).map(|_| func(&mut reader)).collect()))
    }
}

/// Generate the script_pub_key of a corresponding address
pub fn create_script_pub_key<N: DogecoinNetwork>(address: &DogecoinAddress<N>) -> Result<Vec<u8>, TransactionError> {
    match address.format() {
        DogecoinFormat::P2PKH => {
            let bytes = &address.to_string().from_base58()?;
            let pub_key_hash = bytes[1..(bytes.len() - 4)].to_vec();

            let mut script = vec![];
            script.push(Opcode::OP_DUP as u8);
            script.push(Opcode::OP_HASH160 as u8);
            script.extend(variable_length_integer(pub_key_hash.len() as u64)?);
            script.extend(pub_key_hash);
            script.push(Opcode::OP_EQUALVERIFY as u8);
            script.push(Opcode::OP_CHECKSIG as u8);
            Ok(script)
        }
        DogecoinFormat::P2WSH => {
            let bech32 = Bech32::from_str(&address.to_string())?;
            let (v, script) = bech32.data().split_at(1);
            let script = Vec::from_base32(script)?;
            let mut script_bytes = vec![v[0].to_u8(), script.len() as u8];
            script_bytes.extend(script);
            Ok(script_bytes)
        }
        DogecoinFormat::P2SH_P2WPKH => {
            let script_bytes = &address.to_string().from_base58()?;
            let script_hash = script_bytes[1..(script_bytes.len() - 4)].to_vec();

            let mut script = vec![];
            script.push(Opcode::OP_HASH160 as u8);
            script.extend(variable_length_integer(script_hash.len() as u64)?);
            script.extend(script_hash);
            script.push(Opcode::OP_EQUAL as u8);
            Ok(script)
        }
    }
}

/// Represents a Dogecoin signature hash
/// https://en.bitcoin.it/wiki/OP_CHECKSIG
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[allow(non_camel_case_types)]
pub enum SignatureHash {
    /// Signs all inputs and outputs.
    SIGHASH_ALL = 0x01,
    /// Signs all inputs and none of the outputs.
    /// (e.g. "blank check" transaction, where any address can redeem the output)
    SIGHASH_NONE = 0x02,
    /// Signs all inputs and one corresponding output per input.
    /// (e.g. signing vin 0 will result in signing vout 0)
    SIGHASH_SINGLE = 0x03,
    /// Signs only one input and all outputs.
    /// Allows anyone to add or remove other inputs, forbids changing any outputs.
    /// (e.g. "crowdfunding" transaction, where the output is the "goal" address)
    SIGHASH_ALL_SIGHASH_ANYONECANPAY = 0x81,
    /// Signs only one input and none of the outputs.
    /// Allows anyone to add or remove other inputs or any outputs.
    /// (e.g. "dust collector" transaction, where "dust" can be aggregated and spent together)
    SIGHASH_NONE_SIGHASH_ANYONECANPAY = 0x82,
    /// Signs only one input and one corresponding output per input.
    /// Allows anyone to add or remove other inputs.
    SIGHASH_SINGLE_SIGHASH_ANYONECANPAY = 0x83,
}

impl fmt::Display for SignatureHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignatureHash::SIGHASH_ALL => write!(f, "SIGHASH_ALL"),
            SignatureHash::SIGHASH_NONE => write!(f, "SIGHASH_NONE"),
            SignatureHash::SIGHASH_SINGLE => write!(f, "SIGHASH_SINGLE"),
            SignatureHash::SIGHASH_ALL_SIGHASH_ANYONECANPAY => write!(f, "SIGHASH_ALL | SIGHASH_ANYONECANPAY"),
            SignatureHash::SIGHASH_NONE_SIGHASH_ANYONECANPAY => write!(f, "SIGHASH_NONE | SIGHASH_ANYONECANPAY"),
            SignatureHash::SIGHASH_SINGLE_SIGHASH_ANYONECANPAY => write!(f, "SIGHASH_SINGLE | SIGHASH_ANYONECANPAY"),
        }
    }
}

impl SignatureHash {
    fn from_byte(byte: &u8) -> Self {
        match byte {
            0x01 => SignatureHash::SIGHASH_ALL,
            0x02 => SignatureHash::SIGHASH_NONE,
            0x03 => SignatureHash::SIGHASH_SINGLE,
            0x81 => SignatureHash::SIGHASH_ALL_SIGHASH_ANYONECANPAY,
            0x82 => SignatureHash::SIGHASH_NONE_SIGHASH_ANYONECANPAY,
            0x83 => SignatureHash::SIGHASH_SINGLE_SIGHASH_ANYONECANPAY,
            _ => SignatureHash::SIGHASH_ALL,
        }
    }
}

/// Represents the commonly used script opcodes
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[allow(non_camel_case_types)]
pub enum Opcode {
    OP_DUP = 0x76,
    OP_HASH160 = 0xa9,
    OP_CHECKSIG = 0xac,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Opcode::OP_DUP => write!(f, "OP_DUP"),
            Opcode::OP_HASH160 => write!(f, "OP_HASH160"),
            Opcode::OP_CHECKSIG => write!(f, "OP_CHECKSIG"),
            Opcode::OP_EQUAL => write!(f, "OP_EQUAL"),
            Opcode::OP_EQUALVERIFY => write!(f, "OP_EQUALVERIFY"),
        }
    }
}

/// Represents a Dogecoin transaction outpoint
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Outpoint<N: DogecoinNetwork> {
    /// The previous transaction hash (32 bytes) (uses reversed hash order from Dogecoin RPC)
    pub reverse_transaction_id: Vec<u8>,
    /// The index of the transaction input (4 bytes)
    pub index: u32,
    /// The amount associated with this input (used for SegWit transaction signatures)
    pub amount: Option<DogecoinAmount>,
    /// The script public key associated with spending this input
    pub script_pub_key: Option<Vec<u8>>,
    /// An optional redeem script (for SegWit transactions)
    pub redeem_script: Option<Vec<u8>>,
    /// The address of the outpoint
    pub address: Option<DogecoinAddress<N>>,
}

impl<N: DogecoinNetwork> Outpoint<N> {
    /// Returns a new Dogecoin transaction outpoint
    pub fn new(
        reverse_transaction_id: Vec<u8>,
        index: u32,
        address: Option<DogecoinAddress<N>>,
        amount: Option<DogecoinAmount>,
        redeem_script: Option<Vec<u8>>,
        script_pub_key: Option<Vec<u8>>,
    ) -> Result<Self, TransactionError> {
        let (script_pub_key, redeem_script) = match address.clone() {
            Some(address) => {
                let script_pub_key = script_pub_key.unwrap_or(create_script_pub_key::<N>(&address)?);
                let redeem_script = match address.format() {
                    DogecoinFormat::P2PKH => match redeem_script {
                        Some(_) => return Err(TransactionError::InvalidInputs("P2PKH".into())),
                        None => match script_pub_key[0] != Opcode::OP_DUP as u8
                            && script_pub_key[1] != Opcode::OP_HASH160 as u8
                            && script_pub_key[script_pub_key.len() - 1] != Opcode::OP_CHECKSIG as u8
                        {
                            true => return Err(TransactionError::InvalidScriptPubKey("P2PKH".into())),
                            false => None,
                        },
                    },
                    DogecoinFormat::P2WSH => match redeem_script {
                        Some(redeem_script) => match script_pub_key[0] != 0x00 as u8
                            && script_pub_key[1] != 0x20 as u8 && script_pub_key.len() != 34 // zero [32-byte sha256(witness script)]
                        {
                            true => return Err(TransactionError::InvalidScriptPubKey("P2WSH".into())),
                            false => Some(redeem_script),
                        },
                        None => return Err(TransactionError::InvalidInputs("P2WSH".into())),
                    },
                    DogecoinFormat::P2SH_P2WPKH => match redeem_script {
                        Some(redeem_script) => match script_pub_key[0] != Opcode::OP_HASH160 as u8
                            && script_pub_key[script_pub_key.len() - 1] != Opcode::OP_EQUAL as u8
                        {
                            true => return Err(TransactionError::InvalidScriptPubKey("P2SH_P2WPKH".into())),
                            false => Some(redeem_script),
                        },
                        None => return Err(TransactionError::InvalidInputs("P2SH_P2WPKH".into())),
                    },
                };

                (Some(script_pub_key), redeem_script)
            }
            None => (None, None),
        };

        Ok(Self {
            reverse_transaction_id,
            index,
            amount,
            redeem_script,
            script_pub_key,
            address,
        })
    }
}

/// Represents a Dogecoin transaction input
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DogecoinTransactionInput<N: DogecoinNetwork> {
    /// The outpoint (36 bytes)
    pub outpoint: Outpoint<N>,
    /// The transaction input script (variable size)
    pub script_sig: Vec<u8>,
    /// The sequence number (4 bytes) (0xFFFFFFFF unless lock > 0)
    /// Also used in replace-by-fee (BIP 125)
    pub sequence: Vec<u8>,
    /// The signature hash (4 bytes) (used in signing raw transaction only)
    pub sighash_code: SignatureHash,
    /// The witnesses in a SegWit transaction
    pub witnesses: Vec<Vec<u8>>,
    /// If true, the input has been signed
    pub is_signed: bool,
    /// Provide more flexibility for multiple signatures (for P2WSH)
    pub additional_witness: Option<(Vec<u8>, bool)>,
    /// Option for additional witness stack script args
    pub witness_script_data: Option<Vec<u8>>,
}

impl<N: DogecoinNetwork> DogecoinTransactionInput<N> {
    const DEFAULT_SEQUENCE: [u8; 4] = [0xff, 0xff, 0xff, 0xff];

    /// Returns a new Dogecoin transaction input without the script (unlocking).
    pub fn new(
        transaction_id: Vec<u8>,
        index: u32,
        address: Option<DogecoinAddress<N>>,
        amount: Option<DogecoinAmount>,
        redeem_script: Option<Vec<u8>>,
        script_pub_key: Option<Vec<u8>>,
        sequence: Option<Vec<u8>>,
        sighash: SignatureHash,
    ) -> Result<Self, TransactionError> {
        if transaction_id.len() != 32 {
            return Err(TransactionError::InvalidTransactionId(transaction_id.len()));
        }

        // Byte-wise reverse of computed SHA-256 hash values
        // https://bitcoin.org/en/developer-reference#hash-byte-order
        let mut reverse_transaction_id = transaction_id;
        reverse_transaction_id.reverse();

        let outpoint = Outpoint::<N>::new(
            reverse_transaction_id,
            index,
            address,
            amount,
            redeem_script,
            script_pub_key,
        )?;

        Ok(Self {
            outpoint,
            script_sig: vec![],
            sequence: sequence.unwrap_or(DogecoinTransactionInput::<N>::DEFAULT_SEQUENCE.to_vec()),
            sighash_code: sighash,
            witnesses: vec![],
            is_signed: false,
            additional_witness: None,
            witness_script_data: None,
        })
    }

    /// Read and output a Dogecoin transaction input
    pub fn read<R: Read>(mut reader: &mut R) -> Result<Self, TransactionError> {
        let mut transaction_hash = [0u8; 32];
        let mut vin = [0u8; 4];
        let mut sequence = [0u8; 4];

        reader.read(&mut transaction_hash)?;
        reader.read(&mut vin)?;

        let outpoint = Outpoint::<N>::new(
            transaction_hash.to_vec(),
            u32::from_le_bytes(vin),
            None,
            None,
            None,
            None,
        )?;

        let script_sig: Vec<u8> = DogecoinVector::read(&mut reader, |s| {
            let mut byte = [0u8; 1];
            s.read(&mut byte)?;
            Ok(byte[0])
        })?;

        reader.read(&mut sequence)?;

        let script_sig_len = read_variable_length_integer(&script_sig[..])?;
        let sighash_code = SignatureHash::from_byte(&match script_sig_len {
            0 => 0x01,
            length => script_sig[length],
        });

        Ok(Self {
            outpoint,
            script_sig: script_sig.to_vec(),
            sequence: sequence.to_vec(),
            sighash_code,
            witnesses: vec![],
            is_signed: script_sig.len() > 0,
            additional_witness: None,
            witness_script_data: None,
        })
    }

    /// Returns the serialized transaction input.
    pub fn serialize(&self, raw: bool) -> Result<Vec<u8>, TransactionError> {
        let mut input = vec![];
        input.extend(&self.outpoint.reverse_transaction_id);
        input.extend(&self.outpoint.index.to_le_bytes());

        match raw {
            true => input.extend(vec![0x00]),
            false => match self.script_sig.len() {
                0 => match &self.outpoint.address {
                    Some(address) => match address.format() {
                        DogecoinFormat::P2WSH => input.extend(vec![0x00]),
                        _ => {
                            let script_pub_key = match &self.outpoint.script_pub_key {
                                Some(script) => script,
                                None => return Err(TransactionError::MissingOutpointScriptPublicKey),
                            };
                            input.extend(variable_length_integer(script_pub_key.len() as u64)?);
                            input.extend(script_pub_key);
                        }
                    },
                    None => input.extend(vec![0x00]),
                },
                _ => {
                    input.extend(variable_length_integer(self.script_sig.len() as u64)?);
                    input.extend(&self.script_sig);
                }
            },
        };

        input.extend(&self.sequence);
        Ok(input)
    }
}

/// Represents a Dogecoin transaction output
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DogecoinTransactionOutput {
    /// The amount (in Satoshi)
    pub amount: DogecoinAmount,
    /// The public key script
    pub script_pub_key: Vec<u8>,
}

impl DogecoinTransactionOutput {
    /// Returns a Dogecoin transaction output.
    pub fn new<N: DogecoinNetwork>(
        address: &DogecoinAddress<N>,
        amount: DogecoinAmount,
    ) -> Result<Self, TransactionError> {
        Ok(Self {
            amount,
            script_pub_key: create_script_pub_key::<N>(address)?,
        })
    }

    /// Read and output a Dogecoin transaction output
    pub fn read<R: Read>(mut reader: &mut R) -> Result<Self, TransactionError> {
        let mut amount = [0u8; 8];
        reader.read(&mut amount)?;

        let script_pub_key: Vec<u8> = DogecoinVector::read(&mut reader, |s| {
            let mut byte = [0u8; 1];
            s.read(&mut byte)?;
            Ok(byte[0])
        })?;

        Ok(Self {
            amount: DogecoinAmount::from_satoshi(u64::from_le_bytes(amount) as i64)?,
            script_pub_key,
        })
    }

    /// Returns the serialized transaction output.
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        let mut output = vec![];
        output.extend(&self.amount.0.to_le_bytes());
        output.extend(variable_length_integer(self.script_pub_key.len() as u64)?);
        output.extend(&self.script_pub_key);
        Ok(output)
    }
}

/// Represents an Dogecoin transaction id and witness transaction id
/// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#transaction-id
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DogecoinTransactionId {
    pub txid: Vec<u8>,
    pub wtxid: Vec<u8>,
}

impl TransactionId for DogecoinTransactionId {}

impl fmt::Display for DogecoinTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &hex::encode(&self.txid))
    }
}

/// Represents the Dogecoin transaction parameters
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DogecoinTransactionParameters<N: DogecoinNetwork> {
    /// The version number (4 bytes)
    pub version: u32,
    /// The transaction inputs
    pub inputs: Vec<DogecoinTransactionInput<N>>,
    /// The transaction outputs
    pub outputs: Vec<DogecoinTransactionOutput>,
    /// The lock time (4 bytes)
    pub lock_time: u32,
    /// An optional 2 bytes to indicate SegWit transactions
    pub segwit_flag: bool,
}

impl<N: DogecoinNetwork> DogecoinTransactionParameters<N> {
    /// Read and output the Dogecoin transaction parameters
    pub fn read<R: Read>(mut reader: R) -> Result<Self, TransactionError> {
        let mut version = [0u8; 4];
        reader.read(&mut version)?;

        let mut inputs = DogecoinVector::read(&mut reader, DogecoinTransactionInput::<N>::read)?;

        let segwit_flag = match inputs.is_empty() {
            true => {
                let mut flag = [0u8; 1];
                reader.read(&mut flag)?;
                match flag[0] {
                    1 => {
                        inputs = DogecoinVector::read(&mut reader, DogecoinTransactionInput::<N>::read)?;
                        true
                    }
                    _ => return Err(TransactionError::InvalidSegwitFlag(flag[0] as usize)),
                }
            }
            false => false,
        };

        let outputs = DogecoinVector::read(&mut reader, DogecoinTransactionOutput::read)?;

        if segwit_flag {
            for input in &mut inputs {
                let witnesses: Vec<Vec<u8>> = DogecoinVector::read(&mut reader, |s| {
                    let (size, witness) = DogecoinVector::read_witness(s, |sr| {
                        let mut byte = [0u8; 1];
                        sr.read(&mut byte)?;
                        Ok(byte[0])
                    })?;

                    Ok([variable_length_integer(size as u64)?, witness?].concat())
                })?;

                if witnesses.len() > 0 {
                    input.sighash_code = SignatureHash::from_byte(&witnesses[0][&witnesses[0].len() - 1]);
                    input.is_signed = true;
                }
                input.witnesses = witnesses;
            }
        }

        let mut lock_time = [0u8; 4];
        reader.read(&mut lock_time)?;

        let transaction_parameters = DogecoinTransactionParameters::<N> {
            version: u32::from_le_bytes(version),
            inputs,
            outputs,
            lock_time: u32::from_le_bytes(lock_time),
            segwit_flag,
        };

        Ok(transaction_parameters)
    }
}

/// Represents a Dogecoin transaction
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DogecoinTransaction<N: DogecoinNetwork> {
    /// The transaction parameters (version, inputs, outputs, lock_time, segwit_flag)
    pub parameters: DogecoinTransactionParameters<N>,
}

impl<N: DogecoinNetwork> Transaction for DogecoinTransaction<N> {
    type Address = DogecoinAddress<N>;
    type Format = DogecoinFormat;
    type PrivateKey = DogecoinPrivateKey<N>;
    type PublicKey = DogecoinPublicKey<N>;
    type TransactionId = DogecoinTransactionId;
    type TransactionParameters = DogecoinTransactionParameters<N>;

    /// Returns an unsigned transaction given the transaction parameters.
    fn new(parameters: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(Self {
            parameters: parameters.clone(),
        })
    }
    /// Returns a signed transaction given the private key of the sender.
    fn partial_sign(&self, private_key: &Self::PrivateKey, partial_script: &Vec<u8>) -> Result<Self, TransactionError> {
        let mut transaction = self.clone();
        for (vin, input) in self.parameters.inputs.iter().enumerate() {
            let address = match &input.outpoint.address {
                Some(address) => address,
                None => continue,
            };

            let address_is_valid = match &address.format() {
                DogecoinFormat::P2WSH => {
                    let input_script = match &input.outpoint.redeem_script {
                        Some(redeem_script) => redeem_script.clone(),
                        None => return Err(TransactionError::InvalidInputs("P2WSH".into())),
                    };
                    let c_address = DogecoinAddress::<N>::p2wsh(&input_script)?;
                    address == &c_address
                }
                _ => address == &private_key.to_address(&address.format())?,
            };

            if address_is_valid && !transaction.parameters.inputs[vin].is_signed {
                // Transaction hash
                let preimage = match &address.format() {
                    DogecoinFormat::P2PKH => transaction.p2pkh_hash_preimage(vin, input.sighash_code)?,
                    _ => transaction.hash_preimage(vin, input.sighash_code)?,
                };

                let transaction_hash = Sha256::digest(Sha256::digest(&preimage).as_slice());

                // Signature
                let (signature, _) = secp256k1::sign(
                    &secp256k1::Message::parse_slice(transaction_hash.as_slice())?,
                    &private_key.to_secp256k1_secret_key(),
                );
                let mut signature = signature.serialize_der().as_ref().to_vec();
                signature.push((input.sighash_code as u32).to_le_bytes()[0]);
                let signature = [variable_length_integer(signature.len() as u64)?, signature].concat();

                // Public key
                let public_key = private_key.to_public_key();
                let public_key_bytes = match (&address.format(), public_key.is_compressed()) {
                    (DogecoinFormat::P2PKH, false) => public_key.to_secp256k1_public_key().serialize().to_vec(),
                    _ => public_key.to_secp256k1_public_key().serialize_compressed().to_vec(),
                };
                let public_key = [vec![public_key_bytes.len() as u8], public_key_bytes].concat();

                match &address.format() {
                    DogecoinFormat::P2PKH => {
                        transaction.parameters.inputs[vin].script_sig = [signature.clone(), public_key].concat();
                        transaction.parameters.inputs[vin].is_signed = true;
                    }
                    DogecoinFormat::P2WSH => {
                        let input_script = match &input.outpoint.redeem_script {
                            Some(redeem_script) => redeem_script.clone(),
                            None => return Err(TransactionError::InvalidInputs("P2WSH".into())),
                        };

                        let ser_input_script =
                            [variable_length_integer(input_script.len() as u64)?, input_script].concat();
                        transaction.parameters.segwit_flag = true;
                        transaction.parameters.inputs[vin].script_sig = vec![];
                        // TODO: (jaakinyele) Generalize to a vec of additional witnesses
                        let (other_signature, is_other_sig_first) =
                            match transaction.parameters.inputs[vin].additional_witness.clone() {
                                Some(n) => (n.0, n.1),
                                None => {
                                    return Err(TransactionError::InvalidInputs(
                                        "P2WSH: missing additional witness input to complete multi-sig".into(),
                                    ))
                                }
                            };
                        // Determine whether to append or prepend other signature(s)
                        let mut witness_field = match is_other_sig_first {
                            true => vec![other_signature, signature.clone()],
                            false => vec![signature.clone(), other_signature],
                        };
                        // Append witness stack script args (before witness script)
                        if transaction.parameters.inputs[vin].witness_script_data.is_some() {
                            let witness_script_data =
                                transaction.parameters.inputs[vin].witness_script_data.clone().unwrap();
                            let witness_script_data =
                                [vec![witness_script_data.len() as u8], witness_script_data].concat();
                            witness_field.append(&mut vec![witness_script_data]);
                        }
                        // Append the witness script last
                        witness_field.append(&mut vec![ser_input_script.clone()]);
                        transaction.parameters.inputs[vin].witnesses.append(&mut witness_field);
                        transaction.parameters.inputs[vin].is_signed = true;
                    }
                    DogecoinFormat::P2SH_P2WPKH => {
                        let input_script = match &input.outpoint.redeem_script {
                            Some(redeem_script) => redeem_script.clone(),
                            None => return Err(TransactionError::InvalidInputs("P2SH_P2WPKH".into())),
                        };

                        let sig = [partial_script.clone(), signature.clone()].concat();
                        let redeem_script =
                            [variable_length_integer(input_script.len() as u64)?, input_script].concat();
                        let input_script = redeem_script;
                        transaction.parameters.segwit_flag = false;
                        transaction.parameters.inputs[vin].script_sig = [sig, input_script].concat();

                        transaction.parameters.inputs[vin].is_signed = true;
                    }
                };
            }
        }
        // TODO: (raychu86) Raise error if no input was signed
        Ok(transaction)
    }
    /// Returns a signed transaction given the private key of the sender.
    fn sign(&self, private_key: &Self::PrivateKey) -> Result<Self, TransactionError> {
        let mut transaction = self.clone();
        for (vin, input) in self.parameters.inputs.iter().enumerate() {
            let address = match &input.outpoint.address {
                Some(address) => address,
                None => continue,
            };

            let address_is_valid = match &address.format() {
                DogecoinFormat::P2WSH => {
                    let input_script = match &input.outpoint.redeem_script {
                        Some(redeem_script) => redeem_script.clone(),
                        None => return Err(TransactionError::InvalidInputs("P2WSH".into())),
                    };
                    let c_address = DogecoinAddress::<N>::p2wsh(&input_script)?;
                    address == &c_address
                }
                _ => address == &private_key.to_address(&address.format())?,
            };

            if address_is_valid && !transaction.parameters.inputs[vin].is_signed {
                // Transaction hash
                let preimage = match &address.format() {
                    DogecoinFormat::P2PKH => transaction.p2pkh_hash_preimage(vin, input.sighash_code)?,
                    _ => transaction.hash_preimage(vin, input.sighash_code)?,
                };

                let transaction_hash = Sha256::digest(&Sha256::digest(&preimage));

                // Signature
                let (signature, _) = secp256k1::sign(
                    &secp256k1::Message::parse_slice(&transaction_hash)?,
                    &private_key.to_secp256k1_secret_key(),
                );
                let mut signature = signature.serialize_der().as_ref().to_vec();
                signature.push((input.sighash_code as u32).to_le_bytes()[0]);
                let signature = [variable_length_integer(signature.len() as u64)?, signature].concat();

                // Public key
                let public_key = private_key.to_public_key();
                let public_key_bytes = match (&address.format(), public_key.is_compressed()) {
                    (DogecoinFormat::P2PKH, false) => public_key.to_secp256k1_public_key().serialize().to_vec(),
                    _ => public_key.to_secp256k1_public_key().serialize_compressed().to_vec(),
                };
                let public_key = [vec![public_key_bytes.len() as u8], public_key_bytes].concat();

                match &address.format() {
                    DogecoinFormat::P2PKH => {
                        transaction.parameters.inputs[vin].script_sig = [signature.clone(), public_key].concat();
                        transaction.parameters.inputs[vin].is_signed = true;
                    }
                    DogecoinFormat::P2WSH => {
                        let input_script = match &input.outpoint.redeem_script {
                            Some(redeem_script) => redeem_script.clone(),
                            None => return Err(TransactionError::InvalidInputs("P2WSH".into())),
                        };

                        let ser_input_script =
                            [variable_length_integer(input_script.len() as u64)?, input_script].concat();
                        transaction.parameters.segwit_flag = true;
                        transaction.parameters.inputs[vin].script_sig = vec![];
                        // TODO: (jaakinyele) Generalize to a vec of additional witnesses
                        let (other_signature, is_other_sig_first) =
                            match transaction.parameters.inputs[vin].additional_witness.clone() {
                                Some(n) => (n.0, n.1),
                                None => {
                                    return Err(TransactionError::InvalidInputs(
                                        "P2WSH: missing additional witness input to complete multi-sig".into(),
                                    ))
                                }
                            };
                        // Determine whether to append or prepend other signature(s)
                        let mut witness_field = match is_other_sig_first {
                            true => vec![other_signature, signature.clone()],
                            false => vec![signature.clone(), other_signature],
                        };
                        // Append witness stack script args (before witness script)
                        if transaction.parameters.inputs[vin].witness_script_data.is_some() {
                            let witness_script_data =
                                transaction.parameters.inputs[vin].witness_script_data.clone().unwrap();
                            let witness_script_data =
                                [vec![witness_script_data.len() as u8], witness_script_data].concat();
                            witness_field.append(&mut vec![witness_script_data]);
                        }
                        // Append the witness script last
                        witness_field.append(&mut vec![ser_input_script.clone()]);
                        transaction.parameters.inputs[vin].witnesses.append(&mut witness_field);
                        transaction.parameters.inputs[vin].is_signed = true;
                    }
                    DogecoinFormat::P2SH_P2WPKH => {
                        let input_script = match &input.outpoint.redeem_script {
                            Some(redeem_script) => redeem_script.clone(),
                            None => return Err(TransactionError::InvalidInputs("P2SH_P2WPKH".into())),
                        };
                        let start = [0x5a, 0x0].to_vec();
                        let sig = [start, signature.clone()].concat();
                        let redeem_script =
                            [variable_length_integer(input_script.len() as u64)?, input_script].concat();
                        let input_script = [vec![0x4c], redeem_script].concat();
                        transaction.parameters.segwit_flag = false;
                        transaction.parameters.inputs[vin].script_sig = [sig, input_script].concat();

                        transaction.parameters.inputs[vin].is_signed = true;
                    }
                };
            }
        }
        // TODO: (raychu86) Raise error if no input was signed
        Ok(transaction)
    }

    /// Returns a transaction given the transaction bytes.
    /// Note:: Raw transaction hex does not include enough
    fn from_transaction_bytes(transaction: &Vec<u8>) -> Result<Self, TransactionError> {
        Ok(Self {
            parameters: Self::TransactionParameters::read(&transaction[..])?,
        })
    }

    /// Returns the transaction in bytes.
    fn to_transaction_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let mut transaction = self.parameters.version.to_le_bytes().to_vec();

        if self.parameters.segwit_flag {
            transaction.extend(vec![0x00, 0x01]);
        }

        transaction.extend(variable_length_integer(self.parameters.inputs.len() as u64)?);
        let mut has_witness = false;
        for input in &self.parameters.inputs {
            if !has_witness {
                has_witness = input.witnesses.len() > 0;
            }
            transaction.extend(input.serialize(!input.is_signed)?);
        }

        transaction.extend(variable_length_integer(self.parameters.outputs.len() as u64)?);
        for output in &self.parameters.outputs {
            transaction.extend(output.serialize()?);
        }

        if has_witness {
            for input in &self.parameters.inputs {
                match input.witnesses.len() {
                    0 => transaction.extend(vec![0x00]),
                    _ => {
                        transaction.extend(variable_length_integer(input.witnesses.len() as u64)?);
                        for witness in &input.witnesses {
                            transaction.extend(witness);
                        }
                    }
                };
            }
        }

        transaction.extend(&self.parameters.lock_time.to_le_bytes());

        Ok(transaction)
    }

    /// Returns the transaction id.
    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        let mut txid = Sha256::digest(&Sha256::digest(&self.to_transaction_bytes_without_witness()?)).to_vec();
        let mut wtxid = Sha256::digest(&Sha256::digest(&self.to_transaction_bytes()?)).to_vec();

        txid.reverse();
        wtxid.reverse();

        Ok(Self::TransactionId { txid, wtxid })
    }
}

impl<N: DogecoinNetwork> DogecoinTransaction<N> {
    /// Return the P2PKH hash preimage of the raw transaction.
    pub fn p2pkh_hash_preimage(&self, vin: usize, sighash: SignatureHash) -> Result<Vec<u8>, TransactionError> {
        let mut preimage = self.parameters.version.to_le_bytes().to_vec();
        preimage.extend(variable_length_integer(self.parameters.inputs.len() as u64)?);
        for (index, input) in self.parameters.inputs.iter().enumerate() {
            preimage.extend(input.serialize(index != vin)?);
        }
        preimage.extend(variable_length_integer(self.parameters.outputs.len() as u64)?);
        for output in &self.parameters.outputs {
            preimage.extend(output.serialize()?);
        }
        preimage.extend(&self.parameters.lock_time.to_le_bytes());
        preimage.extend(&(sighash as u32).to_le_bytes());
        Ok(preimage)
    }
    /// Return the old hash preimage of the raw transaction
    pub fn hash_preimage(&self, vin: usize, sighash_type: SignatureHash) -> Result<Vec<u8>, TransactionError> {
        let input = &self.parameters.inputs[vin];
        let format = match &input.outpoint.address {
            Some(address) => address.format(),
            None => return Err(TransactionError::MissingOutpointAddress),
        };

        let script = match format {
            DogecoinFormat::P2SH_P2WPKH => match &input.outpoint.redeem_script {
                Some(redeem_script) => redeem_script.to_vec(),
                None => return Err(TransactionError::InvalidInputs("P2WSH".into())),
            },

            _ => return Err(TransactionError::UnsupportedPreimage("P2PKH".into())),
        };

        let mut preimage = vec![];
        preimage.extend(self.parameters.version.to_le_bytes());
        preimage.extend(variable_length_integer(self.parameters.inputs.len() as u64).unwrap());
        let index: u32 = input.outpoint.index;

        let txid = &input.outpoint.reverse_transaction_id;

        preimage.extend(txid);
        preimage.extend(index.to_le_bytes());
        preimage.extend(variable_length_integer(script.len() as u64).unwrap());
        preimage.extend(script);
        preimage.extend(&input.sequence);

        preimage.extend(variable_length_integer(self.parameters.outputs.len() as u64).unwrap());
        for output in &self.parameters.outputs {
            preimage.extend(&output.serialize().unwrap());
        }

        preimage.extend(&self.parameters.lock_time.to_le_bytes());
        preimage.extend(&(sighash_type as u32).to_le_bytes());
        Ok(preimage)
    }
    /// Return the SegWit hash preimage of the raw transaction
    /// https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
    pub fn segwit_hash_preimage(&self, vin: usize, sighash: SignatureHash) -> Result<Vec<u8>, TransactionError> {
        let mut prev_outputs = vec![];
        let mut prev_sequences = vec![];
        let mut outputs = vec![];

        for input in &self.parameters.inputs {
            prev_outputs.extend(&input.outpoint.reverse_transaction_id);
            prev_outputs.extend(&input.outpoint.index.to_le_bytes());
            prev_sequences.extend(&input.sequence);
        }

        for output in &self.parameters.outputs {
            outputs.extend(&output.serialize()?);
        }

        let input = &self.parameters.inputs[vin];
        let format = match &input.outpoint.address {
            Some(address) => address.format(),
            None => return Err(TransactionError::MissingOutpointAddress),
        };

        let script = match format {
            DogecoinFormat::P2WSH => match &input.outpoint.redeem_script {
                Some(redeem_script) => redeem_script.to_vec(),
                None => return Err(TransactionError::InvalidInputs("P2WSH".into())),
            },
            DogecoinFormat::P2SH_P2WPKH => match &input.outpoint.redeem_script {
                Some(redeem_script) => redeem_script[1..].to_vec(),
                None => return Err(TransactionError::InvalidInputs("P2SH_P2WPKH".into())),
            },
            DogecoinFormat::P2PKH => return Err(TransactionError::UnsupportedPreimage("P2PKH".into())),
        };

        let mut script_code = vec![];
        if format == DogecoinFormat::P2WSH {
            script_code.extend(script);
        } else {
            script_code.push(Opcode::OP_DUP as u8);
            script_code.push(Opcode::OP_HASH160 as u8);
            script_code.extend(script);
            script_code.push(Opcode::OP_EQUALVERIFY as u8);
            script_code.push(Opcode::OP_CHECKSIG as u8);
        }
        let script_code = [variable_length_integer(script_code.len() as u64)?, script_code].concat();
        let hash_prev_outputs = Sha256::digest(&Sha256::digest(&prev_outputs));
        let hash_sequence = Sha256::digest(&Sha256::digest(&prev_sequences));
        let hash_outputs = Sha256::digest(&Sha256::digest(&outputs));
        let outpoint_amount = match &input.outpoint.amount {
            Some(amount) => amount.0.to_le_bytes(),
            None => return Err(TransactionError::MissingOutpointAmount),
        };

        let mut preimage = vec![];
        preimage.extend(&self.parameters.version.to_le_bytes());
        preimage.extend(hash_prev_outputs);
        preimage.extend(hash_sequence);
        preimage.extend(&input.outpoint.reverse_transaction_id);
        preimage.extend(&input.outpoint.index.to_le_bytes());
        preimage.extend(&script_code);
        preimage.extend(&outpoint_amount);
        preimage.extend(&input.sequence);
        preimage.extend(hash_outputs);
        preimage.extend(&self.parameters.lock_time.to_le_bytes());
        preimage.extend(&(sighash as u32).to_le_bytes());

        Ok(preimage)
    }

    /// Returns the transaction with the traditional serialization (no witness).
    fn to_transaction_bytes_without_witness(&self) -> Result<Vec<u8>, TransactionError> {
        let mut transaction = self.parameters.version.to_le_bytes().to_vec();

        transaction.extend(variable_length_integer(self.parameters.inputs.len() as u64)?);
        for input in &self.parameters.inputs {
            transaction.extend(input.serialize(false)?);
        }

        transaction.extend(variable_length_integer(self.parameters.outputs.len() as u64)?);
        for output in &self.parameters.outputs {
            transaction.extend(output.serialize()?);
        }

        transaction.extend(&self.parameters.lock_time.to_le_bytes());

        Ok(transaction)
    }

    /// Update a transaction's input outpoint
    #[allow(dead_code)]
    pub fn update_outpoint(&self, outpoint: Outpoint<N>) -> Self {
        let mut new_transaction = self.clone();
        for (vin, input) in self.parameters.inputs.iter().enumerate() {
            if &outpoint.reverse_transaction_id == &input.outpoint.reverse_transaction_id
                && &outpoint.index == &input.outpoint.index
            {
                new_transaction.parameters.inputs[vin].outpoint = outpoint.clone();
            }
        }
        new_transaction
    }
}

impl<N: DogecoinNetwork> FromStr for DogecoinTransaction<N> {
    type Err = TransactionError;

    fn from_str(transaction: &str) -> Result<Self, Self::Err> {
        Self::from_transaction_bytes(&hex::decode(transaction)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Mainnet;
    use wagyu_model::crypto::hash160;

    pub struct TransactionTestCase<'a> {
        pub version: u32,
        pub lock_time: u32,
        pub inputs: &'a [Input],
        pub outputs: &'a [Output],
        pub expected_signed_transaction: &'a str,
        pub expected_transaction_id: &'a str,
    }

    #[derive(Debug, Clone)]
    pub struct Input {
        pub private_key: &'static str,
        pub address_format: DogecoinFormat,
        pub transaction_id: &'static str,
        pub index: u32,
        pub redeem_script: Option<&'static str>,
        pub script_pub_key: Option<&'static str>,
        pub utxo_amount: DogecoinAmount,
        pub sequence: Option<[u8; 4]>,
        pub sighash_code: SignatureHash,
    }

    #[derive(Clone)]
    pub struct Output {
        pub address: &'static str,
        pub amount: DogecoinAmount,
    }

    fn test_multisig_transaction<N: DogecoinNetwork>(
        version: u32,
        lock_time: u32,
        inputs: Vec<Input>,
        outputs: Vec<Output>,
        expected_signed_transaction: &str,
        expected_transaction_id: &str,
    ) {
        let mut input_vec = vec![];
        for input in &inputs {
            let private_key = DogecoinPrivateKey::from_str(input.private_key).unwrap();
            let transaction_id = hex::decode(input.transaction_id).unwrap();
            let redeem_script = match (input.redeem_script, input.address_format.clone()) {
                (Some(script), DogecoinFormat::P2WSH) => Some(hex::decode(script).unwrap()),
                (Some(script), _) => Some(hex::decode(script).unwrap()),
                (None, DogecoinFormat::P2SH_P2WPKH) => {
                    let mut redeem_script = vec![0x00, 0x14];
                    redeem_script.extend(&hash160(
                        &private_key
                            .to_public_key()
                            .to_secp256k1_public_key()
                            .serialize_compressed(),
                    ));
                    Some(redeem_script)
                }
                (None, _) => None,
            };
            let address = match &input.address_format {
                DogecoinFormat::P2WSH => DogecoinAddress::<N>::p2wsh(redeem_script.as_ref().unwrap()).unwrap(),
                _ => private_key.to_address(&input.address_format).unwrap(),
            };
            let script_pub_key = input.script_pub_key.map(|script| hex::decode(script).unwrap());
            let sequence = input.sequence.map(|seq| seq.to_vec());
            let mut transaction_input = DogecoinTransactionInput::<N>::new(
                transaction_id,
                input.index,
                Some(address),
                Some(input.utxo_amount),
                redeem_script,
                script_pub_key,
                sequence,
                input.sighash_code,
            )
            .unwrap();

            // check if P2WSH input (include any additional witness)
            transaction_input.additional_witness = Some((vec![0x00], false));
            transaction_input.witness_script_data = None;

            input_vec.push(transaction_input);
        }

        let mut output_vec = vec![];
        for output in outputs {
            let address = DogecoinAddress::<N>::from_str(output.address);
            if address.is_ok() {
                output_vec.push(DogecoinTransactionOutput::new(&address.unwrap(), output.amount).unwrap());
            } else {
                let tx_output = DogecoinTransactionOutput {
                    amount: output.amount,
                    script_pub_key: hex::decode(output.address).unwrap(),
                };
                output_vec.push(tx_output);
            }
        }

        let transaction_parameters = DogecoinTransactionParameters::<N> {
            version,
            inputs: input_vec,
            outputs: output_vec,
            lock_time,
            segwit_flag: false,
        };

        let mut transaction = DogecoinTransaction::<N>::new(&transaction_parameters).unwrap();

        // Sign transaction
        for input in inputs {
            transaction = transaction
                .sign(&DogecoinPrivateKey::from_str(input.private_key).unwrap())
                .unwrap();
        }

        let signed_transaction_without_witness =
            hex::encode(&transaction.to_transaction_bytes_without_witness().unwrap());
        let transaction_id = hex::encode(&transaction.to_transaction_id().unwrap().txid);

        assert_eq!(expected_signed_transaction, &signed_transaction_without_witness);
        assert_eq!(expected_transaction_id, &transaction_id);
    }

    fn test_transaction_ps<N: DogecoinNetwork>(
        version: u32,
        lock_time: u32,
        inputs: Vec<Input>,
        outputs: Vec<Output>,
        expected_signed_transaction: &str,
        expected_transaction_id: &str,
    ) {
        let mut input_vec = vec![];
        for input in &inputs {
            let private_key = DogecoinPrivateKey::from_str(input.private_key).unwrap();
            let address = private_key.to_address(&input.address_format).unwrap();
            let transaction_id = hex::decode(input.transaction_id).unwrap();
            let redeem_script = match (input.redeem_script, input.address_format.clone()) {
                (Some(script), _) => Some(hex::decode(script).unwrap()),
                (None, DogecoinFormat::P2SH_P2WPKH) => {
                    let mut redeem_script = vec![0x00, 0x14];
                    redeem_script.extend(&hash160(
                        &private_key
                            .to_public_key()
                            .to_secp256k1_public_key()
                            .serialize_compressed(),
                    ));
                    Some(redeem_script)
                }
                (None, _) => None,
            };
            let script_pub_key = input.script_pub_key.map(|script| hex::decode(script).unwrap());
            let sequence = input.sequence.map(|seq| seq.to_vec());
            let transaction_input = DogecoinTransactionInput::<N>::new(
                transaction_id,
                input.index,
                Some(address),
                Some(input.utxo_amount),
                redeem_script,
                script_pub_key,
                sequence,
                input.sighash_code,
            )
            .unwrap();

            input_vec.push(transaction_input);
        }

        let mut output_vec = vec![];
        for output in outputs {
            let address = DogecoinAddress::<N>::from_str(output.address).unwrap();
            output_vec.push(DogecoinTransactionOutput::new(&address, output.amount).unwrap());
        }

        let transaction_parameters = DogecoinTransactionParameters::<N> {
            version,
            inputs: input_vec,
            outputs: output_vec,
            lock_time,
            segwit_flag: false,
        };

        let mut transaction = DogecoinTransaction::<N>::new(&transaction_parameters).unwrap();
        let inscribe_str = "036f72645118746578742f706c61696e3b636861727365743d7574662d3800357b2270223a226472632d3230222c226f70223a226d696e74222c227469636b223a2238622174222c22616d74223a2231303030227d";
        let partial_script = hex::decode(inscribe_str).unwrap();
        // Sign transaction
        for input in inputs {
            transaction = transaction
                .partial_sign(
                    &DogecoinPrivateKey::from_str(input.private_key).unwrap(),
                    &partial_script,
                )
                .unwrap();
        }

        let signed_transaction = hex::encode(&transaction.to_transaction_bytes().unwrap());
        let transaction_id = hex::encode(&transaction.to_transaction_id().unwrap().txid);
        println!("signed transaction {}", signed_transaction);
        assert_eq!(expected_signed_transaction, &signed_transaction);
        assert_eq!(expected_transaction_id, &transaction_id);
    }

    fn test_transaction<N: DogecoinNetwork>(
        version: u32,
        lock_time: u32,
        inputs: Vec<Input>,
        outputs: Vec<Output>,
        expected_signed_transaction: &str,
        expected_transaction_id: &str,
    ) {
        let mut input_vec = vec![];
        for input in &inputs {
            let private_key = DogecoinPrivateKey::from_str(input.private_key).unwrap();
            let address = private_key.to_address(&input.address_format).unwrap();
            let transaction_id = hex::decode(input.transaction_id).unwrap();
            let redeem_script = match (input.redeem_script, input.address_format.clone()) {
                (Some(script), _) => Some(hex::decode(script).unwrap()),
                (None, DogecoinFormat::P2SH_P2WPKH) => {
                    let mut redeem_script = vec![0x00, 0x14];
                    redeem_script.extend(&hash160(
                        &private_key
                            .to_public_key()
                            .to_secp256k1_public_key()
                            .serialize_compressed(),
                    ));
                    Some(redeem_script)
                }
                (None, _) => None,
            };
            let script_pub_key = input.script_pub_key.map(|script| hex::decode(script).unwrap());
            let sequence = input.sequence.map(|seq| seq.to_vec());
            let transaction_input = DogecoinTransactionInput::<N>::new(
                transaction_id,
                input.index,
                Some(address),
                Some(input.utxo_amount),
                redeem_script,
                script_pub_key,
                sequence,
                input.sighash_code,
            )
            .unwrap();

            input_vec.push(transaction_input);
        }

        let mut output_vec = vec![];
        for output in outputs {
            let address = DogecoinAddress::<N>::from_str(output.address).unwrap();
            output_vec.push(DogecoinTransactionOutput::new(&address, output.amount).unwrap());
        }

        let transaction_parameters = DogecoinTransactionParameters::<N> {
            version,
            inputs: input_vec,
            outputs: output_vec,
            lock_time,
            segwit_flag: false,
        };

        let mut transaction = DogecoinTransaction::<N>::new(&transaction_parameters).unwrap();

        // Sign transaction
        for input in inputs {
            transaction = transaction
                .sign(&DogecoinPrivateKey::from_str(input.private_key).unwrap())
                .unwrap();
        }

        let signed_transaction = hex::encode(&transaction.to_transaction_bytes().unwrap());
        let transaction_id = hex::encode(&transaction.to_transaction_id().unwrap().txid);
        println!("signed transaction {}", signed_transaction);
        assert_eq!(expected_signed_transaction, &signed_transaction);
        assert_eq!(expected_transaction_id, &transaction_id);
    }

    fn test_reconstructed_transaction<N: DogecoinNetwork>(
        version: u32,
        lock_time: u32,
        inputs: Vec<Input>,
        outputs: Vec<Output>,
        expected_signed_transaction: &str,
        expected_transaction_id: &str,
    ) {
        let mut input_vec = vec![];
        for input in &inputs {
            let private_key = DogecoinPrivateKey::from_str(input.private_key).unwrap();
            let address = private_key.to_address(&input.address_format).unwrap();
            let transaction_id = hex::decode(input.transaction_id).unwrap();
            let redeem_script = match (input.redeem_script, input.address_format.clone()) {
                (Some(script), _) => Some(hex::decode(script).unwrap()),
                (None, DogecoinFormat::P2SH_P2WPKH) => {
                    let mut redeem_script = vec![0x00, 0x14];
                    redeem_script.extend(&hash160(
                        &private_key
                            .to_public_key()
                            .to_secp256k1_public_key()
                            .serialize_compressed(),
                    ));
                    Some(redeem_script)
                }
                (None, _) => None,
            };
            let script_pub_key = input.script_pub_key.map(|script| hex::decode(script).unwrap());
            let sequence = input.sequence.map(|seq| seq.to_vec());
            let transaction_input = DogecoinTransactionInput::<N>::new(
                transaction_id,
                input.index,
                Some(address),
                Some(input.utxo_amount),
                redeem_script,
                script_pub_key,
                sequence,
                input.sighash_code,
            )
            .unwrap();

            input_vec.push(transaction_input);
        }

        let mut output_vec = vec![];
        for output in outputs {
            let address = DogecoinAddress::<N>::from_str(output.address).unwrap();
            output_vec.push(DogecoinTransactionOutput::new(&address, output.amount).unwrap());
        }

        let transaction_parameters = DogecoinTransactionParameters::<N> {
            version,
            inputs: input_vec.clone(),
            outputs: output_vec,
            lock_time,
            segwit_flag: false,
        };

        let transaction = DogecoinTransaction::<N>::new(&transaction_parameters).unwrap();
        let unsigned_raw_transaction = hex::encode(&transaction.to_transaction_bytes().unwrap());

        let mut new_transaction = DogecoinTransaction::<N>::from_str(&unsigned_raw_transaction).unwrap();

        // Sign transaction reconstructed from hex
        for input in inputs {
            let partial_signed_transaction = hex::encode(&new_transaction.to_transaction_bytes().unwrap());
            new_transaction = DogecoinTransaction::<N>::from_str(&partial_signed_transaction).unwrap();

            let mut reverse_transaction_id = hex::decode(input.transaction_id).unwrap();
            reverse_transaction_id.reverse();
            let tx_input = input_vec.iter().cloned().find(|tx_input| {
                tx_input.outpoint.reverse_transaction_id == reverse_transaction_id
                    && tx_input.outpoint.index == input.index
            });

            if let Some(tx_input) = tx_input {
                new_transaction = new_transaction.update_outpoint(tx_input.outpoint);
                new_transaction = new_transaction
                    .sign(&DogecoinPrivateKey::from_str(input.private_key).unwrap())
                    .unwrap();
            }
        }

        let new_signed_transaction = hex::encode(new_transaction.to_transaction_bytes().unwrap());

        let new_transaction_id = new_transaction.to_transaction_id().unwrap().to_string();

        assert_eq!(expected_signed_transaction, &new_signed_transaction);
        assert_eq!(expected_transaction_id, &new_transaction_id);
    }
    fn test_transaction_new<N: DogecoinNetwork>(
        version: u32,
        lock_time: u32,
        inputs: Vec<Input>,
        outputs: Vec<Output>,
        expected_signed_transaction: &str,
        expected_transaction_id: &str,
    ) {
        let mut input_vec = vec![];
        for input in &inputs {
            let private_key = DogecoinPrivateKey::from_str(input.private_key).unwrap();
            let address = private_key.to_address(&input.address_format).unwrap();
            let transaction_id = hex::decode(input.transaction_id).unwrap();
            let redeem_script = match (input.redeem_script, input.address_format.clone()) {
                (Some(script), _) => Some(hex::decode(script).unwrap()),
                (None, DogecoinFormat::P2SH_P2WPKH) => {
                    let mut redeem_script = vec![0x00, 0x14];
                    redeem_script.extend(&hash160(
                        &private_key
                            .to_public_key()
                            .to_secp256k1_public_key()
                            .serialize_compressed(),
                    ));
                    Some(redeem_script)
                }
                (None, _) => None,
            };
            let script_pub_key = input.script_pub_key.map(|script| hex::decode(script).unwrap());
            let sequence = input.sequence.map(|seq| seq.to_vec());
            let transaction_input = DogecoinTransactionInput::<N>::new(
                transaction_id,
                input.index,
                Some(address),
                Some(input.utxo_amount),
                redeem_script,
                script_pub_key,
                sequence,
                input.sighash_code,
            )
            .unwrap();

            input_vec.push(transaction_input);
        }

        let mut output_vec = vec![];
        for output in outputs {
            let address = DogecoinAddress::<N>::from_str(output.address).unwrap();
            output_vec.push(DogecoinTransactionOutput::new(&address, output.amount).unwrap());
        }

        let transaction_parameters = DogecoinTransactionParameters::<N> {
            version,
            inputs: input_vec,
            outputs: output_vec,
            lock_time,
            segwit_flag: false,
        };

        let transaction = DogecoinTransaction::<N>::new(&transaction_parameters).unwrap();

        let mut preimage = vec![];
        preimage.extend(transaction.parameters.version.to_le_bytes());
        preimage.extend(variable_length_integer(transaction.parameters.inputs.len() as u64).unwrap());
        let index: u32 = 0;
        for input in transaction.parameters.inputs {
            let txid = input.outpoint.reverse_transaction_id;

            preimage.extend(txid);
            preimage.extend(index.to_le_bytes());
            if let Some(script) = input.outpoint.redeem_script {
                preimage.extend(variable_length_integer(script.len() as u64).unwrap());
                preimage.extend(script);
                preimage.extend(input.sequence);
            }
        }
        preimage.extend(variable_length_integer(transaction.parameters.outputs.len() as u64).unwrap());
        for output in transaction.parameters.outputs {
            preimage.extend(&output.serialize().unwrap());
        }
        let sighash_type = SignatureHash::SIGHASH_ALL;
        preimage.extend(&transaction.parameters.lock_time.to_le_bytes());
        preimage.extend(&(sighash_type as u32).to_le_bytes());
    }
    #[test]
    fn test_sighash() {
        let preimage_str = "01000000022a78d590bffab4ba11e5ef2effd1170901fbcdf84713928f1e0f224b2ceafa6d0000000029210221e8d62fbc14c60861cd9e8068c5557837b42d86a855852b94fc84c2a548e7d3ad757575757551ffffffff02a0860100000000001976a9148700b1ef1b640d1dd14c6e0b510567869317ea8c88acfc25cf40000000001976a914a38e2c3b36c3547f3c67f36fe40021d88a8ccf7388ac0000000001000000";
        let preimage = hex::decode(preimage_str).unwrap();
        let transaction_hash = Sha256::digest(&Sha256::digest(&preimage));
        println!("sighash: {:x?}", transaction_hash.to_vec());
    }
    mod test_valid_mainnet_transactions {
        use super::*;
        type N = Mainnet;

        const TRANSACTIONS: [TransactionTestCase; 1] = [
            // TransactionTestCase { // p2pkh to p2pkh - based on https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/test/integration/transactions.js
            //     version: 1,
            //     lock_time: 0,
            //     inputs: &[
            //         Input {
            //             private_key: "QRJx7uvj55L3oVRADWJfFjJ31H9Beg75xZ2GcmR8rKFNHA4ZacKJ",
            //             address_format: DogecoinFormat::P2SH_P2WPKH,
            //             transaction_id: "52491cf5bafff1b1098d997a93429f818239e764084007e4fbef8b290dde051e",
            //             index: 0,
            //             redeem_script: Some("51210339b5b2e90a6e3939c6197f1a1ef9d14af856f76b4234cbf7b34ead7d904fef5251ae036f726418746578742f706c61696e3b636861727365743d7574662d384c4d7b22616d74223a22313030303030303030222c226f70223a227472616e73666572222c2270223a226472632d3230222c227469636b223a2257444f474528575241505045442d444f474529227d75757575"),
            //             script_pub_key: None,
            //             utxo_amount: DogecoinAmount(99448207),
            //             sequence: Some([0xff, 0xff, 0xff, 0xff]),
            //             sighash_code: SignatureHash::SIGHASH_ALL
            //         },
            //     ],
            //     outputs: &[
            //         Output {
            //             address: "DTZSTXecLmSXpRGSfht4tAMyqra1wsL7xb",
            //             amount: DogecoinAmount(100000)
            //         },
            //         Output {
            //             address: "D92uJjQ9eHUcv2GjJUgp6m58V8wYvGV2g9",
            //             amount: DogecoinAmount(89027161)
            //         },
            //     ],
            //     expected_signed_transaction: "01000000011e05de0d298beffbe407400864e73982819f42937a998d09b1f1ffbaf51c495200000000e15a00473044022028757c5e87c8997044ad23de3b27e5f5f64ea9f2e6905afd9e2d3529379aa60a02204cd926c1e73bd9a347ec9993177db5c2b207586d9bb89bd7d489bc312e1f2aa4014c9551210339b5b2e90a6e3939c6197f1a1ef9d14af856f76b4234cbf7b34ead7d904fef5251ae036f726418746578742f706c61696e3b636861727365743d7574662d384c4d7b22616d74223a22313030303030303030222c226f70223a227472616e73666572222c2270223a226472632d3230222c227469636b223a2257444f474528575241505045442d444f474529227d75757575ffffffff02a0860100000000001976a914f5ed609ea6c6bacc5314e9a1a4eabd45457849d088ac59724e05000000001976a9142ab4a15e6855c0b4512b0792a4508bf4b17bfc9588ac00000000",
            //     expected_transaction_id: "ee2724816de845063a22b74b7b0fc91a837dfb2bd3e315a205246fd20f52d3a8",
            // },
            TransactionTestCase {
                // p2pkh to p2pkh - based on https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/test/integration/transactions.js
                version: 1,
                lock_time: 0,
                inputs: &[Input {
                    private_key: "QSqGTn8B4YBU9Gw54HnDY2niy86rZuZ7sipiwfLQTscuxeHbzRSP",
                    address_format: DogecoinFormat::P2SH_P2WPKH,
                    transaction_id: "32f31978a5110f5b023822508cadc85598a6f593b6be2940c58160cc2b930ea2",
                    index: 0,
                    redeem_script: Some(
                        "21033dd3bdefd734c879196e1a966f038808a59f3b214e32922f2a564666c2754ec5ad757575757551",
                    ),
                    script_pub_key: None,
                    utxo_amount: DogecoinAmount(99448207),
                    sequence: Some([0xff, 0xff, 0xff, 0xff]),
                    sighash_code: SignatureHash::SIGHASH_ALL,
                }],
                outputs: &[Output {
                    address: "DNLAAKAJZf4h8pheVSquisEyKCqDNDRGYm",
                    amount: DogecoinAmount(100000),
                }],
                expected_signed_transaction: "",
                expected_transaction_id: "",
            },
        ];
        #[test]
        fn test_transactions_ps() {
            TRANSACTIONS.iter().for_each(|transaction| {
                test_transaction_ps::<N>(
                    transaction.version,
                    transaction.lock_time,
                    transaction.inputs.to_vec(),
                    transaction.outputs.to_vec(),
                    transaction.expected_signed_transaction,
                    transaction.expected_transaction_id,
                );
            });
        }
        #[test]
        fn test_sig() {
            TRANSACTIONS.iter().for_each(|transaction| {
                test_transaction_new::<N>(
                    transaction.version,
                    transaction.lock_time,
                    transaction.inputs.to_vec(),
                    transaction.outputs.to_vec(),
                    transaction.expected_signed_transaction,
                    transaction.expected_transaction_id,
                );
            });
        }
        #[test]
        fn test_mainnet_transactions() {
            TRANSACTIONS.iter().for_each(|transaction| {
                test_transaction::<N>(
                    transaction.version,
                    transaction.lock_time,
                    transaction.inputs.to_vec(),
                    transaction.outputs.to_vec(),
                    transaction.expected_signed_transaction,
                    transaction.expected_transaction_id,
                );
            });
        }

        #[test]
        fn test_reconstructed_mainnet_transactions() {
            TRANSACTIONS.iter().for_each(|transaction| {
                test_reconstructed_transaction::<N>(
                    transaction.version,
                    transaction.lock_time,
                    transaction.inputs.to_vec(),
                    transaction.outputs.to_vec(),
                    transaction.expected_signed_transaction,
                    transaction.expected_transaction_id,
                );
            });
        }
    }

    mod test_real_mainnet_transactions {
        use super::*;
        type N = Mainnet;

        const REAL_TRANSACTIONS: [TransactionTestCase; 3] = [
            TransactionTestCase { // Transaction 1 -> Segwit P2SH_P2WPKH to P2PKH and Bech32(P2WPKH)
                version: 1,
                lock_time: 0,
                inputs: &[
                    Input {
                        private_key: "L1fUQgwdWcqGUAr3kFznuAP36Vw3oFeGHH29XRYMwxN1HpSw5yBm",
                        address_format: DogecoinFormat::P2SH_P2WPKH,
                        transaction_id: "a5766fafb27aba97e7aeb3e71be79806dd23f03bbd1b61135bf5792159f42ab6",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: DogecoinAmount(80000),
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                ],
                outputs: &[
                    Output {
                        address: "176DPNootfp2bSiE7KQUZp1VZj5EyGQeCt",
                        amount: DogecoinAmount(35000)
                    },
                    Output {
                        address: "bc1qcsjz44ce84j3650qfu9k87tyd3z8h4qyxz470n",
                        amount: DogecoinAmount(35000)
                    },
                ],
                expected_signed_transaction: "01000000000101b62af4592179f55b13611bbd3bf023dd0698e71be7b3aee797ba7ab2af6f76a50000000017160014b5ccbe3c5a285af4afada113a8619827fb30b2eeffffffff02b8880000000000001976a91442cd2c7460acc561c96b11c4aa96d0346b84db7f88acb888000000000000160014c4242ad7193d651d51e04f0b63f9646c447bd404024730440220449ca32ff3f8da3c17c1813dac91010cb1fea7a77b2f63065184b8318e1b9ed70220315da34cfeae62c26557c40f5ac5cde46b2801349e6677fc96597b4bfee04b0b012102973e9145ca85357b06de3009a12db171d70bae8a648dc8188e49723a2a46459100000000",
                expected_transaction_id: "60805eb82c53d9c53900ad6d1c423ffc2235caa0c266625afd9cf03e856bf92c",
            },
            TransactionTestCase { // Transaction 2 -> P2PKH to P2SH_P2WPKH and P2PKH uncompressed
                version: 1,
                lock_time: 0,
                inputs: &[
                    Input {
                        private_key: "KzZQ4ZzAecDmeDqxEJqSKpCfpPCa1x74ouyBhXUgMV2UdqNcaJiJ",
                        address_format: DogecoinFormat::P2PKH,
                        transaction_id: "60805eb82c53d9c53900ad6d1c423ffc2235caa0c266625afd9cf03e856bf92c",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: DogecoinAmount(0),
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                ],
                outputs: &[
                    Output {
                        address: "3QDTHVyuJrHixUhhsdZXQ7M8P9MQngmw1P",
                        amount: DogecoinAmount(12000)
                    },
                    Output {
                        address: "1C5RdoaGMVyQy8qjk96NsL4dW79aVPYrCK",
                        amount: DogecoinAmount(12000)
                    },
                ],
                expected_signed_transaction: "01000000012cf96b853ef09cfd5a6266c2a0ca3522fc3f421c6dad0039c5d9532cb85e8060000000006a473044022079471aadca4be014260a4788e7dc7d7168712c8f21c536f326caccb843569ab802206c7b464e3fbe0518f147ee7c5fa39c05e04e7ed17fbe464a2773b179fe0ef35401210384faa5d9710f727523906f6d2fe781b40cf58a3139d02eeaad293dd03be7b69cffffffff02e02e00000000000017a914f7146aaa6f24a1012528c1d27cfe49d256d5a70187e02e0000000000001976a914797f9c80ef57ba7f30b31598383683923a5a7a7c88ac00000000",
                expected_transaction_id: "76ef90fa70e4c10adc358432a979683a2cf1855ff545f88c5022dea8863ed5ab",
            },
            TransactionTestCase { // Transaction 4 -> Segwit P2SH_P2WPKH to Bech32(P2WPKH) and itself
                version: 1,
                lock_time: 0,
                inputs: &[
                    Input {
                        private_key: "L5TmwLMEyEqMAYj1qd7Fx9YRhNJTCvNn4ofr98ErbgHA99GjLBXC",
                        address_format: DogecoinFormat::P2SH_P2WPKH,
                        transaction_id: "32464234781c37831398b5d2f1e1766f8dbb55ac3b41ed047e365c07e9b03429",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: DogecoinAmount(25000),
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                    Input {
                        private_key: "L5TmwLMEyEqMAYj1qd7Fx9YRhNJTCvNn4ofr98ErbgHA99GjLBXC",
                        address_format: DogecoinFormat::P2SH_P2WPKH,
                        transaction_id: "76ef90fa70e4c10adc358432a979683a2cf1855ff545f88c5022dea8863ed5ab",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: DogecoinAmount(12000),
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                ],
                outputs: &[
                    Output {
                        address: "bc1qzkuhp5jxuvwx90eg65wkxuw6y2pfe740yw6h5s",
                        amount: DogecoinAmount(12000)
                    },
                    Output {
                        address: "3QDTHVyuJrHixUhhsdZXQ7M8P9MQngmw1P",
                        amount: DogecoinAmount(15000)
                    },
                ],
                expected_signed_transaction: "010000000001022934b0e9075c367e04ed413bac55bb8d6f76e1f1d2b5981383371c78344246320000000017160014354816a98500d7df9201d46e008c203dd5143b92ffffffffabd53e86a8de22508cf845f55f85f12c3a6879a9328435dc0ac1e470fa90ef760000000017160014354816a98500d7df9201d46e008c203dd5143b92ffffffff02e02e00000000000016001415b970d246e31c62bf28d51d6371da22829cfaaf983a00000000000017a914f7146aaa6f24a1012528c1d27cfe49d256d5a7018702483045022100988bc569371f74d6e49f20ae05ab06abfbe7ba92bbc177b61e38c0c9f430646702207a874da47387b6cfc066c26c24c99ccb75dac6772a0f94b7327703bdb156c4c8012103f850b5fa8fe53be8675dd3045ed89c8a4235155b484d88eb62d0afed7cb9ef050247304402204296465f1f95480f058ccebd70a0f80b9f092021a15793c954f39373e1e6500102206ca2d3f6cb68d1a9fde36ed6ded6509e2284c6afe860abf7f49c3ae18944ffdf012103f850b5fa8fe53be8675dd3045ed89c8a4235155b484d88eb62d0afed7cb9ef0500000000",
                expected_transaction_id: "6a06bd83718f24dd1883332939e59fdd26b95d8a328eac37a45b7c489618eac8",
            }
        ];

        #[test]
        fn test_real_mainnet_transactions() {
            REAL_TRANSACTIONS.iter().for_each(|transaction| {
                test_transaction::<N>(
                    transaction.version,
                    transaction.lock_time,
                    transaction.inputs.to_vec(),
                    transaction.outputs.to_vec(),
                    transaction.expected_signed_transaction,
                    transaction.expected_transaction_id,
                );
            });
        }

        #[test]
        fn test_real_reconstructed_mainnet_transactions() {
            REAL_TRANSACTIONS.iter().for_each(|transaction| {
                test_reconstructed_transaction::<N>(
                    transaction.version,
                    transaction.lock_time,
                    transaction.inputs.to_vec(),
                    transaction.outputs.to_vec(),
                    transaction.expected_signed_transaction,
                    transaction.expected_transaction_id,
                );
            });
        }
    }

    mod test_invalid_transactions {
        use super::*;
        type N = Mainnet;

        const INVALID_INPUTS: [Input; 6] = [
            Input {
                private_key: "L5BsLN6keEWUuF1JxfG6w5U1FDHs29faMpr9QX2MMVuQt7ymTorX",
                address_format: DogecoinFormat::P2SH_P2WPKH,
                transaction_id: "61d520ccb74288c96bc1a2b20ea1c0d5a704776dd0164a396efec3ea7040349d",
                index: 0,
                redeem_script: None,
                script_pub_key: None,
                utxo_amount: DogecoinAmount(0),
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sighash_code: SignatureHash::SIGHASH_ALL,
            },
            Input {
                private_key: "L5BsLN6keEWUuF1JxfG6w5U1FDHs29faMpr9QX2MMVuQt7ymTorX",
                address_format: DogecoinFormat::P2PKH,
                transaction_id: "7dabce",
                index: 0,
                redeem_script: None,
                script_pub_key: Some("a914e39b100350d6896ad0f572c9fe452fcac549fe7b87"),
                utxo_amount: DogecoinAmount(10000),
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sighash_code: SignatureHash::SIGHASH_ALL,
            },
            Input {
                private_key: "L5BsLN6keEWUuF1JxfG6w5U1FDHs29faMpr9QX2MMVuQt7ymTorX",
                address_format: DogecoinFormat::P2SH_P2WPKH,
                transaction_id: "7dabce",
                index: 0,
                redeem_script: Some("00142b6e15d83c28acd7e2373ba81bb4adf4dee3c01a"),
                script_pub_key: None,
                utxo_amount: DogecoinAmount(10000),
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sighash_code: SignatureHash::SIGHASH_ALL,
            },
            Input {
                private_key: "L5BsLN6keEWUuF1JxfG6w5U1FDHs29faMpr9QX2MMVuQt7ymTorX",
                address_format: DogecoinFormat::P2SH_P2WPKH,
                transaction_id: "7dabce588a8a57786790",
                index: 0,
                redeem_script: Some("00142b6e15d83c28acd7e2373ba81bb4adf4dee3c01a"),
                script_pub_key: None,
                utxo_amount: DogecoinAmount(10000),
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sighash_code: SignatureHash::SIGHASH_ALL,
            },
            Input {
                private_key: "L5BsLN6keEWUuF1JxfG6w5U1FDHs29faMpr9QX2MMVuQt7ymTorX",
                address_format: DogecoinFormat::P2SH_P2WPKH,
                transaction_id: "7dabce588a8a57786790d27810514f5ffccff4148a8105894da57c985d02cdbb7dabce",
                index: 0,
                redeem_script: Some("00142b6e15d83c28acd7e2373ba81bb4adf4dee3c01a"),
                script_pub_key: None,
                utxo_amount: DogecoinAmount(10000),
                sequence: Some([0xff, 0xff, 0xff, 0xff]),
                sighash_code: SignatureHash::SIGHASH_ALL,
            },
            Input {
                private_key: "",
                address_format: DogecoinFormat::P2PKH,
                transaction_id: "",
                index: 0,
                redeem_script: Some(""),
                script_pub_key: None,
                utxo_amount: DogecoinAmount(0),
                sequence: None,
                sighash_code: SignatureHash::SIGHASH_ALL,
            },
        ];

        #[test]
        fn test_invalid_inputs() {
            for input in INVALID_INPUTS.iter() {
                let transaction_id = hex::decode(input.transaction_id).unwrap();
                let redeem_script = input.redeem_script.map(|script| hex::decode(script).unwrap());
                let script_pub_key = input.script_pub_key.map(|script| hex::decode(script).unwrap());
                let sequence = input.sequence.map(|seq| seq.to_vec());

                let private_key = DogecoinPrivateKey::<N>::from_str(input.private_key);
                match private_key {
                    Ok(private_key) => {
                        let address = private_key.to_address(&input.address_format).unwrap();
                        let invalid_input = DogecoinTransactionInput::<N>::new(
                            transaction_id,
                            input.index,
                            Some(address),
                            Some(input.utxo_amount),
                            redeem_script,
                            script_pub_key,
                            sequence,
                            input.sighash_code,
                        );
                        assert!(invalid_input.is_err());
                    }
                    _ => assert!(private_key.is_err()),
                }
            }
        }
    }

    mod test_multisig_mainnet_transactions {
        use super::*;
        type N = Mainnet;

        const TRANSACTIONS: [TransactionTestCase; 2] = [
            TransactionTestCase { // Transaction 1 - p2sh_p2wsh to p2wsh (2-of-2 multisig) output
                version: 2,
                lock_time: 0,
                inputs: &[
                    Input {
                        private_key: "Kxxkik2L9KgrGgvdkEvYSkgAxaY4qPGfvxe1M1KBVBB7Ls3xDD8o",
                        address_format: DogecoinFormat::P2SH_P2WPKH,
                        transaction_id: "7c95424e4c86467eaea85b878985fa77d191bad2b9c5cac5a0cb98f760616afa",
                        index: 55,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: DogecoinAmount(2000000),
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                ],
                outputs: &[
                    Output { // P2WSH output
                        address: "0020c015c4a6be010e21657068fc2e6a9d02b27ebe4d490a25846f7237f104d1a3cd",
                        amount: DogecoinAmount(2000000)
                    },
                ],
                // Not including witness for now
                expected_signed_transaction: "0200000001fa6a6160f798cba0c5cac5b9d2ba91d177fa8589875ba8ae7e46864c4e42957c37000000171600143d295b6276ff8e4579f3350873db3e839e230f41ffffffff0180841e0000000000220020c015c4a6be010e21657068fc2e6a9d02b27ebe4d490a25846f7237f104d1a3cd00000000",
                expected_transaction_id: "d7f70088081d8c3bf45040f11789ee53868b4b00f900c86d32702f3497dec879",
            },
            TransactionTestCase { // Transaction 2 -> P2WSH to Bech32(P2WPKH) and itself
                version: 2,
                lock_time: 0,
                inputs: &[
                    Input {
                        private_key: "L5TmwLMEyEqMAYj1qd7Fx9YRhNJTCvNn4ofr98ErbgHA99GjLBXC",
                        address_format: DogecoinFormat::P2SH_P2WPKH,
                        transaction_id: "32464234781c37831398b5d2f1e1766f8dbb55ac3b41ed047e365c07e9b03429",
                        index: 0,
                        redeem_script: None,
                        script_pub_key: None,
                        utxo_amount: DogecoinAmount(25000),
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                    Input {
                        private_key: "KzBP2LqGgt9jUmF11KB7h5dgFKw3fwYJPey3pbJPgSESvKa3Ngcv",
                        address_format: DogecoinFormat::P2WSH,
                        transaction_id: "76ef90fa70e4c10adc358432a979683a2cf1855ff545f88c5022dea8863ed5ab",
                        index: 0,
                        redeem_script: Some("522103af0530f244a154b278b34de709b84bb85bb39ff3f1302fc51ae275e5a45fb35321027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb52ae"),
                        script_pub_key: None,
                        utxo_amount: DogecoinAmount(12000),
                        sequence: None,
                        sighash_code: SignatureHash::SIGHASH_ALL
                    },
                ],
                outputs: &[
                    Output {
                        address: "bc1qzkuhp5jxuvwx90eg65wkxuw6y2pfe740yw6h5s",
                        amount: DogecoinAmount(12000)
                    },
                    Output {
                        address: "3QDTHVyuJrHixUhhsdZXQ7M8P9MQngmw1P",
                        amount: DogecoinAmount(15000)
                    },
                ],
                // not including witness for now
                expected_signed_transaction: "02000000022934b0e9075c367e04ed413bac55bb8d6f76e1f1d2b5981383371c78344246320000000017160014354816a98500d7df9201d46e008c203dd5143b92ffffffffabd53e86a8de22508cf845f55f85f12c3a6879a9328435dc0ac1e470fa90ef760000000000ffffffff02e02e00000000000016001415b970d246e31c62bf28d51d6371da22829cfaaf983a00000000000017a914f7146aaa6f24a1012528c1d27cfe49d256d5a7018700000000",
                expected_transaction_id: "adbb03a005ccf68c9af6bd94175669a02c8941884bf62fbb3f88d7609dafe39c",
            },
        ];

        #[test]
        fn test_mainnet_transactions() {
            TRANSACTIONS.iter().for_each(|transaction| {
                test_multisig_transaction::<N>(
                    transaction.version,
                    transaction.lock_time,
                    transaction.inputs.to_vec(),
                    transaction.outputs.to_vec(),
                    transaction.expected_signed_transaction,
                    transaction.expected_transaction_id,
                );
            });
        }
    }

    mod test_helper_functions {
        use super::*;

        const LENGTH_VALUES: [(u64, [u8; 9]); 14] = [
            (20, [0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (32, [0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (200, [0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (252, [0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (253, [0xfd, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (40000, [0xfd, 0x40, 0x9c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (65535, [0xfd, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (65536, [0xfe, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (2000000000, [0xfe, 0x00, 0x94, 0x35, 0x77, 0x00, 0x00, 0x00, 0x00]),
            (2000000000, [0xfe, 0x00, 0x94, 0x35, 0x77, 0x00, 0x00, 0x00, 0x00]),
            (4294967295, [0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]),
            (4294967296, [0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
            (
                500000000000000000,
                [0xff, 0x00, 0x00, 0xb2, 0xd3, 0x59, 0x5b, 0xf0, 0x06],
            ),
            (
                18446744073709551615,
                [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];

        #[test]
        fn test_variable_length_integer() {
            LENGTH_VALUES.iter().for_each(|(size, expected_output)| {
                let variable_length_int = variable_length_integer(*size).unwrap();
                let pruned_expected_output = &expected_output[..variable_length_int.len()];
                assert_eq!(hex::encode(pruned_expected_output), hex::encode(&variable_length_int));
            });
        }
    }
}
