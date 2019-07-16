use bitvec::prelude::*;
use hmac::Hmac;
use rand::Rng;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256, Sha512};
use std::str;

use std::fs;
use std::ops::{AddAssign, Div};


const PBKDF2_ROUNDS: usize = 2048;
const PBKDF2_BYTES: usize = 64;

/// Mnemonic word languages
#[allow(non_camel_case_types)]
pub enum Language {
    CHINESE_SIMPLIFIED,
    CHINESE_TRADITIONAL,
    ENGLISH,
    FRENCH,
    ITALIAN,
    JAPANESE,
    KOREAN,
    SPANISH,
}

/// Represents a BIP39 Mnemonic
pub struct Mnemonic {
    /// Initial entropy for generating the mnemonic. Must be a multiple of 32 bits.
    pub entropy: Vec<u8>,

    /// Language of mnemnoic words
    pub language: Language,

    /// Mnemonic phrase
    pub phrase: String,
}

impl Mnemonic {
    /// generates a new mnemonic with word_count words
    pub fn new(word_count: u8, language: Language) -> Self {
        let entropy_length: usize = match word_count {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            _ => panic!("Invalid phrase word count")
        };
        let mut entropy_slice_max = [0u8; 32];
        OsRng.try_fill(&mut entropy_slice_max).expect("Error generating random bytes for entropy");
        let entropy_slice_exact = &entropy_slice_max[0..entropy_length];
        let entropy: Vec<u8> = Vec::from(entropy_slice_exact);

        Mnemonic::from_entropy(&entropy, language)
    }

    /// derives a mnemonic from entropy
    pub fn from_entropy(entropy: &Vec<u8>, language: Language) -> Self {

        // The allowed size of ENT is 128-256 bits.
        let word_count: i32 = match entropy.len() {
            16 => 12,
            20 => 15,
            24 => 18,
            28 => 21,
            32 => 24,
            _ => panic!("Invalid entropy length")
        };
//        println!("{} words", word_count);


        let word_string = match language {
            Language::ENGLISH => fs::read_to_string("src/languages/english.txt").expect("Error reading file"),
            _ => panic!("Invalid language")
        };

        let word_list: Vec<&str> = word_string.lines().collect();

        // A checksum is generated by taking the first `entropy.len() / 32` bits of its SHA256 hash
        let cs = word_count.div(3i32) as usize;
//        println!("{} checksum size", cs);

        let mut hasher = Sha256::new();
        hasher.input(entropy.as_slice());

        let hash_result = hasher.result();

        let checksum_bit_slice: &BitSlice = &hash_result[0].as_bitslice::<BigEndian>()[..cs];

        let mut checksum_bit_vector = BitVec::from_bitslice(checksum_bit_slice);
//        println!("checksum bits {:?}", checksum_bit_vector);


        // The entropy is converted into a bit vector for easier bit manipulation
        let mut encoding_vec: BitVec<LittleEndian> = BitVec::new();

        entropy.iter().for_each(|byte| {
            let byte_bit_slice = byte.as_bitslice::<LittleEndian>();
            let mut byte_bit_vector = BitVec::from_bitslice(&byte_bit_slice);
            encoding_vec.append(&mut byte_bit_vector);
        });

        // The checksum is appended to the end of the initial entropy
        encoding_vec.append(&mut checksum_bit_vector);

        // Next, these concatenated bits are split into groups of 11 bits,
        // each encoding a number from 0-2047, serving as an index into a wordlist.
        // Finally, we convert these numbers into words and use the joined words as a mnemonic sentence.
        let mut phrase = String::new();

        let mut word_bits: Vec<u8> = Vec::with_capacity(11);
        encoding_vec.iter().for_each(|bit| {
            match bit {
                true => word_bits.push(1),
                false => word_bits.push(0)
            }
            if word_bits.len() == 11 {
//                print!("{:?} ", word_bits);
//                print!("{:?} ", get_u11_index(&word_bits));
//                println!("{:?}", word_list[get_u11_index(&word_bits)]);

                phrase.push_str(&word_list[get_u11_index(&word_bits)]);
                phrase.push(' ');
                word_bits = Vec::new();
            }
        });
        // removes trailing space
        phrase.pop();

        /// Returns wordlist index 0-2047 given bit vector in BigEndian form
        fn get_u11_index(bits: &Vec<u8>) -> usize {
            let mut number = 0u16;
            for x in 0..11 {
                if bits[x] == 1 {
                    let exp = (10 - x) as u32;
                    number.add_assign(2u16.pow(exp));
                }
            }

            number as usize
        }

        Self {
            entropy: entropy.clone(),
            language,
            phrase,
        }
    }

    //    /// derives a mnemonic from seed phrase
//    pub fn from_mnemonic(phrase: &str, language: &Language) -> Self {
//        Self {
//            entropy: Mnemonic::to_entropy(phrase, language),
//            language: *language,
//            phrase: String::from_str(phrase);
//        }
//    }
//
//    /// derives entropy from seed phrase
//    // TODO see https://github.com/trezor/python-mnemonic/blob/063a33b517803c88d81e0ff0ccc9587b833d8280/mnemonic/mnemonic.py#L126
//    pub fn to_entropy(phrase: &str, language: &Language) -> Vec<u8> { }
//
    /// Generates seed bytes from mnemonic
    pub fn to_seed(&self, password: Option<&str>) -> Vec<u8> {
        let mut salt = String::from("mnemonic");
        let pass = password.unwrap_or_else(|| "");
//        match password {
//            Some(&str) => salt.push_str(password.unwrap()),
//            None => ()
//        };
        salt.push_str(pass);
//        println!("{:?}", &self.entropy);

        let mut seed = vec![0u8; PBKDF2_BYTES];
        pbkdf2::pbkdf2::<Hmac<Sha512>>(&self.entropy, salt.as_bytes(), PBKDF2_ROUNDS, &mut seed);

        seed
    }

//    /// returns whether or not mnemonic phrase is valid
//    pub fn check_valid(phrase: &str, language: &Language) -> bool { }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    fn test_from_entropy(entropy: &Vec<u8>, expected_phrase: &str, language: Language) {
        let result = Mnemonic::from_entropy(&entropy, language);
//        println!("{:?}", result.phrase);
        assert_eq!(expected_phrase, result.phrase);
    }

    fn test_new(word_count: u8, language: Language) {
        let result = Mnemonic::new(word_count, language);
        test_from_entropy(&result.entropy, &result.phrase, result.language);
    }

    mod english {
        use super::*;

        const PASSWORD: &str = "TREZOR";
        const LANGUAGE: Language = Language::ENGLISH;


        const KEYPAIRS: [(&str, &str, &str); 1] = [
            (
                "00000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
            )
        ];

        #[test]
        fn new() {
            let word_counts: [u8; 5] = [12, 15, 18, 21, 24];
            word_counts.iter().for_each(|word_count| {
                test_new(*word_count, LANGUAGE);
            })
        }

        #[test]
        fn from_entropy() {
            KEYPAIRS.iter().for_each(|(entropy_str, phrase, _)| {
                let entropy: Vec<u8> = Vec::from(hex::decode(entropy_str).unwrap());
                test_from_entropy(&entropy, phrase, LANGUAGE);
            });
        }

        #[test]
        fn to_seed() {
            KEYPAIRS.iter().for_each(|(entropy_str, _, expected_seed)| {
                let entropy: Vec<u8> = Vec::from(hex::decode(entropy_str).unwrap());
                let result = Mnemonic::from_entropy(&entropy, Language::ENGLISH);
//                println!("{:?}", hex::encode(result.to_seed(None)));
//                println!("{:?}", hex::encode(result.to_seed(Some(PASSWORD))));
//                assert_eq!(expected_seed, &hex::encode(result.to_seed(Some(PASSWORD))))
            });
        }
    }
}