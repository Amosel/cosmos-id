use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, Error, KeyInit},
    Aes256Gcm, Nonce,
};
use bech32::{FromBase32, ToBase32, Variant};
use k256::ecdsa::VerifyingKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RecoveryOption {
    EthAddress(String),
    BtcAddress(String),
    Gmail(String),
}

impl RecoveryOption {
    fn into_string(&self) -> String {
        match self {
            RecoveryOption::BtcAddress(address) => format!("btc{}", address),
            RecoveryOption::EthAddress(address) => format!("eth{}", address),
            RecoveryOption::Gmail(address) => format!("gmail{}", address),
        }
    }
    pub fn value(&self) -> String {
        match self {
            RecoveryOption::EthAddress(addr) => addr.clone(),
            RecoveryOption::BtcAddress(addr) => addr.clone(),
            RecoveryOption::Gmail(addr) => addr.clone(),
        }
    }

    pub fn is_eth(&self) -> bool {
        match self {
            RecoveryOption::EthAddress(_) => true,
            _ => false,
        }
    }
    pub fn is_gmail(&self) -> bool {
        match self {
            RecoveryOption::Gmail(_) => true,
            _ => false,
        }
    }
    pub fn is_btc(&self) -> bool {
        match self {
            RecoveryOption::BtcAddress(_) => true,
            _ => false,
        }
    }
}

fn encrypt_data(
    key: &[u8; 32],         // Assuming a 256-bit key.
    nonce_bytes: &[u8; 12], // AES-GCM typically uses a 96-bit nonce.
    plaintext: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce_slice = Nonce::from_slice(nonce_bytes);
    cipher.encrypt(nonce_slice, plaintext)
}

// Function to decrypt data using AES-GCM
fn decrypt_data(key: &[u8], nonce_bytes: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>, Error> {
    let key = GenericArray::from_slice(key);
    let nonce = Nonce::from_slice(nonce_bytes); // Assuming a 96-bit nonce for AES-GCM
    let cipher = Aes256Gcm::new(key);

    cipher.decrypt(nonce, encrypted_data)
}

pub fn create_cosmos_address(
    recovery_options: &Vec<RecoveryOption>,
    salt: &str,
    verifying_key: &VerifyingKey,
) -> String {
    let recovery: String = recovery_options
        .iter()
        .map(RecoveryOption::into_string)
        .collect::<Vec<_>>()
        .join("_");

    let identifier = format!("{}_{}", recovery, salt);
    let hashed_identifier = Sha256::digest(identifier.as_bytes());

    let mut encryption_key = [0u8; 32];
    OsRng.fill_bytes(&mut encryption_key);

    let cipher = Aes256Gcm::new(&encryption_key.into());
    let nonce = b"unique nonce";
    let nonce_slice = Nonce::from_slice(nonce);
    let encrypted_identifier = cipher
        .encrypt(nonce_slice, hashed_identifier.as_slice())
        .expect("encryption failure");

    let public_key_bytes = verifying_key.to_bytes();
    let encrypted_key =
        encrypt_data(&encryption_key, nonce, &encryption_key).expect("key encryption failure");

    let mut address_payload = public_key_bytes.to_vec();
    address_payload.extend_from_slice(&encrypted_identifier);
    address_payload.extend_from_slice(&encrypted_key);

    let mut hasher = Sha256::new();
    hasher.update(&address_payload);
    let address_hash = &hasher.finalize()[..20];

    let prefix = "cosmos";
    let mut payload = String::new();
    payload.push_str(prefix);
    payload.push_str(&hex::encode(address_hash));

    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    let checksum = &hex::encode(&hasher.finalize()[..4]);

    let address_bytes = [payload, checksum.to_string()].concat();
    bech32::encode("cosmos", address_bytes.to_base32(), Variant::Bech32).unwrap()
}

pub fn recover_ownership(
    cosmos_address: &str,
    recovery: RecoveryOption,
) -> Option<Vec<RecoveryOption>> {
    let (_, data, _) = bech32::decode(cosmos_address).ok()?;
    let address_bytes = Vec::<u8>::from_base32(&data).ok()?;

    let payload_len = address_bytes.len() - 4;
    let payload = &address_bytes[..payload_len];
    let checksum = &address_bytes[payload_len..];

    let mut hasher = Sha256::new();
    hasher.update(payload);
    let expected_checksum = hasher.finalize().as_slice()[..4].to_vec();

    if checksum != expected_checksum {
        return None;
    }

    let public_key_bytes = &payload[..33];
    let encrypted_identifier = &payload[33..payload.len() - 32];
    let encrypted_key = &payload[payload.len() - 32..];
    let nonce = b"unique nonce";

    // Determine the appropriate encryption key for decrypting the main encryption key
    let encryption_key = match recovery {
        RecoveryOption::BtcAddress(private_key) => {
            let secret_key_bytes = hex::decode(private_key).ok()?;
            decrypt_data(&secret_key_bytes, nonce, encrypted_key).ok()?
        }
        RecoveryOption::EthAddress(private_key) => {
            let secret_key_bytes = hex::decode(private_key).ok()?;
            decrypt_data(&secret_key_bytes, nonce, encrypted_key).ok()?
        }
        RecoveryOption::Gmail(verification_code) => {
            // This branch would need actual implementation for Gmail verification
            if verification_code == "valid_code" {
                let key_bytes = public_key_bytes; // Simplified for example purposes
                decrypt_data(key_bytes, nonce, encrypted_key).ok()?
            } else {
                return None;
            }
        }
    };

    // Decrypt the identifier using the decrypted main encryption key
    let decrypted_identifier = decrypt_data(&encryption_key, nonce, encrypted_identifier).ok()?;
    let identifier = String::from_utf8(decrypted_identifier).ok()?;
    let mut parts = identifier.split('_');
    let eth_address = parts.next()?.to_string();
    let btc_address = parts.next()?.to_string();
    let gmail = parts.next()?.to_string();

    Some(vec![
        RecoveryOption::EthAddress(eth_address),
        RecoveryOption::BtcAddress(btc_address),
        RecoveryOption::Gmail(gmail),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use rand_core::OsRng;
    // Generates a 256-bit key for testing
    fn generate_test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    // Generates a 96-bit nonce for testing
    fn generate_test_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    #[test]
    fn test_encrypt_decrypt_functionality() {
        let key = generate_test_key();
        let nonce = generate_test_nonce();
        let plaintext = b"Hello, world!";

        let encrypted_data = encrypt_data(&key, &nonce, plaintext).expect("Encryption failed");
        assert_ne!(
            encrypted_data, plaintext,
            "Encrypted data should not match plaintext"
        );

        // Assuming you have a decrypt_data function for symmetry
        let decrypted_data =
            decrypt_data(&key, &nonce, &encrypted_data).expect("Decryption failed");
        assert_eq!(
            decrypted_data, plaintext,
            "Decrypted data does not match original plaintext"
        );
    }

    #[test]
    fn test_create_and_recover_cosmos_address() {
        let eth_address = "0x1234567890123456789012345678901234567890";
        let btc_address = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
        let gmail = "user@example.com";

        let salt = "mysalt";

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let cosmos_address = create_cosmos_address(
            &vec![
                RecoveryOption::EthAddress(eth_address.to_string()),
                RecoveryOption::BtcAddress(btc_address.to_string()),
                RecoveryOption::Gmail(gmail.to_string()),
            ],
            salt,
            &verifying_key,
        );
        assert!(!cosmos_address.is_empty());

        // Test recovery using ETH private key
        let eth_private_key = "0x1234567890123456789012345678901234567890123456789012345678901234";
        let recovered_user_info = recover_ownership(
            &cosmos_address,
            RecoveryOption::EthAddress(eth_private_key.to_string()),
        );
        assert!(recovered_user_info.is_some());
        let recovered_user_info = recovered_user_info.unwrap();
        assert_eq!(
            recovered_user_info
                .iter()
                .find(|i| i.is_eth())
                .unwrap()
                .value(),
            eth_address
        );

        // Test recovery using BTC private key
        let btc_private_key = "L1234567890123456789012345678901234567890123456789012345678901234";
        let recovered_user_info = recover_ownership(
            &cosmos_address,
            RecoveryOption::BtcAddress(btc_private_key.to_string()),
        );

        assert!(recovered_user_info.is_some());
        let recovered_user_info = recovered_user_info.unwrap();
        assert_eq!(
            recovered_user_info
                .iter()
                .find(|i| i.is_btc())
                .unwrap()
                .value(),
            btc_address
        );

        // Test recovery using Gmail verification code
        // let gmail_verification_code = "valid_code";
        // let recovered_user_info = recover_ownership(
        //     &cosmos_address,
        //     None,
        //     None,
        //     Some(gmail_verification_code.to_string()),
        // );
        // assert_eq!(recovered_user_info, Some(user_info.clone()));

        // Test recovery failure with invalid verification code
        // let invalid_verification_code = "invalid_code";
        let recovered_user_info = recover_ownership(
            &cosmos_address,
            RecoveryOption::EthAddress("bad-address".to_string()),
        );
        assert!(recovered_user_info.is_none());
    }

    // #[test]
    // fn test_recover_invalid_cosmos_address() {
    //     let invalid_cosmos_address = "invalid_cosmos_address";
    //     let recovered_user_info = recover_ownership(invalid_cosmos_address, None, None, None);
    //     assert_eq!(recovered_user_info, None);
    // }
}
