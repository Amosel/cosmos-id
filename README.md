The proposed cryptographic scheme for creating a Cosmos address based on the purpose of encoding user information:

1. User Information Encoding:
   - Take the user's authenticated information (e.g., email address) and convert it into a byte array.
   - If using the authentication message as a salt, concatenate the byte array of the user information with the byte array of the salt.
   - Compute the SHA-256 hash of the resulting byte array to obtain a fixed-size representation of the user information.

2. Private Key Generation:
   - Generate a random 256-bit private key using a secure random number generator.
   - Ensure that the private key is securely stored and kept confidential.

3. Public Key Derivation:
   - Use the `secp256k1` elliptic curve cryptography (ECC) algorithm to derive the corresponding public key from the private key.
   - The public key is obtained by multiplying the generator point of the `secp256k1` curve by the private key.

4. Cosmos Address Derivation:
   - Take the public key obtained in step 3 and compute its SHA-256 hash.
   - Take the first 20 bytes (160 bits) of the SHA-256 hash to obtain the Cosmos address payload.
   - Prepend the Cosmos prefix (e.g., "cosmos") to the payload to indicate the address type.
   - Compute the checksum by taking the first 4 bytes of the SHA-256 hash of the concatenated prefix and payload.
   - Append the checksum to the end of the concatenated prefix and payload.
   - Encode the resulting concatenated bytes using Bech32 encoding to obtain the final Cosmos address.

5. Associating User Information:
   - Store the association between the derived Cosmos address and the hashed user information (obtained in step 1) in a secure database or smart contract.
   - This association can be used for various purposes, such as authentication, account recovery, and granting permissions.

Here's a pseudocode representation of the above steps:

```
function createCosmosAddress(userInfo, salt):
    userInfoBytes = encode(userInfo)
    if salt is not None:
        userInfoBytes = concat(userInfoBytes, salt)
    hashedUserInfo = sha256(userInfoBytes)
    
    privateKey = generateSecureRandomKey()
    publicKey = derivePublicKey(privateKey)
    
    addressPayload = sha256(publicKey)[:20]
    prefix = "cosmos"
    payload = concat(prefix, addressPayload)
    checksum = sha256(payload)[:4]
    address = bech32Encode(concat(payload, checksum))
    
    storeAssociation(address, hashedUserInfo)
    
    return address
```

Note that this is a simplified representation, and the actual implementation would need to follow the specific cryptographic primitives and encoding standards used in the Cosmos ecosystem.

It's important to ensure that the private key is securely generated, stored, and managed to maintain the integrity and confidentiality of the associated user information. Additionally, appropriate measures should be taken to protect against unauthorized access and tampering of the stored associations between addresses and user information.


## Running the Rust Example:

```bash
cargo run -- --eth-address "0x1234567890123456789012345678901234567890" --btc-address "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" --gmail "user@example.com" --salt "somesalt"
```

Encoded Cosmos Address: cosmos1vdhhxmt0wvenzc3nv4snzwf5xp3ngerrx4jrydehvcexywf5vvurzdpjxs6nsefsxccnvdfnv4snswfjxsenjvcez4zna

```bash
cargo run -- --cosmos-address cosmos1vdhhxmt0wvenzc3nv4snzwf5xp3ngerrx4jrydehvcexywf5vvurzdpjxs6nsefsxccnvdfnv4snswfjxsenjvcez4zna
```