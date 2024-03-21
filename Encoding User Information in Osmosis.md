# Encoding User Information in Osmosis Addresses for Authentication and Account Management

- Author: [Your Name]
- Status: Draft
- Created: 2024-03-12

## Abstract

This RFC proposes a method for encoding user information, such as names, email addresses, and blockchain addresses, within an Osmosis address along with a private key. The purpose is to associate addresses with various uses, such as custom authenticators, account creation, and account restoration. This method can also be used in conjunction with ICNS (Interchain Name Service) for enhanced functionality.

## Motivation


Currently, there is no standardized way to associate user information with Osmosis addresses. By encoding user information within the address itself, we can enable various use cases, such as:

- Custom authenticators for access control
- Streamlined account creation flow
- Account restoration using encoded information
- Integration with ICNS for extended functionality

## Specification

### Encoding User Information

The user information will be encoded within the Osmosis address using the following steps:

1. Authenticate the ownership of the user's information (e.g., email via Google authentication)
2. Include the actual information (e.g., email) as a preimage or use the authentication message as a salt
3. Generate the Osmosis address using the encoded information and a private key

### Account Creation Flow

The typical account creation flow using this method would be as follows:

1. User authenticates the ownership of their information (e.g., Gmail account)
2. The address is generated, including either the actual email as a preimage or the authentication message from Google as a salt
3. The encoded information can be used by authenticators and to restore accounts, grant blockchain address permissions, and integrate with ICNS

### Integration with ICNS

The encoded user information within the Osmosis address can be used in conjunction with ICNS for extended functionality, such as:

- Associating human-readable names with Osmosis addresses
- Enabling cross-chain communication and interoperability
- Facilitating user-friendly transactions and interactions

## Security Considerations

- The private key associated with the Osmosis address must be securely stored to prevent unauthorized access
- The authentication process for user information ownership must be robust to prevent fraudulent claims
- The encoded information should be protected against tampering and unauthorized modification

## Backwards Compatibility

This proposal does not affect the existing Osmosis address format and is fully backwards compatible with the current system.

## References

- Osmosis Smart Accounts: [pr](https://github.com/osmosis-labs/osmosis/pull/7005)
- ICNS 
  - [Interchain Name Service](https://www.icns.xyz)
  - [ICNS Repository](https://github.com/osmosis-labs/icns)

## Copyright

Copyright and related rights waived via CC0.