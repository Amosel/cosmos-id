use clap::{Parser, Subcommand};
use cosmos_id::{create_cosmos_address, recover_ownership, RecoveryOption};
use k256::ecdsa::SigningKey;
use rand_core::OsRng;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        /// User's ETH address
        #[clap(long, value_parser)]
        eth_address: Option<String>,

        /// User's BTC address
        #[clap(long, value_parser)]
        btc_address: Option<String>,

        /// User's Gmail account
        #[clap(long, value_parser)]
        gmail: Option<String>,

        /// Optional salt
        #[clap(long, value_parser)]
        salt: Option<String>,
    },
    Decrypt {
        /// Encoded Cosmos address (for ownership recovery)
        #[clap(long, value_parser)]
        cosmos_address: String,

        /// ETH private key (for ownership recovery)
        #[clap(long, value_parser)]
        eth_private_key: Option<String>,

        /// BTC private key (for ownership recovery)
        #[clap(long, value_parser)]
        btc_private_key: Option<String>,

        /// Gmail verification code (for ownership recovery)
        #[clap(long, value_parser)]
        gmail_verification_code: Option<String>,
    },
}

fn main() {
    let args = Args::parse();
    match args.command {
        Commands::Encrypt {
            eth_address,
            btc_address,
            gmail,
            salt,
        } => {
            let mut recovery_options = Vec::new();
            if let Some(eth_address) = eth_address {
                recovery_options.push(RecoveryOption::EthAddress(eth_address));
            }
            if let Some(btc_address) = btc_address {
                recovery_options.push(RecoveryOption::BtcAddress(btc_address));
            }
            if let Some(gmail) = gmail {
                recovery_options.push(RecoveryOption::Gmail(gmail));
            }
            if recovery_options.is_empty() {
                return;
            }
            let salt = salt.unwrap_or_else(|| "".to_string());
            let signing_key = SigningKey::random(&mut OsRng);
            let verifying_key = signing_key.verifying_key();

            let cosmos_address = create_cosmos_address(&recovery_options, &salt, &verifying_key);
            println!("Encoded Cosmos Address: {}", cosmos_address);
        }
        Commands::Decrypt {
            cosmos_address,
            eth_private_key,
            btc_private_key,
            gmail_verification_code,
        } => {
            let recovery_option = if let Some(eth_private_key) = eth_private_key {
                RecoveryOption::EthAddress(eth_private_key)
            } else if let Some(btc_private_key) = btc_private_key {
                RecoveryOption::BtcAddress(btc_private_key)
            } else if let Some(gmail_verification_code) = gmail_verification_code {
                RecoveryOption::Gmail(gmail_verification_code)
            } else {
                println!("No Recovery Options provided");
                return;
            };

            let user_info = recover_ownership(&cosmos_address, recovery_option);
            println!("Recovered User Info: {:?}", user_info);
        }
    }
}
