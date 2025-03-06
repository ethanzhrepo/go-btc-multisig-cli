# Bitcoin Multisig CLI Tool
## A command-line tool for creating and managing Bitcoin multisig wallets, built in Go.

**notice**: This tool is still under development and not all features are available.   

### Features
- Generate single-signature wallets with various address types (P2PKH, P2WPKH, P2SH, P2WSH, P2TR)
- Create multisig wallets (P2SH, P2WSH, P2SH-P2WSH)
- Retrieve public keys from encrypted wallet files
- Check current Bitcoin network gas prices
- Support for both mainnet and testnet
- Secure storage options (local filesystem, Google Drive, Dropbox, OneDrive)

### Installation

```bash
go install github.com/ethanzhrepo/go-btc-multisig-cli@latest
```

Or build from source:

```bash
git clone https://github.com/ethanzhrepo/go-btc-multisig-cli.git
cd go-btc-multisig-cli
go build
```

### Configuration

#### RPC Connection

Set up your Bitcoin node RPC connection for gas price estimation:

```bash
go-btc-multisig-cli config set rpc http://localhost:8332
go-btc-multisig-cli config set rpc_pass_required true
go-btc-multisig-cli config set rpc_username your_username
go-btc-multisig-cli config set rpc_password your_password
```

#### Cloud Storage Credentials

For security reasons, cloud storage credentials are read from environment variables:

**Google Drive:**
```bash
export GOOGLE_OAUTH_CLIENT_ID="your_client_id"
export GOOGLE_OAUTH_CLIENT_SECRET="your_client_secret"
```

**Dropbox:**
```bash
export DROPBOX_APP_KEY="your_app_key"
export DROPBOX_APP_SECRET="your_app_secret"
```

**OneDrive:**
```bash
export ONEDRIVE_CLIENT_ID="your_client_id"
export ONEDRIVE_CLIENT_SECRET="your_client_secret"
```

You can obtain these credentials by creating applications in the respective developer portals:
- Google Drive: [Google Cloud Console](https://console.cloud.google.com/)
- Dropbox: [Dropbox Developer Console](https://www.dropbox.com/developers)
- OneDrive: [Microsoft Azure Portal](https://portal.azure.com/)

### Usage

#### Storage Options

The tool supports multiple storage methods:

- `fs:` - Local filesystem
- `googledrive:` - Google Drive
- `dropbox:` - Dropbox
- `onedrive:` - OneDrive

#### Generate a wallet and save to local file
```bash
go-btc-multisig-cli generateWallet --out fs:/path/to/wallet.json
```

#### Generate a testnet wallet and show mnemonic
```bash
go-btc-multisig-cli generateWallet --testnet --show
```

#### Save to cloud storage
```bash
go-btc-multisig-cli generateWallet --out googledrive:/backups/wallet.json
go-btc-multisig-cli generateWallet --out dropbox:/backups/wallet.json
go-btc-multisig-cli generateWallet --out onedrive:/backups/wallet.json
```

#### Get public key from local file
```bash
go-btc-multisig-cli getPublicKey --input fs:/path/to/wallet.json
```

#### Get public key from cloud storage
```bash
go-btc-multisig-cli getPublicKey --input googledrive:/backups/wallet.json
go-btc-multisig-cli getPublicKey --input dropbox:/backups/wallet.json
go-btc-multisig-cli getPublicKey --input onedrive:/backups/wallet.json
```

#### Get public key for testnet
```bash
go-btc-multisig-cli getPublicKey --input fs:/path/to/wallet.json --testnet
```

#### Create a 2-of-3 P2SH multisig wallet
```bash
go-btc-multisig-cli generateMulti --type p2sh --m 2 --n 3 \
  --publicKeys 02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc,\
03301a8259a12e35694cc22ebc45fee635f4993064190f6ce96e7fb19f8ac9483,\
02e7c6b176786f58754b1cc703d78f55107c9b5239befc06a6c7950bc5a61272fd \
  --out fs:/path/to/multisig.json
```

#### Create a P2WSH (native SegWit) multisig wallet
```bash
go-btc-multisig-cli generateMulti --type p2wsh --m 2 --n 3 \
  --publicKeys 02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc,\
03301a8259a12e35694cc22ebc45fee635f4993064190f6ce96e7fb19f8ac9483,\
02e7c6b176786f58754b1cc703d78f55107c9b5239befc06a6c7950bc5a61272fd \
  --testnet
```

#### Create a P2SH-P2WSH (nested SegWit) multisig wallet
```bash
go-btc-multisig-cli generateMulti --type p2sh-p2wsh --m 2 --n 3 \
  --publicKeys 02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc,\
03301a8259a12e35694cc22ebc45fee635f4993064190f6ce96e7fb19f8ac9483,\
02e7c6b176786f58754b1cc703d78f55107c9b5239befc06a6c7950bc5a61272fd
```

#### Check current gas price
```bash
go-btc-multisig-cli getGasPrice
```

### Security Features

- Strong password requirements (minimum 10 characters, uppercase, lowercase, numbers, special characters)
- AES-256-GCM encryption with Argon2id key derivation
- BIP67 deterministic public key sorting for multisig addresses
- Support for various address types with different security properties
- Environment variable-based configuration for sensitive credentials

### License

[MIT License](LICENSE)
