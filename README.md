

```
[96m
██████╗██████╗ ██╗   ██╗██████╗ ████████╗
██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║
██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║
╚██████╗██║  ██║   ██║   ██║        ██║
 ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝

███████╗██╗    ██╗██╗███████╗███████╗
██╔════╝██║    ██║██║██╔════╝██╔════╝
███████╗██║ █╗ ██║██║███████╗███████╗
╚════██║██║███╗██║██║╚════██║╚════██║
███████║╚███╔███╔╝██║███████║███████║
╚══════╝ ╚══╝╚══╝ ╚═╝╚══════╝╚══════╝

██╗  ██╗███╗   ██╗██╗███████╗███████╗
██║ ██╔╝████╗  ██║██║██╔════╝██╔════╝
█████╔╝ ██╔██╗ ██║██║█████╗  █████╗
██╔═██╗ ██║╚██╗██║██║██╔══╝  ██╔══╝
██║  ██╗██║ ╚████║██║██║     ███████╗
╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝     ╚══════╝
[0m
[92mCryptoSwissKnife v1 | 63 Modules[0m
[93m"One tool to encrypt, decrypt, and sign them all."[0m
[93mType 'help' for available commands or 'banner' to display banner again[0m
```


```
[1mCryptoSwissKnife Core Commands[0m
--------------------------------------------------
help                      Show this help menu
use <module>              Select a module (e.g., use caesar)
show modules              List all available modules
show options              Show options for the *current* module
info <module>             Show detailed info for a specific module (e.g., info aes)
search <keyword>          Search for modules
set <OPTION> <VALUE>      Set an option value (e.g., set TEXT "Hello")
run                       Execute the current module
back                      Deselect the current module
banner                    Display the welcome banner
clear                     Clear the screen
version                   Show version information
exit / quit / Ctrl+D      Exit the console
--------------------------------------------------
```

```
[1mAvailable Modules[0m
--------------------------------------------------

[4mAsymmetric Modules[0m
asymmetric/dh                  Diffie-Hellman (DH) key exchange
asymmetric/ecdh                Elliptic Curve Diffie-Hellman (ECDH) key exchange
asymmetric/ecdsa               Elliptic Curve Digital Signature Algorithm (ECDSA)
asymmetric/eddsa               EdDSA (Ed25519) Digital Signatures
asymmetric/elgamal             ElGamal encryption and key generation
asymmetric/rsa                 RSA (Rivest–Shamir–Adleman) operations

[4mBlockchain Modules[0m
blockchain/simple_blockchain   A simplified blockchain implementation

[4mClassical Modules[0m
classical/adfgvx               ADFGVX cipher (WWI German cipher)
classical/affine               Affine cipher: E(x) = (ax + b) mod 26
classical/atbash               Atbash cipher - reverses alphabet
classical/autokey              Vigenere Autokey cipher
classical/beaufort             Beaufort cipher (reciprocal Vigenere)
classical/caesar               Caesar cipher with customizable shift
classical/columnar             Columnar transposition cipher
classical/double_transposition Double columnar transposition cipher
classical/hill                 Hill cipher (matrix-based)
classical/monoalphabetic       Monoalphabetic substitution cipher
classical/playfair             Playfair cipher - digraph substitution
classical/railfence            Rail fence cipher - transposition cipher
classical/scytale              Scytale cipher (simple columnar transposition)
classical/vigenere             Vigenère cipher encryption/decryption

[4mCryptocurrency Modules[0m
cryptocurrency/wallet          Generate and manage cryptocurrency wallets (simplified)

[4mHash Modules[0m
hash/digest                    Generate cryptographic hashes
hash/tiger                     Generate a hash using the Tiger algorithm

[4mHomomorphic Modules[0m
homomorphic/bfv                BFV Fully Homomorphic Encryption
homomorphic/ckks               CKKS Fully Homomorphic Encryption
homomorphic/paillier           Paillier Homomorphic Encryption

[4mHybrid Modules[0m
hybrid/pgp                     PGP encryption, decryption, signing, and key management

[4mKdf Modules[0m
kdf/argon2_hash                Hash a password using Argon2 (modern standard)
kdf/argon2_verify              Verify a password against an Argon2 hash
kdf/bcrypt_hash                Hash a password using bcrypt
kdf/bcrypt_verify              Verify a password against a bcrypt hash
kdf/hkdf                       Derive keys from a master secret using HKDF-SHA256
kdf/pbkdf2                     Derive a key from a password using PBKDF2-HMAC-SHA256
kdf/scrypt_hash                Hash a password using scrypt
kdf/scrypt_verify              Verify a password against an scrypt hash

[4mLightweight Modules[0m
lightweight/ascon              Ascon authenticated encryption (NIST Lightweight Crypto Standard)
lightweight/present            PRESENT lightweight block cipher (Educational Only)
lightweight/simon              Simon lightweight block cipher (Educational Only)
lightweight/speck              Speck lightweight block cipher (Educational Only)

[4mModern Modules[0m
modern/3des                    3DES (Triple DES) cipher (CBC mode)
modern/aes                     AES-256-GCM authenticated encryption
modern/blowfish                Blowfish cipher (CBC mode with PKCS7 padding)
modern/camellia                Camellia cipher (CBC mode)
modern/chacha20                ChaCha20-Poly1305 authenticated encryption
modern/des                     DES cipher (CBC mode) - INSECURE
modern/gost                    GOST 28147-89 (Magma) block cipher
modern/idea                    IDEA cipher (CBC mode)
modern/rc2                     RC2 cipher (CBC mode)
modern/rc5                     RC5 cipher (ECB mode)
modern/rc6                     RC6 cipher (ECB mode)
modern/serpent                 Serpent cipher (CBC mode)
modern/skipjack                Skipjack cipher - INSECURE (Educational Only)
modern/twofish                 Twofish cipher (CBC mode)

[4mPqc Modules[0m
pqc/dilithium                  Dilithium Post-Quantum Digital Signature Module
pqc/falcon                     Falcon Post-Quantum Digital Signatures
pqc/kyber                      Kyber Post-Quantum Key Encapsulation Mechanism
pqc/sphincs                    SPHINCS+ Post-Quantum Digital Signatures

[4mQuantum Modules[0m
quantum/qkd                    Quantum Key Distribution (BB84 Protocol) Simulation

[4mStego Modules[0m
stego/lsb_image_hide           Hide a secret message or file in a PNG image via LSB
stego/lsb_image_reveal         Reveal a secret message or file from an LSB stego image

[4mStream Modules[0m
stream/rc4                     RC4 stream cipher - INSECURE
stream/salsa20                 Salsa20 stream cipher
--------------------------------------------------
Total modules: 63
```
A comprehensive command-line interface (CLI) tool for various cryptographic operations. This project aims to provide a Swiss Army Knife for cryptography, offering a wide range of ciphers, hashing algorithms, key derivation functions, and more.

## Features

-   **Classical Ciphers**: Implementations of historical ciphers like Caesar, Vigenère, Playfair, etc.
-   **Modern Ciphers**: Support for AES, ChaCha20, Blowfish, and other contemporary encryption standards.
-   **Asymmetric Cryptography**: RSA, Diffie-Hellman, ECDH, ECDSA, and ElGamal.
-   **Post-Quantum Cryptography (PQC)**: Kyber, Dilithium, Falcon, and SPHINCS+.
-   **Homomorphic Encryption**: Paillier, BFV, and CKKS.
-   **Hashing Algorithms**: MD5, SHA-family, BLAKE2, and Tiger.
-   **Key Derivation Functions (KDF)**: bcrypt, scrypt, Argon2, PBKDF2, and HKDF.
-   **Steganography**: LSB image hiding/revealing.
-   **Quantum Cryptography**: BB84 QKD simulation.
-   **Blockchain & Cryptocurrency**: Simplified blockchain and wallet functionalities.

## Installation

To get CryptoSwissKnife up and running on your local machine, follow these steps:

### Prerequisites

*   **Python 3.8+**: Ensure you have a compatible version of Python installed.
    You can download it from [python.org](https://www.python.org/downloads/).
*   **pip**: Python's package installer, usually comes with Python.

### Steps

1.  **Clone the Repository**:
    First, clone the CryptoSwissKnife repository to your local machine using Git:
    ```bash
    git clone https://github.com/DCXII/CryptoSwissKnife.git
    cd CryptoSwissKnife
    ```

2.  **Set up a Virtual Environment** (Recommended):
    It's good practice to use a virtual environment to manage project dependencies.
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install Dependencies**:
    Install all required Python packages using pip:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Once installed, you can launch the CryptoSwissKnife console and start exploring its features.

### Running the Console

To start the interactive console, run:
```bash
python3 run_console.py
```
You will be greeted by the CryptoSwissKnife banner and a `crypto >` prompt.

### Basic Commands

*   `help`: Displays a list of all available commands and their descriptions.
*   `show modules`: Lists all cryptographic modules available in the tool, categorized by type (e.g., `classical/caesar`, `modern/aes`).
*   `use <module_name>`: Selects a specific module to work with. For example:
    ```bash
    crypto > use classical/caesar
    crypto (caesar) >
    ```
*   `show options`: After selecting a module, this command shows the configurable options for that module.
*   `set <OPTION> <VALUE>`: Sets a value for a module option. For example:
    ```bash
    crypto (caesar) > set TEXT "Hello World"
    crypto (caesar) > set SHIFT 3
    crypto (caesar) > set MODE encrypt
    ```
*   `run`: Executes the selected module with the currently set options.
*   `back`: Deselects the current module, returning to the main `crypto >` prompt.
*   `exit` or `quit`: Exits the CryptoSwissKnife console.

### Example: Encrypting with Caesar Cipher

1.  **Start the console**:
    ```bash
    python3 run_console.py
    ```
2.  **Use the Caesar module**:
    ```bash
    crypto > use classical/caesar
    [+] Module 'classical/caesar' loaded
    crypto (caesar) >
    ```
3.  **Set options**:
    ```bash
    crypto (caesar) > set TEXT "GEMINI"
    [+] TEXT => GEMINI
    crypto (caesar) > set SHIFT 3
    [+] SHIFT => 3
    crypto (caesar) > set MODE encrypt
    [+] MODE => encrypt
    ```
4.  **Run the module**:
    ```bash
    crypto (caesar) > run
    [*] Running module...
    [+] Result: JHPLQL
    ```
5.  **Decrypt the message**:
    ```bash
    crypto (caesar) > set TEXT "JHPLQL"
    [+] TEXT => JHPLQL
    crypto (caesar) > set MODE decrypt
    [+] MODE => decrypt
    crypto (caesar) > run
    [*] Running module...
    [+] Result: GEMINI
    ```
6.  **Go back or exit**:
    ```bash
    crypto (caesar) > back
    [+] Module deselected
    crypto > exit
    [+] Thanks for using CryptoSwissKnife!
    ```

## Project Structure

The project is organized as follows:

*   `csk/`: Contains the core logic of the CryptoSwissKnife.
    *   `console.py`: Manages the interactive command-line interface.
    *   `engine.py`: Houses the implementations of various cryptographic algorithms.
    *   `utils.py`: Utility functions and classes (e.g., color formatting).
    *   `modules/`: A package containing individual module definitions for each cryptographic function. Each module inherits from `csk.modules.base.CryptoModule`.
*   `run_console.py`: The main entry point to start the CLI application.
*   `requirements.txt`: Lists all Python dependencies required for the project.
*   `tests/`: Contains unit tests for the cryptographic modules.
*   `venv/`: (Ignored by Git) The Python virtual environment.

## Contributing

We welcome contributions! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to submit issues, propose features, and make pull requests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Console Overview

Here's an overview of the CryptoSwissKnife console, including its banner, available commands, and modules.
