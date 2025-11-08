"""
All Hybrid Cryptography modules
"""
from .base import CryptoModule
from ..utils import Colors
from ..engine import ModernCrypto, GPG_INSTALLED

class PGPModule(CryptoModule):
    """PGP (Pretty Good Privacy) Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "hybrid/pgp"
        self.description = "PGP encryption, decryption, signing, and key management"
        self.detailed_description = """
PGP (Pretty Good Privacy) is a popular program used for encrypting and decrypting
email and files, and for authenticating messages with digital signatures.
It uses a hybrid cryptosystem, combining symmetric-key encryption for data
confidentiality and public-key encryption for key exchange and digital signatures.

[+] IMPORTANT: This module requires GnuPG (GNU Privacy Guard) to be installed
on your system, as 'python-gnupg' is a wrapper around the GnuPG executable.

[+] Workflow:
1.  Generate a new PGP key pair (ACTION=genkeys).
2.  Import public keys of recipients (ACTION=import_key).
3.  Encrypt a message for a recipient (ACTION=encrypt).
4.  Decrypt a message using your private key (ACTION=decrypt).
5.  Sign a message with your private key (ACTION=sign).
6.  Verify a signed message using the sender's public key (ACTION=verify).
"""
        self.options = {
            'ACTION': {'value': 'genkeys', 'description': 'Action: genkeys, import_key, encrypt, decrypt, sign, verify'},
            'EMAIL': {'value': '', 'description': 'Email for key generation/recipient'},
            'PASSPHRASE': {'value': '', 'description': 'Passphrase for private key (if encrypted)'},
            'TEXT': {'value': '', 'description': 'Plaintext message to encrypt/sign'},
            'DATA': {'value': '', 'description': 'Encrypted/signed data (Base64 for decrypt/verify)'},
            'KEY_DATA': {'value': '', 'description': 'Public key data to import (PEM format)'},
            'KEY_ID': {'value': '', 'description': 'Key ID or fingerprint for operations'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['ACTION']
    
    def run(self) -> str:
        if not GPG_INSTALLED:
            return f"{Colors.FAIL}[-] 'python-gnupg' library not installed or GnuPG not found.{Colors.ENDC}"

        action = self.options['ACTION']['value'].lower()
        email = self.options['EMAIL']['value']
        passphrase = self.options['PASSPHRASE']['value']
        text = self.options['TEXT']['value']
        data = self.options['DATA']['value']
        key_data = self.options['KEY_DATA']['value']
        key_id = self.options['KEY_ID']['value']

        try:
            if action == 'genkeys':
                if not email:
                    return f"{Colors.FAIL}[-] Missing required option: EMAIL for key generation.{Colors.ENDC}"
                success, msg = ModernCrypto.pgp_genkeys(email, passphrase)
                return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"

            elif action == 'import_key':
                if not key_data:
                    return f"{Colors.FAIL}[-] Missing required option: KEY_DATA to import.{Colors.ENDC}"
                success, msg = ModernCrypto.pgp_import_key(key_data)
                return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"

            elif action == 'encrypt':
                if not text or not email:
                    return f"{Colors.FAIL}[-] Missing required options: TEXT and EMAIL (recipient) for encryption.{Colors.ENDC}"
                raw_result = ModernCrypto.pgp_encrypt(text, email)
                if raw_result.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
                return self._write_output_data(raw_result)

            elif action == 'decrypt':
                if not data:
                    return f"{Colors.FAIL}[-] Missing required option: DATA for decryption.{Colors.ENDC}"
                raw_result = ModernCrypto.pgp_decrypt(data, passphrase)
                if raw_result.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
                return self._write_output_data(raw_result)

            elif action == 'sign':
                if not text or not key_id:
                    return f"{Colors.FAIL}[-] Missing required options: TEXT and KEY_ID for signing.{Colors.ENDC}"
                raw_result = ModernCrypto.pgp_sign(text, key_id, passphrase)
                if raw_result.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
                return self._write_output_data(raw_result)

            elif action == 'verify':
                if not data or not key_id:
                    return f"{Colors.FAIL}[-] Missing required options: DATA and KEY_ID for verification.{Colors.ENDC}"
                success, msg = ModernCrypto.pgp_verify(data, key_id)
                return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"
            
            else:
                return f"{Colors.FAIL}[-] Unknown action: {action}{Colors.ENDC}"
        
        except Exception as e:
            return f"{Colors.FAIL}[-] ERROR: {str(e)}{Colors.ENDC}"