"""
Skipjack Symmetric Cipher Module
"""
from .base import CryptoModule
from ..utils import Colors
from ..engine import ModernCrypto

class SkipjackModule(CryptoModule):
    """Skipjack Symmetric Cipher Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "modern/skipjack"
        self.description = "Skipjack cipher - INSECURE (Educational Only)"
        self.detailed_description = """
Skipjack is a block cipher developed by the U.S. National Security Agency (NSA).
It operates on 64-bit blocks and uses an 80-bit key.

[+] Security:
INSECURE. Skipjack is an older cipher and is not considered secure for modern use.
Its 80-bit key size is vulnerable to brute-force attacks.
It is provided here for educational or historical purposes only.
DO NOT USE THIS FOR REAL-WORLD SECURITY.

[+] Workflow:
1.  Set the TEXT or INFILE option with the message to encrypt/decrypt.
2.  Set the KEY (80-bit, 10 bytes).
3.  Set MODE to 'encrypt' or 'decrypt'.
4.  Run the module.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt (Base64 for decrypt)'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'KEY': {'value': '', 'description': '80-bit key (10 bytes, hex-encoded)'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['KEY', ('TEXT', 'INFILE')]
    
    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
            
        text, data_bytes, err = self._get_input_data(read_as_bytes=True)
        if err:
            return err
            
        key_hex = self.options['KEY']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        try:
            key = bytes.fromhex(key_hex)
            if len(key) != 10:
                return f"{Colors.FAIL}[-] ERROR: Key must be 80 bits (10 bytes) hex-encoded.{Colors.ENDC}"
        except ValueError:
            return f"{Colors.FAIL}[-] ERROR: Key must be a valid hex string.{Colors.ENDC}"

        if decrypt:
            if text:
                raw_result = ModernCrypto.skipjack_decrypt(text.decode(), key)
            else:
                return f"{Colors.FAIL}[-] No data to decrypt.{Colors.ENDC}"
        else:
            if text:
                raw_result = ModernCrypto.skipjack_encrypt(text.decode(), key)
            else:
                return f"{Colors.FAIL}[-] No data to encrypt.{Colors.ENDC}"
        
        if raw_result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
        
        return self._write_output_data(raw_result)