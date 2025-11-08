"""
GOST Symmetric Cipher Module
"""
from .base import CryptoModule
from ..utils import Colors
from ..engine import ModernCrypto, PYCRYPTODOME_INSTALLED

class GOSTModule(CryptoModule):
    """GOST Symmetric Cipher Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "modern/gost"
        self.description = "GOST 28147-89 (Magma) block cipher"
        self.detailed_description = """
GOST 28147-89, also known as Magma, is a symmetric-key block cipher developed
in the Soviet Union. It operates on 64-bit blocks and uses a 256-bit key.

[+] Security:
GOST 28147-89 is considered a strong cipher, though it is not as widely used
internationally as AES. It is part of the Russian cryptographic standards.

[+] Workflow:
1.  Set the TEXT or INFILE option with the message to encrypt/decrypt.
2.  Set the KEY (256-bit, 32 bytes, hex-encoded).
3.  Set MODE to 'encrypt' or 'decrypt'.
4.  Run the module.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt (Base64 for decrypt)'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'KEY': {'value': '', 'description': '256-bit key (32 bytes, hex-encoded)'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['KEY', ('TEXT', 'INFILE')]
    
    def run(self) -> str:
        if not PYCRYPTODOME_INSTALLED:
            return f"{Colors.FAIL}[-] 'pycryptodome' library not installed.{Colors.ENDC}"

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
            if len(key) != 32:
                return f"{Colors.FAIL}[-] ERROR: Key must be 256 bits (32 bytes) hex-encoded.{Colors.ENDC}"
        except ValueError:
            return f"{Colors.FAIL}[-] ERROR: Key must be a valid hex string.{Colors.ENDC}"

        if decrypt:
            if text:
                raw_result = ModernCrypto.gost_decrypt(text.decode(), key)
            else:
                return f"{Colors.FAIL}[-] No data to decrypt.{Colors.ENDC}"
        else:
            if text:
                raw_result = ModernCrypto.gost_encrypt(text.decode(), key)
            else:
                return f"{Colors.FAIL}[-] No data to encrypt.{Colors.ENDC}"
        
        if raw_result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
        
        return self._write_output_data(raw_result)