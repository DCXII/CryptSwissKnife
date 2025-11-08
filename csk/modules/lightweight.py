"""
All Lightweight and IoT Encryption modules
"""
from .base import CryptoModule
from ..utils import Colors
from ..engine import ModernCrypto, ASCON_INSTALLED, PRESENT_INSTALLED, SPECK_INSTALLED, SIMON_INSTALLED

class AsconModule(CryptoModule):
    """Ascon Authenticated Encryption Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "lightweight/ascon"
        self.description = "Ascon authenticated encryption (NIST Lightweight Crypto Standard)"
        self.detailed_description = """
Ascon is a family of lightweight cryptographic algorithms designed for resource-constrained
environments, such as IoT devices. It was selected as the standard for lightweight
cryptography by the NIST Lightweight Cryptography competition.

This module implements Ascon-128 authenticated encryption with associated data (AEAD).

[+] How it works:
Ascon provides both confidentiality (encryption) and authenticity (integrity protection)
for messages, along with optional associated data (AD) that is authenticated but not encrypted.

[+] Workflow:
1.  Set the TEXT or INFILE option with the message to encrypt/decrypt.
2.  Set the KEY (128-bit, 16 bytes, hex-encoded).
3.  Set the NONCE (128-bit, 16 bytes, hex-encoded).
4.  Optionally, set ASSOCIATED_DATA (hex-encoded).
5.  Set MODE to 'encrypt' or 'decrypt'.
6.  Run the module.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt (Base64 for decrypt)'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'KEY': {'value': '', 'description': '128-bit key (16 bytes, hex-encoded)'},
            'NONCE': {'value': '', 'description': '128-bit nonce (16 bytes, hex-encoded)'},
            'ASSOCIATED_DATA': {'value': '', 'description': 'Optional associated data (hex-encoded)'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['KEY', 'NONCE', ('TEXT', 'INFILE')]
    
    def run(self) -> str:
        if not ASCON_INSTALLED:
            return f"{Colors.FAIL}[-] 'ascon' library not installed.{Colors.ENDC}"

        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
            
        text, data_bytes, err = self._get_input_data(read_as_bytes=True)
        if err:
            return err
            
        key_hex = self.options['KEY']['value']
        nonce_hex = self.options['NONCE']['value']
        ad_hex = self.options['ASSOCIATED_DATA']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        try:
            key = bytes.fromhex(key_hex)
            if len(key) != 16:
                return f"{Colors.FAIL}[-] ERROR: Key must be 128 bits (16 bytes) hex-encoded.{Colors.ENDC}"
            nonce = bytes.fromhex(nonce_hex)
            if len(nonce) != 16:
                return f"{Colors.FAIL}[-] ERROR: Nonce must be 128 bits (16 bytes) hex-encoded.{Colors.ENDC}"
            ad = bytes.fromhex(ad_hex) if ad_hex else b''
        except ValueError:
            return f"{Colors.FAIL}[-] ERROR: Key, Nonce, or Associated Data must be valid hex strings.{Colors.ENDC}"

        if decrypt:
            if text:
                raw_result = ModernCrypto.ascon_decrypt(text.decode(), key, nonce, ad)
            else:
                return f"{Colors.FAIL}[-] No data to decrypt.{Colors.ENDC}"
        else:
            if text:
                raw_result = ModernCrypto.ascon_encrypt(text.decode(), key, nonce, ad)
            else:
                return f"{Colors.FAIL}[-] No data to encrypt.{Colors.ENDC}"
        
        if raw_result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
        
        return self._write_output_data(raw_result)

class PresentModule(CryptoModule):
    """PRESENT Lightweight Block Cipher Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "lightweight/present"
        self.description = "PRESENT lightweight block cipher (Educational Only)"
        self.detailed_description = """
PRESENT is a lightweight block cipher designed for resource-constrained environments.
It operates on 64-bit blocks and supports 80-bit or 128-bit keys.

[+] Security:
PRESENT is a lightweight cipher, and while considered secure for its intended use-case
(resource-constrained devices), it is not recommended for general-purpose high-security
applications. This implementation is for educational purposes only.

[+] Workflow:
1.  Set the TEXT or INFILE option with the message to encrypt/decrypt.
2.  Set the KEY (80-bit or 128-bit, hex-encoded).
3.  Set MODE to 'encrypt' or 'decrypt'.
4.  Run the module.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt (Base64 for decrypt)'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'KEY': {'value': '', 'description': '80-bit (10 bytes) or 128-bit (16 bytes) key, hex-encoded'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['KEY', ('TEXT', 'INFILE')]
    
    def run(self) -> str:
        if not PRESENT_INSTALLED:
            return f"{Colors.FAIL}[-] 'PRESENT' implementation not available.{Colors.ENDC}"

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
            if len(key) not in [10, 16]:
                return f"{Colors.FAIL}[-] ERROR: Key must be 80 bits (10 bytes) or 128 bits (16 bytes) hex-encoded.{Colors.ENDC}"
        except ValueError:
            return f"{Colors.FAIL}[-] ERROR: Key must be a valid hex string.{Colors.ENDC}"

        if decrypt:
            if text:
                raw_result = ModernCrypto.present_decrypt(text.decode(), key)
            else:
                return f"{Colors.FAIL}[-] No data to decrypt.{Colors.ENDC}"
        else:
            if text:
                raw_result = ModernCrypto.present_encrypt(text.decode(), key)
            else:
                return f"{Colors.FAIL}[-] No data to encrypt.{Colors.ENDC}"
        
        if raw_result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
        
        return self._write_output_data(raw_result)

class SpeckModule(CryptoModule):
    """Speck Lightweight Block Cipher Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "lightweight/speck"
        self.description = "Speck lightweight block cipher (Educational Only)"
        self.detailed_description = """
Speck is a lightweight block cipher designed by the NSA for resource-constrained
environments. It is known for its simplicity and efficiency in software.

[+] Security:
Speck is a lightweight cipher, and while designed for specific use-cases,
it is not recommended for general-purpose high-security applications, especially
given its NSA origin which has raised some concerns. This implementation is for
educational purposes only.

[+] Workflow:
1.  Set the TEXT or INFILE option with the message to encrypt/decrypt.
2.  Set the KEY (e.g., 128-bit, 16 bytes, hex-encoded).
3.  Set MODE to 'encrypt' or 'decrypt'.
4.  Run the module.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt (Base64 for decrypt)'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'KEY': {'value': '', 'description': 'Key (hex-encoded, e.g., 16 bytes for 128-bit)'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['KEY', ('TEXT', 'INFILE')]
    
    def run(self) -> str:
        if not SPECK_INSTALLED:
            return f"{Colors.FAIL}[-] 'simonspeckciphers' library not installed.{Colors.ENDC}"

        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
            
        text, data_bytes, err = self._get_input_data(read_as_bytes=True)
        if err:
            return err
            
        key_hex = self.options['KEY']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        try:
            key_int = int(key_hex, 16)
        except ValueError:
            return f"{Colors.FAIL}[-] ERROR: Key must be a valid hex string.{Colors.ENDC}"

        if decrypt:
            if text:
                raw_result = ModernCrypto.speck_decrypt(text.decode(), key_int)
            else:
                return f"{Colors.FAIL}[-] No data to decrypt.{Colors.ENDC}"
        else:
            if text:
                raw_result = ModernCrypto.speck_encrypt(text.decode(), key_int)
            else:
                return f"{Colors.FAIL}[-] No data to encrypt.{Colors.ENDC}"
        
        if raw_result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
        
        return self._write_output_data(raw_result)

class SimonModule(CryptoModule):
    """Simon Lightweight Block Cipher Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "lightweight/simon"
        self.description = "Simon lightweight block cipher (Educational Only)"
        self.detailed_description = """
Simon is a lightweight block cipher designed by the NSA for resource-constrained
environments. It is known for its simplicity and efficiency in hardware.

[+] Security:
Simon is a lightweight cipher, and while designed for specific use-cases,
it is not recommended for general-purpose high-security applications, especially
given its NSA origin which has raised some concerns. This implementation is for
educational purposes only.

[+] Workflow:
1.  Set the TEXT or INFILE option with the message to encrypt/decrypt.
2.  Set the KEY (e.g., 128-bit, 16 bytes, hex-encoded).
3.  Set MODE to 'encrypt' or 'decrypt'.
4.  Run the module.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt (Base64 for decrypt)'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'KEY': {'value': '', 'description': 'Key (hex-encoded, e.g., 16 bytes for 128-bit)'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['KEY', ('TEXT', 'INFILE')]
    
    def run(self) -> str:
        if not SIMON_INSTALLED:
            return f"{Colors.FAIL}[-] 'simonspeckciphers' library not installed.{Colors.ENDC}"

        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
            
        text, data_bytes, err = self._get_input_data(read_as_bytes=True)
        if err:
            return err
            
        key_hex = self.options['KEY']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        try:
            key_int = int(key_hex, 16)
        except ValueError:
            return f"{Colors.FAIL}[-] ERROR: Key must be a valid hex string.{Colors.ENDC}"

        if decrypt:
            if text:
                raw_result = ModernCrypto.simon_decrypt(text.decode(), key_int)
            else:
                return f"{Colors.FAIL}[-] No data to decrypt.{Colors.ENDC}"
        else:
            if text:
                raw_result = ModernCrypto.simon_encrypt(text.decode(), key_int)
            else:
                return f"{Colors.FAIL}[-] No data to encrypt.{Colors.ENDC}"
        
        if raw_result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
        
        return self._write_output_data(raw_result)