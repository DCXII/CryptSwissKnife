"""
All Modern Symmetric Cipher modules
"""
from .base import CryptoModule
from ..utils import Colors
from ..engine import ModernCrypto

class AESModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "modern/aes"
        self.description = "AES-256-GCM authenticated encryption"
        self.detailed_description = """
The Advanced Encryption Standard (AES) is the U.S. government standard for symmetric encryption. It is used worldwide to protect sensitive data.

This module implements AES in GCM mode (Galois/Counter Mode).

[+] How it works:
1.  **Key Derivation**: Your PASSWORD is combined with a random 'salt' and fed into a Key Derivation Function (PBKDF2) to produce a strong 256-bit encryption key. This prevents pre-computed (rainbow table) attacks.
2.  **Encryption**: The plaintext is encrypted using the 256-bit key in GCM mode. GCM is an "authenticated" mode (AEAD), which means it provides both:
    * **Confidentiality**: The data is unreadable.
    * **Authenticity**: The data is protected from tampering. An attempt to modify the ciphertext will cause decryption to fail.
3.  **Output**: The final output is a Base64 string containing:
    [ 16-byte Salt | 12-byte Nonce | Encrypted Data ]

[+] Security:
AES-256-GCM is the industry standard for high-security symmetric encryption. It is considered secure against all known practical attacks.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt (Base64 for decrypt)'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'PASSWORD': {'value': '', 'description': 'Password for encryption'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['PASSWORD', ('TEXT', 'INFILE')]
    
    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
            
        text, data_bytes, err = self._get_input_data(read_as_bytes=True)
        if err:
            return err
            
        password = self.options['PASSWORD']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        if decrypt:
            if text:
                raw_result = ModernCrypto.aes_decrypt(text.decode(), password)
            else:
                return f"{Colors.FAIL}[-] No data to decrypt.{Colors.ENDC}"
        else:
            if text:
                raw_result = ModernCrypto.aes_encrypt(text.decode(), password)
            else:
                return f"{Colors.FAIL}[-] No data to encrypt.{Colors.ENDC}"
        
        if raw_result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
        
        return self._write_output_data(raw_result)

class ChaCha20Module(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "modern/chacha20"
        self.description = "ChaCha20-Poly1305 authenticated encryption"
        self.detailed_description = """
ChaCha20-Poly1305 is a modern authenticated encryption algorithm.
It combines the ChaCha20 stream cipher for confidentiality with the Poly1305 message
authentication code for authenticity and integrity.

[+] Security:
ChaCha20-Poly1305 is a highly secure and performant algorithm, often used as an
alternative to AES-GCM, especially in software implementations where AES hardware
acceleration is not available. It is widely used in TLS and other protocols.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt (Base64 for decrypt)'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'PASSWORD': {'value': '', 'description': 'Password for encryption'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['PASSWORD', ('TEXT', 'INFILE')]

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
            
        text, data_bytes, err = self._get_input_data(read_as_bytes=True)
        if err:
            return err
            
        password = self.options['PASSWORD']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        if decrypt:
            if text:
                raw_result = ModernCrypto.chacha20_decrypt(text.decode(), password)
            else:
                return f"{Colors.FAIL}[-] No data to decrypt.{Colors.ENDC}"
        else:
            if text:
                raw_result = ModernCrypto.chacha20_encrypt(text.decode(), password)
            else:
                return f"{Colors.FAIL}[-] No data to encrypt.{Colors.ENDC}"
            
        if raw_result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
            
        return self._write_output_data(raw_result)

class BlowfishModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "modern/blowfish"
        self.description = "Blowfish cipher (CBC mode with PKCS7 padding)"
        self.detailed_description = """
Blowfish is a symmetric-key block cipher designed by Bruce Schneier.
It has a 64-bit block size and a variable key length from 32 bits to 448 bits.

[+] Security:
Blowfish is considered secure if a sufficiently long key is used. However, due to its
64-bit block size, it can be susceptible to birthday attacks if large amounts of data
are encrypted under the same key. AES is generally preferred for new applications.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt (Base64 for decrypt)'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'PASSWORD': {'value': '', 'description': 'Password to derive key'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['PASSWORD', ('TEXT', 'INFILE')]

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
        
        text, _, err = self._get_input_data(read_as_bytes=True)
        if err:
            return err
            
        password = self.options['PASSWORD']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        try:
            if decrypt:
                if text:
                    raw_result = ModernCrypto.blowfish_decrypt(text.decode(), password)
                else:
                    return f"{Colors.FAIL}[-] No data to decrypt.{Colors.ENDC}"
            else:
                if text:
                    raw_result = ModernCrypto.blowfish_encrypt(text.decode(), password)
                else:
                    return f"{Colors.FAIL}[-] No data to encrypt.{Colors.ENDC}"
        except Exception as e:
            return f"{Colors.FAIL}[-] ERROR: Operation failed. {str(e)}{Colors.ENDC}"

        if raw_result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
            
        return self._write_output_data(raw_result)

class DESModule(CryptoModule):
    """DES-CBC Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "modern/des"
        self.description = "DES cipher (CBC mode) - INSECURE"
        self.detailed_description = """
DES (Data Encryption Standard) is an obsolete symmetric-key block cipher.
It uses a 56-bit key and a 64-bit block size.

[+] Security:
INSECURE. DES is thoroughly broken and vulnerable to brute-force attacks in minutes.
It is provided here for educational or legacy purposes (e.g., CTFs) only.
DO NOT USE THIS FOR REAL-WORLD SECURITY.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt (Base64 for decrypt)'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'PASSWORD': {'value': '', 'description': 'Password to derive 8-byte key'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['PASSWORD', ('TEXT', 'INFILE')]

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
        
        text, _, err = self._get_input_data(read_as_bytes=True)
        if err:
            return err
            
        password = self.options['PASSWORD']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        try:
            if decrypt:
                if text:
                    raw_result = ModernCrypto.des_decrypt(text.decode(), password)
                else:
                    return f"{Colors.FAIL}[-] No data to decrypt.{Colors.ENDC}"
            else:
                if text:
                    raw_result = ModernCrypto.des_encrypt(text.decode(), password)
                else:
                    return f"{Colors.FAIL}[-] No data to encrypt.{Colors.ENDC}"
        except Exception as e:
            return f"{Colors.FAIL}[-] ERROR: Operation failed. {str(e)}{Colors.ENDC}"

        if raw_result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
            
        return self._write_output_data(raw_result)

class TripleDESModule(CryptoModule):
    """3DES-CBC Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "modern/3des"
        self.description = "3DES (Triple DES) cipher (CBC mode)"
        self.detailed_description = """
3DES (Triple DES) was the successor to DES, designed to fix its small key size.
It applies the DES cipher three times with two or three different keys.

[+] Security:
DEPRECATED. 3DES is slow and has a small 64-bit block size, which makes it vulnerable to some attacks (like Sweet32) if used for large amounts of data.
It is considered secure enough for some legacy applications but AES is strongly preferred.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt (Base64 for decrypt)'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'PASSWORD': {'value': '', 'description': 'Password to derive 24-byte key'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['PASSWORD', ('TEXT', 'INFILE')]

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
        
        text, _, err = self._get_input_data(read_as_bytes=True)
        if err:
            return err
            
        password = self.options['PASSWORD']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        try:
            if decrypt:
                if text:
                    raw_result = ModernCrypto.triple_des_decrypt(text.decode(), password)
                else:
                    return f"{Colors.FAIL}[-] No data to decrypt.{Colors.ENDC}"
            else:
                if text:
                    raw_result = ModernCrypto.triple_des_encrypt(text.decode(), password)
                else:
                    return f"{Colors.FAIL}[-] No data to encrypt.{Colors.ENDC}"
        except Exception as e:
            return f"{Colors.FAIL}[-] ERROR: Operation failed. {str(e)}{Colors.ENDC}"

        if raw_result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
            
        return self._write_output_data(raw_result)

class TwofishModule(CryptoModule):
    """Twofish-CBC Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "modern/twofish"
        self.description = "Twofish cipher (CBC mode)"
        self.detailed_description = """
Twofish is a symmetric-key block cipher with a 128-bit block size and keys up to 256 bits.
It was one of the five finalists in the AES competition.

[+] Security:
Twofish is considered highly secure and is not known to be broken. It is a strong, reliable alternative to AES.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt (Base64 for decrypt)'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'PASSWORD': {'value': '', 'description': 'Password to derive 32-byte (256-bit) key'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['PASSWORD', ('TEXT', 'INFILE')]

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
        
        text, _, err = self._get_input_data(read_as_bytes=True)
        if err:
            return err
            
        password = self.options['PASSWORD']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        try:
            if decrypt:
                if text:
                    raw_result = ModernCrypto.twofish_decrypt(text.decode(), password)
                else:
                    return f"{Colors.FAIL}[-] No data to decrypt.{Colors.ENDC}"
            else:
                if text:
                    raw_result = ModernCrypto.twofish_encrypt(text.decode(), password)
                else:
                    return f"{Colors.FAIL}[-] No data to encrypt.{Colors.ENDC}"
        except Exception as e:
            return f"{Colors.FAIL}[-] ERROR: Operation failed. {str(e)}{Colors.ENDC}"

        if raw_result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
            
        return self._write_output_data(raw_result)

class CamelliaModule(CryptoModule):
    """Camellia-CBC Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "modern/camellia"
        self.description = "Camellia cipher (CBC mode)"
        self.detailed_description = """
Camellia is a symmetric-key block cipher with a 128-bit block size and keys up to 256 bits.
It was developed in Japan and is approved for use by the Japanese government.

[+] Security:
Camellia is considered highly secure, with a security level comparable to AES. It is an excellent, modern cipher.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt (Base64 for decrypt)'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'PASSWORD': {'value': '', 'description': 'Password to derive 32-byte (256-bit) key'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['PASSWORD', ('TEXT', 'INFILE')]

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
        
        text, _, err = self._get_input_data(read_as_bytes=True)
        if err:
            return err
            
        password = self.options['PASSWORD']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        try:
            if decrypt:
                if text:
                    raw_result = ModernCrypto.camellia_decrypt(text.decode(), password)
                else:
                    return f"{Colors.FAIL}[-] No data to decrypt.{Colors.ENDC}"
            else:
                if text:
                    raw_result = ModernCrypto.camellia_encrypt(text.decode(), password)
                else:
                    return f"{Colors.FAIL}[-] No data to encrypt.{Colors.ENDC}"
        except Exception as e:
            return f"{Colors.FAIL}[-] ERROR: Operation failed. {str(e)}{Colors.ENDC}"

        if raw_result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
            
        return self._write_output_data(raw_result)

class RC4Module(CryptoModule):
    """RC4 Stream Cipher Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "stream/rc4"
        self.description = "RC4 stream cipher - INSECURE"
        self.detailed_description = """
RC4 is a stream cipher. It was once widely used (e.g., in SSL, WEP) but is now considered completely insecure.

[+] Security:
INSECURE. RC4 is vulnerable to several attacks (e.g., Fluhrer-Mantin-Shamir attack) that can recover the key.
It is provided here for educational or legacy purposes (e.g., CTFs) only.
DO NOT USE THIS FOR REAL-WORLD SECURITY.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt (Base64 for decrypt)'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'PASSWORD': {'value': '', 'description': 'Password to derive 16-byte (128-bit) key'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['PASSWORD', ('TEXT', 'INFILE')]

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
        
        text, _, err = self._get_input_data(read_as_bytes=True)
        if err:
            return err
            
        password = self.options['PASSWORD']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        try:
            if decrypt:
                if text:
                    raw_result = ModernCrypto.rc4_decrypt(text.decode(), password)
                else:
                    return f"{Colors.FAIL}[-] No data to decrypt.{Colors.ENDC}"
            else:
                if text:
                    raw_result = ModernCrypto.rc4_encrypt(text.decode(), password)
                else:
                    return f"{Colors.FAIL}[-] No data to encrypt.{Colors.ENDC}"
        except Exception as e:
            return f"{Colors.FAIL}[-] ERROR: Operation failed. {str(e)}{Colors.ENDC}"

        if raw_result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
            
        return self._write_output_data(raw_result)

class IDEAModule(CryptoModule):
    """IDEA Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "modern/idea"
        self.description = "IDEA cipher (CBC mode)"
        self.detailed_description = """
IDEA (International Data Encryption Algorithm) is a symmetric-key block cipher.
It has a 64-bit block size and a 128-bit key.

[+] Security:
IDEA is considered a secure cipher, though it is not as widely used as AES.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt (Base64 for decrypt)'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'PASSWORD': {'value': '', 'description': 'Password to derive 16-byte (128-bit) key'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['PASSWORD', ('TEXT', 'INFILE')]

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
        
        text, _, err = self._get_input_data(read_as_bytes=True)
        if err:
            return err
            
        password = self.options['PASSWORD']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        try:
            if decrypt:
                if text:
                    raw_result = ModernCrypto.idea_decrypt(text.decode(), password)
                else:
                    return f"{Colors.FAIL}[-] No data to decrypt.{Colors.ENDC}"
            else:
                if text:
                    raw_result = ModernCrypto.idea_encrypt(text, password)
                else:
                    return f"{Colors.FAIL}[-] No data to encrypt.{Colors.ENDC}"
        except Exception as e:
            return f"{Colors.FAIL}[-] ERROR: Operation failed. {str(e)}{Colors.ENDC}"

        if raw_result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
            
        return self._write_output_data(raw_result)

class RC2Module(CryptoModule):
    """RC2 Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "modern/rc2"
        self.description = "RC2 cipher (CBC mode)"
        self.detailed_description = """
RC2 is a symmetric-key block cipher.
It has a 64-bit block size and a variable key size.

[+] Security:
RC2 is considered weak and is not recommended for new applications.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt (Base64 for decrypt)'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'PASSWORD': {'value': '', 'description': 'Password to derive 16-byte (128-bit) key'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['PASSWORD', ('TEXT', 'INFILE')]

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
        
        text, _, err = self._get_input_data(read_as_bytes=True)
        if err:
            return err
            
        password = self.options['PASSWORD']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        try:
            if decrypt:
                if text:
                    raw_result = ModernCrypto.rc2_decrypt(text.decode(), password)
                else:
                    return f"{Colors.FAIL}[-] No data to decrypt.{Colors.ENDC}"
            else:
                if text:
                    raw_result = ModernCrypto.rc2_encrypt(text, password)
                else:
                    return f"{Colors.FAIL}[-] No data to encrypt.{Colors.ENDC}"
        except Exception as e:
            return f"{Colors.FAIL}[-] ERROR: Operation failed. {str(e)}{Colors.ENDC}"

        if raw_result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
            
        return self._write_output_data(raw_result)

class RC5Module(CryptoModule):
    """RC5 Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "modern/rc5"
        self.description = "RC5 cipher (ECB mode)"
        self.detailed_description = """
RC5 is a symmetric-key block cipher.
It has a 64-bit block size and a variable key size.

[+] Security:
RC5 is considered weak and is not recommended for new applications.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt (Base64 for decrypt)'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'PASSWORD': {'value': '', 'description': 'Password to derive 16-byte (128-bit) key'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['PASSWORD', ('TEXT', 'INFILE')]

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
        
        text, _, err = self._get_input_data(read_as_bytes=True)
        if err:
            return err
            
        password = self.options['PASSWORD']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        try:
            if decrypt:
                if text:
                    raw_result = ModernCrypto.rc5_decrypt(text.decode(), password)
                else:
                    return f"{Colors.FAIL}[-] No data to decrypt.{Colors.ENDC}"
            else:
                if text:
                    raw_result = ModernCrypto.rc5_encrypt(text, password)
                else:
                    return f"{Colors.FAIL}[-] No data to encrypt.{Colors.ENDC}"
        except Exception as e:
            return f"{Colors.FAIL}[-] ERROR: Operation failed. {str(e)}{Colors.ENDC}"

        if raw_result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
            
        return self._write_output_data(raw_result)

class RC6Module(CryptoModule):
    """RC6 Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "modern/rc6"
        self.description = "RC6 cipher (ECB mode)"
        self.detailed_description = """
RC6 is a symmetric-key block cipher.
It has a 128-bit block size and a variable key size.

[+] Security:
RC6 was a finalist in the AES competition and is considered secure.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt (Base64 for decrypt)'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'PASSWORD': {'value': '', 'description': 'Password to derive 32-byte (256-bit) key'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['PASSWORD', ('TEXT', 'INFILE')]

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
        
        text, _, err = self._get_input_data(read_as_bytes=True)
        if err:
            return err
            
        password = self.options['PASSWORD']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        try:
            if decrypt:
                if text:
                    raw_result = ModernCrypto.rc6_decrypt(text.decode(), password)
                else:
                    return f"{Colors.FAIL}[-] No data to decrypt.{Colors.ENDC}"
            else:
                if text:
                    raw_result = ModernCrypto.rc6_encrypt(text, password)
                else:
                    return f"{Colors.FAIL}[-] No data to encrypt.{Colors.ENDC}"
        except Exception as e:
            return f"{Colors.FAIL}[-] ERROR: Operation failed. {str(e)}{Colors.ENDC}"

        if raw_result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
            
        return self._write_output_data(raw_result)

class SerpentModule(CryptoModule):
    """Serpent Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "modern/serpent"
        self.description = "Serpent cipher (CBC mode)"
        self.detailed_description = """
Serpent is a symmetric-key block cipher.
It was a finalist in the AES competition and is considered very secure.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt (Base64 for decrypt)'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'PASSWORD': {'value': '', 'description': 'Password to derive 32-byte (256-bit) key'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['PASSWORD', ('TEXT', 'INFILE')]

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
        
        text, _, err = self._get_input_data(read_as_bytes=True)
        if err:
            return err
            
        password = self.options['PASSWORD']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        try:
            if decrypt:
                if text:
                    raw_result = ModernCrypto.serpent_decrypt(text.decode(), password)
                else:
                    return f"{Colors.FAIL}[-] No data to decrypt.{Colors.ENDC}"
            else:
                if text:
                    raw_result = ModernCrypto.serpent_encrypt(text, password)
                else:
                    return f"{Colors.FAIL}[-] No data to encrypt.{Colors.ENDC}"
        except Exception as e:
            return f"{Colors.FAIL}[-] ERROR: Operation failed. {str(e)}{Colors.ENDC}"

        if raw_result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
            
        return self._write_output_data(raw_result)

class Salsa20Module(CryptoModule):
    """Salsa20 Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "stream/salsa20"
        self.description = "Salsa20 stream cipher"
        self.detailed_description = """
Salsa20 is a stream cipher designed by Daniel J. Bernstein.
It is known for its high performance and security.

[+] Security:
Salsa20 is considered a very secure stream cipher.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt (Base64 for decrypt)'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'PASSWORD': {'value': '', 'description': 'Password to derive 32-byte (256-bit) key'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['PASSWORD', ('TEXT', 'INFILE')]

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
        
        text, _, err = self._get_input_data(read_as_bytes=True)
        if err:
            return err
            
        password = self.options['PASSWORD']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        try:
            if decrypt:
                if text:
                    raw_result = ModernCrypto.salsa20_decrypt(text.decode(), password)
                else:
                    return f"{Colors.FAIL}[-] No data to decrypt.{Colors.ENDC}"
            else:
                if text:
                    raw_result = ModernCrypto.salsa20_encrypt(text, password)
                else:
                    return f"{Colors.FAIL}[-] No data to encrypt.{Colors.ENDC}"
        except Exception as e:
            return f"{Colors.FAIL}[-] ERROR: Operation failed. {str(e)}{Colors.ENDC}"

        if raw_result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
            
        return self._write_output_data(raw_result)