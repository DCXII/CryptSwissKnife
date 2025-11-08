"""
Paillier Homomorphic Encryption Module
"""
from .base import CryptoModule
from ..utils import Colors
from ..engine import ModernCrypto, PHE_INSTALLED

class PaillierModule(CryptoModule):
    """Paillier Homomorphic Encryption Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "homomorphic/paillier"
        self.description = "Paillier Homomorphic Encryption"
        self.detailed_description = """
Paillier is an additive homomorphic encryption scheme, meaning that
arithmetic operations can be performed directly on ciphertexts.

[+] Workflow:
1.  (One time): Run ACTION=genkeys to create `paillier_priv.bin` and `paillier_pub.bin`.
2.  (Encryptor): Use the recipient's public key (`paillier_pub.bin`) to encrypt a number.
3.  (Decryptor): Use their private key (`paillier_priv.bin`) to decrypt the number.
"""
        self.options = {
            'ACTION': {'value': 'genkeys', 'description': 'Action: genkeys, encrypt, decrypt'},
            'KEY_LENGTH': {'value': '2048', 'description': 'Key length in bits (e.g., 1024, 2048)'},
            'PUB_KEY': {'value': 'paillier_pub.bin', 'description': 'Public key file (IN/OUT)'},
            'PRIV_KEY': {'value': 'paillier_priv.bin', 'description': 'Private key file (IN/OUT)'},
            'NUMBER': {'value': '', 'description': 'Integer to encrypt'},
            'CIPHERTEXT': {'value': '', 'description': 'Base64 ciphertext to decrypt'},
        }
        self.required_options = ['ACTION']
    
    def run(self) -> str:
        if not PHE_INSTALLED:
            return f"{Colors.FAIL}[-] 'phe' library not installed.{Colors.ENDC}"
            
        action = self.options['ACTION']['value'].lower()
        pub_key_path = self.options['PUB_KEY']['value']
        priv_key_path = self.options['PRIV_KEY']['value']

        try:
            if action == 'genkeys':
                key_length = int(self.options['KEY_LENGTH']['value'])
                success, msg = ModernCrypto.paillier_genkeys(priv_key_path, pub_key_path, key_length)
                return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"

            elif action == 'encrypt':
                number_str = self.options['NUMBER']['value']
                if not number_str:
                    return f"{Colors.FAIL}[-] Missing required option: NUMBER{Colors.ENDC}"
                try:
                    number = int(number_str)
                except ValueError:
                    return f"{Colors.FAIL}[-] NUMBER must be an integer.{Colors.ENDC}"
                
                if not pub_key_path:
                    return f"{Colors.FAIL}[-] Missing required option: PUB_KEY{Colors.ENDC}"
                
                raw_result = ModernCrypto.paillier_encrypt(pub_key_path, number)
                if raw_result.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
                
                self.options['CIPHERTEXT']['value'] = raw_result
                return (f"{Colors.OKGREEN}[+] Number encrypted. Ciphertext (Base64):{Colors.ENDC} {raw_result}\n"
                        f"{Colors.OKCYAN}[*] CIPHERTEXT option has been updated.{Colors.ENDC}")

            elif action == 'decrypt':
                ciphertext_b64 = self.options['CIPHERTEXT']['value']
                if not ciphertext_b64:
                    return f"{Colors.FAIL}[-] Missing required option: CIPHERTEXT{Colors.ENDC}"
                if not priv_key_path:
                    return f"{Colors.FAIL}[-] Missing required option: PRIV_KEY{Colors.ENDC}"
                
                raw_result = ModernCrypto.paillier_decrypt(priv_key_path, ciphertext_b64)
                if isinstance(raw_result, str) and raw_result.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
                return f"{Colors.OKGREEN}[+] Decrypted Number:{Colors.ENDC} {raw_result}"                
            else:
                return f"{Colors.FAIL}[-] Unknown action: {action}{Colors.ENDC}"
        
        except Exception as e:
            return f"{Colors.FAIL}[-] ERROR: {str(e)}{Colors.ENDC}"