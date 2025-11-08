"""
BFV Fully Homomorphic Encryption Module
"""
from .base import CryptoModule
from ..utils import Colors
from ..engine import ModernCrypto, PYFHEL_INSTALLED

class BFVModule(CryptoModule):
    """BFV Fully Homomorphic Encryption Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "homomorphic/bfv"
        self.description = "BFV Fully Homomorphic Encryption"
        self.detailed_description = """
BFV is a Fully Homomorphic Encryption (FHE) scheme that allows computations
on encrypted data without decrypting it first. It supports addition and
multiplication of integers.

[+] Workflow:
1.  (One time): Run ACTION=genkeys to create context, public, and secret keys.
2.  (Encryptor): Use the public key to encrypt a list of integers.
3.  (Compute): Perform homomorphic addition or multiplication on ciphertexts.
4.  (Decryptor): Use the secret key to decrypt the result.
"""
        self.options = {
            'ACTION': {'value': 'genkeys', 'description': 'Action: genkeys, encrypt, decrypt, add, mul'},
            'CONTEXT_FILE': {'value': 'bfv_context.bin', 'description': 'BFV context file (IN/OUT)'},
            'PUB_KEY': {'value': 'bfv_pub.bin', 'description': 'BFV public key file (IN/OUT)'},
            'PRIV_KEY': {'value': 'bfv_priv.bin', 'description': 'BFV private key file (IN/OUT)'},
            'PLAINTEXT': {'value': '', 'description': 'Comma-separated integers to encrypt (e.g., "1,2,3")'},
            'CIPHERTEXT1': {'value': '', 'description': 'Base64 ciphertext 1 for add/mul'},
            'CIPHERTEXT2': {'value': '', 'description': 'Base64 ciphertext 2 for add/mul'},
        }
        self.required_options = ['ACTION']
    
    def run(self) -> str:
        if not PYFHEL_INSTALLED:
            return f"{Colors.FAIL}[-] 'Pyfhel' library not installed.{Colors.ENDC}"
            
        action = self.options['ACTION']['value'].lower()
        context_file = self.options['CONTEXT_FILE']['value']
        pub_key_file = self.options['PUB_KEY']['value']
        priv_key_file = self.options['PRIV_KEY']['value']

        try:
            if action == 'genkeys':
                success, msg = ModernCrypto.bfv_genkeys(context_file, pub_key_file, priv_key_file)
                return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"

            elif action == 'encrypt':
                plaintext_str = self.options['PLAINTEXT']['value']
                if not plaintext_str:
                    return f"{Colors.FAIL}[-] Missing required option: PLAINTEXT{Colors.ENDC}"
                try:
                    plaintext = [int(x.strip()) for x in plaintext_str.split(',')]
                except ValueError:
                    return f"{Colors.FAIL}[-] PLAINTEXT must be comma-separated integers.{Colors.ENDC}"
                
                if not pub_key_file:
                    return f"{Colors.FAIL}[-] Missing required option: PUB_KEY{Colors.ENDC}"
                
                raw_result = ModernCrypto.bfv_encrypt(context_file, pub_key_file, plaintext)
                if raw_result.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
                
                self.options['CIPHERTEXT1']['value'] = raw_result
                return (f"{Colors.OKGREEN}[+] Plaintext encrypted. Ciphertext (Base64):{Colors.ENDC} {raw_result}\n"
                        f"{Colors.OKCYAN}[*] CIPHERTEXT1 option has been updated.{Colors.ENDC}")

            elif action == 'decrypt':
                ciphertext_b64 = self.options['CIPHERTEXT1']['value']
                if not ciphertext_b64:
                    return f"{Colors.FAIL}[-] Missing required option: CIPHERTEXT1{Colors.ENDC}"
                
                raw_result = ModernCrypto.bfv_decrypt(context_file, priv_key_file, ciphertext_b64)
                if isinstance(raw_result, str) and raw_result.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
                return f"{Colors.OKGREEN}[+] Decrypted Plaintext:{Colors.ENDC} {raw_result}"

            elif action == 'add':
                ctxt1_b64 = self.options['CIPHERTEXT1']['value']
                ctxt2_b64 = self.options['CIPHERTEXT2']['value']
                if not ctxt1_b64 or not ctxt2_b64:
                    return f"{Colors.FAIL}[-] Missing required options: CIPHERTEXT1 and CIPHERTEXT2{Colors.ENDC}"
                
                raw_result = ModernCrypto.bfv_add(context_file, ctxt1_b64, ctxt2_b64)
                if raw_result.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
                
                self.options['CIPHERTEXT1']['value'] = raw_result
                return (f"{Colors.OKGREEN}[+] Ciphertexts added. Resulting Ciphertext (Base64):{Colors.ENDC} {raw_result}\n"
                        f"{Colors.OKCYAN}[*] CIPHERTEXT1 option has been updated.{Colors.ENDC}")

            elif action == 'mul':
                ctxt1_b64 = self.options['CIPHERTEXT1']['value']
                ctxt2_b64 = self.options['CIPHERTEXT2']['value']
                if not ctxt1_b64 or not ctxt2_b64:
                    return f"{Colors.FAIL}[-] Missing required options: CIPHERTEXT1 and CIPHERTEXT2{Colors.ENDC}"
                
                raw_result = ModernCrypto.bfv_mul(context_file, ctxt1_b64, ctxt2_b64)
                if raw_result.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
                
                self.options['CIPHERTEXT1']['value'] = raw_result
                return (f"{Colors.OKGREEN}[+] Ciphertexts multiplied. Resulting Ciphertext (Base64):{Colors.ENDC} {raw_result}\n"
                        f"{Colors.OKCYAN}[*] CIPHERTEXT1 option has been updated.{Colors.ENDC}")
                
            else:
                return f"{Colors.FAIL}[-] Unknown action: {action}{Colors.ENDC}"
        
        except Exception as e:
            return f"{Colors.FAIL}[-] ERROR: {str(e)}{Colors.ENDC}"