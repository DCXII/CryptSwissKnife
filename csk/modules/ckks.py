"""
CKKS Fully Homomorphic Encryption Module
"""
from .base import CryptoModule
from ..utils import Colors
from ..engine import ModernCrypto, PYFHEL_INSTALLED

class CKKSModule(CryptoModule):
    """CKKS Fully Homomorphic Encryption Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "homomorphic/ckks"
        self.description = "CKKS Fully Homomorphic Encryption"
        self.detailed_description = """
CKKS is a Fully Homomorphic Encryption (FHE) scheme that allows approximate
computations on encrypted real or complex numbers. It supports addition and
multiplication.

[+] Workflow:
1.  (One time): Run ACTION=genkeys to create context, public, secret, relinearization, and rotation keys.
2.  (Encryptor): Use the public key to encrypt a list of real numbers.
3.  (Compute): Perform homomorphic addition, multiplication, or rotation on ciphertexts.
4.  (Decryptor): Use the secret key to decrypt the result.
"""
        self.options = {
            'ACTION': {'value': 'genkeys', 'description': 'Action: genkeys, encrypt, decrypt, add, mul, rotate'},
            'CONTEXT_FILE': {'value': 'ckks_context.bin', 'description': 'CKKS context file (IN/OUT)'},
            'PUB_KEY': {'value': 'ckks_pub.bin', 'description': 'CKKS public key file (IN/OUT)'},
            'PRIV_KEY': {'value': 'ckks_priv.bin', 'description': 'CKKS private key file (IN/OUT)'},
            'RELIN_KEY': {'value': 'ckks_relin.bin', 'description': 'CKKS relinearization key file (IN/OUT)'},
            'ROTATE_KEY': {'value': 'ckks_rotate.bin', 'description': 'CKKS rotation key file (IN/OUT)'},
            'PLAINTEXT': {'value': '', 'description': 'Comma-separated real numbers to encrypt (e.g., "1.0,2.5,3.1")'},
            'CIPHERTEXT1': {'value': '', 'description': 'Base64 ciphertext 1 for add/mul/rotate'},
            'CIPHERTEXT2': {'value': '', 'description': 'Base64 ciphertext 2 for add/mul'},
            'STEPS': {'value': '1', 'description': 'Number of steps to rotate (for "rotate" action)'},
        }
        self.required_options = ['ACTION']
    
    def run(self) -> str:
        if not PYFHEL_INSTALLED:
            return f"{Colors.FAIL}[-] 'Pyfhel' library not installed.{Colors.ENDC}"
            
        action = self.options['ACTION']['value'].lower()
        context_file = self.options['CONTEXT_FILE']['value']
        pub_key_file = self.options['PUB_KEY']['value']
        priv_key_file = self.options['PRIV_KEY']['value']
        relin_key_file = self.options['RELIN_KEY']['value']
        rotate_key_file = self.options['ROTATE_KEY']['value']

        try:
            if action == 'genkeys':
                success, msg = ModernCrypto.ckks_genkeys(context_file, pub_key_file, priv_key_file, relin_key_file, rotate_key_file)
                return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"

            elif action == 'encrypt':
                plaintext_str = self.options['PLAINTEXT']['value']
                if not plaintext_str:
                    return f"{Colors.FAIL}[-] Missing required option: PLAINTEXT{Colors.ENDC}"
                try:
                    plaintext = [float(x.strip()) for x in plaintext_str.split(',')]
                except ValueError:
                    return f"{Colors.FAIL}[-] PLAINTEXT must be comma-separated real numbers.{Colors.ENDC}"
                
                if not pub_key_file:
                    return f"{Colors.FAIL}[-] Missing required option: PUB_KEY{Colors.ENDC}"
                
                raw_result = ModernCrypto.ckks_encrypt(context_file, pub_key_file, plaintext)
                if raw_result.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
                
                self.options['CIPHERTEXT1']['value'] = raw_result
                return (f"{Colors.OKGREEN}[+] Plaintext encrypted. Ciphertext (Base64):{Colors.ENDC} {raw_result}\n"
                        f"{Colors.OKCYAN}[*] CIPHERTEXT1 option has been updated.{Colors.ENDC}")

            elif action == 'decrypt':
                ciphertext_b64 = self.options['CIPHERTEXT1']['value']
                if not ciphertext_b64:
                    return f"{Colors.FAIL}[-] Missing required option: CIPHERTEXT1{Colors.ENDC}"
                
                raw_result = ModernCrypto.ckks_decrypt(context_file, priv_key_file, ciphertext_b64)
                if isinstance(raw_result, str) and raw_result.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
                return f"{Colors.OKGREEN}[+] Decrypted Plaintext:{Colors.ENDC} {raw_result}"

            elif action == 'add':
                ctxt1_b64 = self.options['CIPHERTEXT1']['value']
                ctxt2_b64 = self.options['CIPHERTEXT2']['value']
                if not ctxt1_b64 or not ctxt2_b64:
                    return f"{Colors.FAIL}[-] Missing required options: CIPHERTEXT1 and CIPHERTEXT2{Colors.ENDC}"
                
                raw_result = ModernCrypto.ckks_add(context_file, ctxt1_b64, ctxt2_b64)
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
                
                raw_result = ModernCrypto.ckks_mul(context_file, ctxt1_b64, ctxt2_b64)
                if raw_result.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
                
                self.options['CIPHERTEXT1']['value'] = raw_result
                return (f"{Colors.OKGREEN}[+] Ciphertexts multiplied. Resulting Ciphertext (Base64):{Colors.ENDC} {raw_result}\n"
                        f"{Colors.OKCYAN}[*] CIPHERTEXT1 option has been updated.{Colors.ENDC}")

            elif action == 'rotate':
                ciphertext_b64 = self.options['CIPHERTEXT1']['value']
                steps_str = self.options['STEPS']['value']
                if not ciphertext_b64:
                    return f"{Colors.FAIL}[-] Missing required option: CIPHERTEXT1{Colors.ENDC}"
                try:
                    steps = int(steps_str)
                except ValueError:
                    return f"{Colors.FAIL}[-] STEPS must be an integer.{Colors.ENDC}"
                
                raw_result = ModernCrypto.ckks_rotate(context_file, rotate_key_file, ciphertext_b64, steps)
                if raw_result.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
                
                self.options['CIPHERTEXT1']['value'] = raw_result
                return (f"{Colors.OKGREEN}[+] Ciphertext rotated. Resulting Ciphertext (Base64):{Colors.ENDC} {raw_result}\n"
                        f"{Colors.OKCYAN}[*] CIPHERTEXT1 option has been updated.{Colors.ENDC}")
                
            else:
                return f"{Colors.FAIL}[-] Unknown action: {action}{Colors.ENDC}"
        
        except Exception as e:
            return f"{Colors.FAIL}[-] ERROR: {str(e)}{Colors.ENDC}"