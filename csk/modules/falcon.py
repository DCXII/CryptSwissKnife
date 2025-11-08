"""
Falcon Post-Quantum Digital Signature Module
"""
from .base import CryptoModule
from ..utils import Colors
from ..engine import ModernCrypto, OQS_INSTALLED

class FalconModule(CryptoModule):
    """Falcon Post-Quantum Digital Signature Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "pqc/falcon"
        self.description = "Falcon Post-Quantum Digital Signatures"
        self.detailed_description = """
Falcon is a post-quantum digital signature scheme designed
to be secure against attacks from quantum computers. It is a candidate for
standardization by NIST.

[+] Workflow:
1.  (Signer): Run ACTION=genkeys to create `falcon_priv.bin` and `falcon_pub.bin`.
2.  (Signer): Give `falcon_pub.bin` to the verifier.
3.  (Signer): Run ACTION=sign, setting PRIV_KEY and INFILE (or TEXT) to sign.
    This produces a Base64 signature. Set the SIGNATURE option.
4.  (Verifier): Run ACTION=verify, setting PUB_KEY, INFILE (or TEXT),
    and the SIGNATURE to verify.
"""
        self.options = {
            'ACTION': {'value': 'genkeys', 'description': 'Action: genkeys, sign, verify'},
            'ALGORITHM': {'value': 'Falcon512', 'description': 'Falcon algorithm (e.g., Falcon512, Falcon1024)'},
            'PUB_KEY': {'value': 'falcon_pub.bin', 'description': 'Public key file (IN/OUT)'},
            'PRIV_KEY': {'value': 'falcon_priv.bin', 'description': 'Private key file (IN/OUT)'},
            'TEXT': {'value': '', 'description': 'Plaintext message to sign/verify'},
            'INFILE': {'value': '', 'description': 'Input file to sign/verify (overrides TEXT)'},
            'SIGNATURE': {'value': '', 'description': 'Base64 signature to verify (IN)'},
        }
        self.required_options = ['ACTION']
    
    def run(self) -> str:
        if not OQS_INSTALLED:
            return f"{Colors.FAIL}[-] 'liboqs-python' library not installed.{Colors.ENDC}"
            
        action = self.options['ACTION']['value'].lower()
        algorithm = self.options['ALGORITHM']['value']
        pub_key_path = self.options['PUB_KEY']['value']
        priv_key_path = self.options['PRIV_KEY']['value']
        
        if action == 'genkeys':
            success, msg = ModernCrypto.falcon_genkeys(priv_key_path, pub_key_path, algorithm)
            return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"

        elif action == 'sign':
            _, data_bytes, err = self._get_input_data(read_as_bytes=True)
            if err:
                return err
            if not priv_key_path:
                return f"{Colors.FAIL}[-] Missing required option: PRIV_KEY{Colors.ENDC}"

            raw_result = ModernCrypto.falcon_sign(priv_key_path, data_bytes, algorithm)
            if raw_result.startswith("ERROR:"):
                return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
            
            self.options['SIGNATURE']['value'] = raw_result
            return (f"{Colors.OKGREEN}[+] Message signed. Signature (Base64):{Colors.ENDC} {raw_result}\n"
                    f"{Colors.OKCYAN}[*] SIGNATURE option has been updated.{Colors.ENDC}")

        elif action == 'verify':
            _, data_bytes, err = self._get_input_data(read_as_bytes=True)
            if err:
                return err
            signature = self.options['SIGNATURE']['value']
            if not pub_key_path:
                return f"{Colors.FAIL}[-] Missing required option: PUB_KEY{Colors.ENDC}"
            if not signature:
                return f"{Colors.FAIL}[-] Missing required option: SIGNATURE{Colors.ENDC}"
            
            success, msg = ModernCrypto.falcon_verify(pub_key_path, data_bytes, signature, algorithm)
            if success:
                return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}"
            else:
                return f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"
            
        else:
            return f"{Colors.FAIL}[-] Unknown action: {action}{Colors.ENDC}"