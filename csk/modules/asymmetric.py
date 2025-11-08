"""
All Asymmetric Cipher modules
"""
from .base import CryptoModule
from ..utils import Colors
from ..engine import ModernCrypto, CRYPTO_INSTALLED, OQS_INSTALLED

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
except ImportError:
    pass 

class RSAModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "asymmetric/rsa"
        self.description = "RSA (Rivest–Shamir–Adleman) operations"
        self.detailed_description = """
RSA is a public-key cryptosystem that is widely used for secure data transmission.
It relies on the difficulty of factoring the product of two large prime numbers.

This module supports 5 actions:
- genkeys: Creates a new public/private key pair.
- encrypt: Encrypts data with a public key (for confidentiality).
- decrypt: Decrypts data with a private key.
- sign: Creates a digital signature for a message with a private key (for authenticity).
- verify: Verifies a signature using the public key.

NOTE: Private keys can be password-protected. If your key is, set the PASSWORD option.
"""
        self.options = {
            'ACTION': {'value': 'genkeys', 'description': 'Action: genkeys, encrypt, decrypt, sign, verify'},
            'KEY_SIZE': {'value': '2048', 'description': 'Key size in bits (e.g., 2048, 4096)'},
            'PASSWORD': {'value': '', 'description': 'Password for encrypted private keys (optional)'},
            'PUB_KEY': {'value': 'rsa_pub.pem', 'description': 'Path to public key file (IN/OUT)'},
            'PRIV_KEY': {'value': 'rsa_priv.pem', 'description': 'Path to private key file (IN/OUT)'},
            'TEXT': {'value': '', 'description': 'Plaintext message to encrypt/sign'},
            'DATA': {'value': '', 'description': 'Base64 data to decrypt/verify'},
            'SIGNATURE': {'value': '', 'description': 'Base64 signature to verify'},
            'INFILE': {'value': '', 'description': 'Input file (overrides TEXT or DATA)'},
            'OUTFILE': {'value': '', 'description': 'Output file (for keys or results)'}
        }
        self.required_options = ['ACTION']
    
    def run(self) -> str:
        if not CRYPTO_INSTALLED:
            return f"{Colors.FAIL}[-] 'cryptography' library not installed.{Colors.ENDC}"
            
        action = self.options['ACTION']['value'].lower()
        password = self.options['PASSWORD']['value'] or None
        pub_key_path = self.options['PUB_KEY']['value']
        priv_key_path = self.options['PRIV_KEY']['value']

        try:
            if action == 'genkeys':
                key_size = int(self.options['KEY_SIZE']['value'])
                
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=key_size,
                )
                public_key = private_key.public_key()
                
                if password:
                    enc_alg = serialization.BestAvailableEncryption(password.encode())
                else:
                    enc_alg = serialization.NoEncryption()

                with open(priv_key_path, "wb") as f:
                    f.write(private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=enc_alg
                    ))
                
                with open(pub_key_path, "wb") as f:
                    f.write(public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ))
                return (f"{Colors.OKGREEN}[+] Generated {key_size}-bit keys:\n"
                        f"  Private Key: {priv_key_path} {'(Encrypted)' if password else ''}\n"
                        f"  Public Key:  {pub_key_path}{Colors.ENDC}")

            elif action == 'encrypt':
                text, _, err = self._get_input_data()
                if err:
                    return err
                if not pub_key_path:
                    return f"{Colors.FAIL}[-] Missing required option: PUB_KEY{Colors.ENDC}"
                
                raw_result = ModernCrypto.rsa_encrypt(pub_key_path, text)
                if raw_result.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
                return self._write_output_data(raw_result)

            elif action == 'decrypt':
                data, _, err = self._get_data_input()
                if err:
                    return err
                if not priv_key_path:
                    return f"{Colors.FAIL}[-] Missing required option: PRIV_KEY{Colors.ENDC}"
                
                raw_result = ModernCrypto.rsa_decrypt(priv_key_path, data, password)
                if raw_result.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
                return self._write_output_data(raw_result)

            elif action == 'sign':
                message, msg_bytes, err = self._get_input_data(read_as_bytes=True)
                if err:
                    return err
                if not priv_key_path:
                    return f"{Colors.FAIL}[-] Missing required option: PRIV_KEY{Colors.ENDC}"
                
                data_to_sign = msg_bytes if msg_bytes else message.encode()

                raw_result = ModernCrypto.rsa_sign(priv_key_path, data_to_sign, password)
                if raw_result.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
                
                self.options['SIGNATURE']['value'] = raw_result
                return (f"{Colors.OKGREEN}[+] Message signed. Signature (Base64):{Colors.ENDC} {raw_result}\n"
                        f"{Colors.OKCYAN}[*] SIGNATURE option has been updated.{Colors.ENDC}")

            elif action == 'verify':
                message, msg_bytes, err = self._get_input_data(read_as_bytes=True)
                if err:
                    return err
                signature = self.options['SIGNATURE']['value']
                if not pub_key_path:
                    return f"{Colors.FAIL}[-] Missing required option: PUB_KEY{Colors.ENDC}"
                if not signature:
                    return f"{Colors.FAIL}[-] Missing required option: SIGNATURE{Colors.ENDC}"
                
                data_to_verify = msg_bytes if msg_bytes else message.encode()
                
                success, msg = ModernCrypto.rsa_verify(pub_key_path, data_to_verify, signature)
                if success:
                    return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}"
                else:
                    return f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"
                
            else:
                return f"{Colors.FAIL}[-] Unknown action: {action}{Colors.ENDC}"
        
        except Exception as e:
            return f"{Colors.FAIL}[-] ERROR: {str(e)}{Colors.ENDC}"


class DHModule(CryptoModule):
    """Diffie-Hellman Key Exchange Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "asymmetric/dh"
        self.description = "Diffie-Hellman (DH) key exchange"
        self.detailed_description = """
Diffie-Hellman is a key exchange protocol that allows two parties,
each having their own private/public key pair, to establish a shared
secret over an insecure channel.

[+] Workflow:
1.  (One time): One party runs ACTION=genparams to create `dh_params.pem`.
2.  (Both parties): Both parties run ACTION=genkeys (using the same `dh_params.pem`)
    to create their own private and public keys.
3.  (Exchange): Both parties exchange their public key files.
4.  (Derive): Each party runs ACTION=derive, setting PRIV_KEY to their *own*
    private key and PEER_PUB_KEY to the *other's* public key.
    
Both parties will arrive at the exact same shared secret (hex) value.
"""
        self.options = {
            'ACTION': {'value': 'genparams', 'description': 'Action: genparams, genkeys, derive'},
            'KEY_SIZE': {'value': '2048', 'description': 'Key size in bits for parameters (e.g., 2048)'},
            'PARAM_FILE': {'value': 'dh_params.pem', 'description': 'DH parameters file (IN/OUT)'},
            'PRIV_KEY': {'value': 'dh_priv.pem', 'description': 'Your private key file (IN/OUT)'},
            'PEER_PUB_KEY': {'value': 'dh_peer_pub.pem', 'description': 'The other party\'s public key (IN)'},
        }
        self.required_options = ['ACTION']
    
    def run(self) -> str:
        if not CRYPTO_INSTALLED:
            return f"{Colors.FAIL}[-] 'cryptography' library not installed.{Colors.ENDC}"
            
        action = self.options['ACTION']['value'].lower()
        param_file = self.options['PARAM_FILE']['value']
        
        if action == 'genparams':
            try:
                key_size = int(self.options['KEY_SIZE']['value'])
            except ValueError:
                return f"{Colors.FAIL}[-] ERROR: KEY_SIZE must be an integer.{Colors.ENDC}"
            
            success, msg = ModernCrypto.dh_genparams(key_size, param_file)
            return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"
            
        elif action == 'genkeys':
            priv_key = self.options['PRIV_KEY']['value']
            pub_key = 'dh_pub.pem'
            
            success, msg = ModernCrypto.dh_genkeys(param_file, priv_key, pub_key)
            return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"

        elif action == 'derive':
            priv_key = self.options['PRIV_KEY']['value']
            peer_pub_key = self.options['PEER_PUB_KEY']['value']
            
            if not priv_key or not peer_pub_key:
                return f"{Colors.FAIL}[-] ERROR: PRIV_KEY and PEER_PUB_KEY are required for 'derive'.{Colors.ENDC}"
                
            shared_key = ModernCrypto.dh_derive(priv_key, peer_pub_key)
            
            if shared_key.startswith("ERROR:"):
                return f"{Colors.FAIL}[-] {shared_key}{Colors.ENDC}"
            return f"{Colors.OKGREEN}[+] Shared Secret (hex):{Colors.ENDC} {shared_key}"
            
        else:
            return f"{Colors.FAIL}[-] Unknown action: {action}{Colors.ENDC}"


class ECDHModule(CryptoModule):
    """Elliptic Curve Diffie-Hellman Key Exchange Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "asymmetric/ecdh"
        self.description = "Elliptic Curve Diffie-Hellman (ECDH) key exchange"
        self.detailed_description = """
ECDH is a modern key exchange protocol that provides the same security as
DH but with much smaller key sizes, making it faster and more efficient.

[+] Workflow:
1.  (Both parties): Run ACTION=genkeys to create their own private/public keys.
    (Recommended CURVE: SECP384R1)
2.  (Exchange): Both parties exchange their public key files.
3.  (Derive): Each party runs ACTION=derive, setting PRIV_KEY to their *own*
    private key and PEER_PUB_KEY to the *other's* public key.
    
Both parties will arrive at the exact same shared secret (hex) value.
"""
        self.options = {
            'ACTION': {'value': 'genkeys', 'description': 'Action: genkeys, derive'},
            'CURVE': {'value': 'SECP384R1', 'description': 'Elliptic curve (e.g., SECP256R1, SECP384R1)'},
            'PRIV_KEY': {'value': 'ec_priv.pem', 'description': 'Your private key file (IN/OUT)'},
            'PEER_PUB_KEY': {'value': 'ec_peer_pub.pem', 'description': 'The other party\'s public key (IN)'},
        }
        self.required_options = ['ACTION']
    
    def run(self) -> str:
        if not CRYPTO_INSTALLED:
            return f"{Colors.FAIL}[-] 'cryptography' library not installed.{Colors.ENDC}"
            
        action = self.options['ACTION']['value'].lower()
        
        if action == 'genkeys':
            curve = self.options['CURVE']['value']
            priv_key = self.options['PRIV_KEY']['value']
            pub_key = 'ec_pub.pem'
            
            success, msg = ModernCrypto.ecdh_genkeys(curve, priv_key, pub_key)
            return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"

        elif action == 'derive':
            priv_key = self.options['PRIV_KEY']['value']
            peer_pub_key = self.options['PEER_PUB_KEY']['value']
            
            if not priv_key or not peer_pub_key:
                return f"{Colors.FAIL}[-] ERROR: PRIV_KEY and PEER_PUB_KEY are required for 'derive'.{Colors.ENDC}"
                
            shared_key = ModernCrypto.ecdh_derive(priv_key, peer_pub_key)
            
            if shared_key.startswith("ERROR:"):
                return f"{Colors.FAIL}[-] {shared_key}{Colors.ENDC}"
            return f"{Colors.OKGREEN}[+] Shared Secret (hex):{Colors.ENDC} {shared_key}"
            
        else:
            return f"{Colors.FAIL}[-] Unknown action: {action}{Colors.ENDC}"


class ECDSAModule(CryptoModule):
    """Elliptic Curve Digital Signature Algorithm Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "asymmetric/ecdsa"
        self.description = "Elliptic Curve Digital Signature Algorithm (ECDSA)"
        self.detailed_description = """
ECDSA is the elliptic curve equivalent of RSA for digital signatures.
It provides the same level of security as RSA with much smaller keys.

[+] Workflow:
1.  (Signer): Run ACTION=genkeys to create `ecdsa_priv.pem` and `ecdsa_pub.pem`.
2.  (Signer): Give `ecdsa_pub.pem` to the verifier.
3.  (Signer): Run ACTION=sign, setting PRIV_KEY and INFILE (or TEXT) to sign.
    This produces a Base64 signature. Set the SIGNATURE option.
4.  (Verifier): Run ACTION=verify, setting PUB_KEY, INFILE (or TEXT),
    and the SIGNATURE to verify.
"""
        self.options = {
            'ACTION': {'value': 'genkeys', 'description': 'Action: genkeys, sign, verify'},
            'CURVE': {'value': 'SECP384R1', 'description': 'Elliptic curve (e.g., SECP256R1, SECP384R1)'},
            'PUB_KEY': {'value': 'ecdsa_pub.pem', 'description': 'Public key file (IN/OUT)'},
            'PRIV_KEY': {'value': 'ecdsa_priv.pem', 'description': 'Private key file (IN/OUT)'},
            'TEXT': {'value': '', 'description': 'Plaintext message to sign/verify'},
            'INFILE': {'value': '', 'description': 'Input file to sign/verify (overrides TEXT)'},
            'SIGNATURE': {'value': '', 'description': 'Base64 signature to verify (IN)'},
        }
        self.required_options = ['ACTION']
    
    def run(self) -> str:
        if not CRYPTO_INSTALLED:
            return f"{Colors.FAIL}[-] 'cryptography' library not installed.{Colors.ENDC}"
            
        action = self.options['ACTION']['value'].lower()
        pub_key_path = self.options['PUB_KEY']['value']
        priv_key_path = self.options['PRIV_KEY']['value']
        
        if action == 'genkeys':
            curve = self.options['CURVE']['value']
            success, msg = ModernCrypto.ecdsa_genkeys(curve, priv_key_path, pub_key_path)
            return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"

        elif action == 'sign':
            _, data_bytes, err = self._get_input_data(read_as_bytes=True)
            if err:
                return err
            if not priv_key_path:
                return f"{Colors.FAIL}[-] Missing required option: PRIV_KEY{Colors.ENDC}"

            raw_result = ModernCrypto.ecdsa_sign(priv_key_path, data_bytes)
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
            
            success, msg = ModernCrypto.ecdsa_verify(pub_key_path, data_bytes, signature)
            if success:
                return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}"
            else:
                return f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"
            
        else:
            return f"{Colors.FAIL}[-] Unknown action: {action}{Colors.ENDC}"

class EdDSAModule(CryptoModule):
    """EdDSA (Ed25519) Digital Signature Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "asymmetric/eddsa"
        self.description = "EdDSA (Ed25519) Digital Signatures"
        self.detailed_description = """
EdDSA (Edwards-curve Digital Signature Algorithm) is a modern, high-performance
digital signature scheme. This module implements Ed25519.

[+] Workflow:
1.  (Signer): Run ACTION=genkeys to create `eddsa_priv.pem` and `eddsa_pub.pem`.
2.  (Signer): Give `eddsa_pub.pem` to the verifier.
3.  (Signer): Run ACTION=sign, setting PRIV_KEY and INFILE (or TEXT) to sign.
    This produces a Base64 signature. Set the SIGNATURE option.
4.  (Verifier): Run ACTION=verify, setting PUB_KEY, INFILE (or TEXT),
    and the SIGNATURE to verify.
"""
        self.options = {
            'ACTION': {'value': 'genkeys', 'description': 'Action: genkeys, sign, verify'},
            'PUB_KEY': {'value': 'eddsa_pub.pem', 'description': 'Public key file (IN/OUT)'},
            'PRIV_KEY': {'value': 'eddsa_priv.pem', 'description': 'Private key file (IN/OUT)'},
            'TEXT': {'value': '', 'description': 'Plaintext message to sign/verify'},
            'INFILE': {'value': '', 'description': 'Input file to sign/verify (overrides TEXT)'},
            'SIGNATURE': {'value': '', 'description': 'Base64 signature to verify (IN)'},
        }
        self.required_options = ['ACTION']
    
    def run(self) -> str:
        if not CRYPTO_INSTALLED:
            return f"{Colors.FAIL}[-] 'cryptography' library not installed.{Colors.ENDC}"
            
        action = self.options['ACTION']['value'].lower()
        pub_key_path = self.options['PUB_KEY']['value']
        priv_key_path = self.options['PRIV_KEY']['value']
        
        if action == 'genkeys':
            success, msg = ModernCrypto.eddsa_genkeys(priv_key_path, pub_key_path)
            return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"

        elif action == 'sign':
            _, data_bytes, err = self._get_input_data(read_as_bytes=True)
            if err:
                return err
            if not priv_key_path:
                return f"{Colors.FAIL}[-] Missing required option: PRIV_KEY{Colors.ENDC}"

            raw_result = ModernCrypto.eddsa_sign(priv_key_path, data_bytes)
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
            
            success, msg = ModernCrypto.eddsa_verify(pub_key_path, data_bytes, signature)
            if success:
                return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}"
            else:
                return f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"
            
        else:
            return f"{Colors.FAIL}[-] Unknown action: {action}{Colors.ENDC}"

class ElGamalModule(CryptoModule):
    """ElGamal Encryption Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "asymmetric/elgamal"
        self.description = "ElGamal encryption and key generation"
        self.detailed_description = """
ElGamal is an asymmetric key encryption algorithm based on the Diffie-Hellman key exchange.
It can be used for both encryption and digital signatures.

[+] Workflow:
1.  (One time): Run ACTION=genkeys to create `elgamal_priv.pem` and `elgamal_pub.pem`.
2.  (Encryptor): Use the recipient's public key (`elgamal_pub.pem`) to encrypt a message.
3.  (Decryptor): Use their private key (`elgamal_priv.pem`) to decrypt the message.
"""
        self.options = {
            'ACTION': {'value': 'genkeys', 'description': 'Action: genkeys, encrypt, decrypt'},
            'KEY_SIZE': {'value': '2048', 'description': 'Key size in bits (e.g., 1024, 2048)'},
            'PUB_KEY': {'value': 'elgamal_pub.pem', 'description': 'Public key file (IN/OUT)'},
            'PRIV_KEY': {'value': 'elgamal_priv.pem', 'description': 'Private key file (IN/OUT)'},
            'TEXT': {'value': '', 'description': 'Plaintext message to encrypt'},
            'DATA': {'value': '', 'description': 'Base64 ciphertext to decrypt'},
            'INFILE': {'value': '', 'description': 'Input file (overrides TEXT or DATA)'},
            'OUTFILE': {'value': '', 'description': 'Output file (for keys or results)'}
        }
        self.required_options = ['ACTION']
    
    def run(self) -> str:
        if not CRYPTO_INSTALLED:
            return f"{Colors.FAIL}[-] 'cryptography' library not installed.{Colors.ENDC}"
            
        action = self.options['ACTION']['value'].lower()
        pub_key_path = self.options['PUB_KEY']['value']
        priv_key_path = self.options['PRIV_KEY']['value']

        try:
            if action == 'genkeys':
                key_size = int(self.options['KEY_SIZE']['value'])
                success, msg = ModernCrypto.elgamal_genkeys(key_size, priv_key_path, pub_key_path)
                return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"

            elif action == 'encrypt':
                text, _, err = self._get_input_data(read_as_bytes=True)
                if err:
                    return err
                if not pub_key_path:
                    return f"{Colors.FAIL}[-] Missing required option: PUB_KEY{Colors.ENDC}"
                
                raw_result = ModernCrypto.elgamal_encrypt(pub_key_path, text)
                if raw_result.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
                return self._write_output_data(raw_result)

            elif action == 'decrypt':
                data, _, err = self._get_data_input()
                if err:
                    return err
                if not priv_key_path:
                    return f"{Colors.FAIL}[-] Missing required option: PRIV_KEY{Colors.ENDC}"
                
                raw_result = ModernCrypto.elgamal_decrypt(priv_key_path, data)
                if raw_result.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
                return self._write_output_data(raw_result)
                
            else:
                return f"{Colors.FAIL}[-] Unknown action: {action}{Colors.ENDC}"
        
        except Exception as e:
            return f"{Colors.FAIL}[-] ERROR: {str(e)}{Colors.ENDC}"

class KyberModule(CryptoModule):
    """Kyber Key Encapsulation Mechanism (KEM) Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "pqc/kyber"
        self.description = "Kyber Post-Quantum Key Encapsulation Mechanism"
        self.detailed_description = """
Kyber is a post-quantum key encapsulation mechanism (KEM) that is designed
to be secure against attacks from quantum computers. It is a candidate for
standardization by NIST.

[+] Workflow:
1.  (Recipient): Run ACTION=genkeys to create `kyber_priv.bin` and `kyber_pub.bin`.
2.  (Recipient): Give `kyber_pub.bin` to the sender.
3.  (Sender): Run ACTION=encapsulate, setting PUB_KEY to the recipient's
    public key. This produces a ciphertext and a shared secret.
4.  (Recipient): Run ACTION=decapsulate, setting PRIV_KEY to their private
    key and CIPHERTEXT to the ciphertext from the sender.
    
Both parties will arrive at the exact same shared secret (Base64) value.
"""
        self.options = {
            'ACTION': {'value': 'genkeys', 'description': 'Action: genkeys, encapsulate, decapsulate'},
            'ALGORITHM': {'value': 'Kyber768', 'description': 'Kyber algorithm (e.g., Kyber512, Kyber768, Kyber1024)'},
            'PUB_KEY': {'value': 'kyber_pub.bin', 'description': 'Public key file (IN/OUT)'},
            'PRIV_KEY': {'value': 'kyber_priv.bin', 'description': 'Private key file (IN/OUT)'},
            'CIPHERTEXT': {'value': '', 'description': 'Base64 encapsulated ciphertext (IN)'},
            'OUTFILE': {'value': '', 'description': 'Output file (for keys or results)'}
        }
        self.required_options = ['ACTION']
    
    def run(self) -> str:
        if not OQS_INSTALLED:
            return f"{Colors.FAIL}[-] 'liboqs-python' library not installed.{Colors.ENDC}"
            
        action = self.options['ACTION']['value'].lower()
        algorithm = self.options['ALGORITHM']['value']
        pub_key_path = self.options['PUB_KEY']['value']
        priv_key_path = self.options['PRIV_KEY']['value']

        try:
            if action == 'genkeys':
                success, msg = ModernCrypto.kyber_genkeys(priv_key_path, pub_key_path, algorithm)
                return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"

            elif action == 'encapsulate':
                if not pub_key_path:
                    return f"{Colors.FAIL}[-] Missing required option: PUB_KEY{Colors.ENDC}"
                
                ciphertext_b64, shared_secret_b64 = ModernCrypto.kyber_encapsulate(pub_key_path, algorithm)
                if ciphertext_b64.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {ciphertext_b64}{Colors.ENDC}"
                
                self.options['CIPHERTEXT']['value'] = ciphertext_b64
                return (f"{Colors.OKGREEN}[+] Key encapsulated. Ciphertext (Base64):{Colors.ENDC} {ciphertext_b64}\n"
                        f"{Colors.OKGREEN}[+] Shared Secret (Base64):{Colors.ENDC} {shared_secret_b64}\n"
                        f"{Colors.OKCYAN}[*] CIPHERTEXT option has been updated.{Colors.ENDC}")

            elif action == 'decapsulate':
                ciphertext_b64 = self.options['CIPHERTEXT']['value']
                if not priv_key_path:
                    return f"{Colors.FAIL}[-] Missing required option: PRIV_KEY{Colors.ENDC}"
                if not ciphertext_b64:
                    return f"{Colors.FAIL}[-] Missing required option: CIPHERTEXT{Colors.ENDC}"
                
                shared_secret_b64 = ModernCrypto.kyber_decapsulate(priv_key_path, ciphertext_b64, algorithm)
                if shared_secret_b64.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {shared_secret_b64}{Colors.ENDC}"
                return f"{Colors.OKGREEN}[+] Decapsulated Shared Secret (Base64):{Colors.ENDC} {shared_secret_b64}"
                
            else:
                return f"{Colors.FAIL}[-] Unknown action: {action}{Colors.ENDC}"
        
        except Exception as e:
            return f"{Colors.FAIL}[-] ERROR: {str(e)}{Colors.ENDC}"

class DilithiumModule(CryptoModule):
    """Dilithium Post-Quantum Digital Signature Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "pqc/dilithium"
        self.description = "Dilithium Post-Quantum Digital Signatures"
        self.detailed_description = """
Dilithium (ML-DSA) is a post-quantum digital signature scheme designed
to be secure against attacks from quantum computers. It is a candidate for
standardization by NIST.

[+] Workflow:
1.  (Signer): Run ACTION=genkeys to create `dilithium_priv.bin` and `dilithium_pub.bin`.
2.  (Signer): Give `dilithium_pub.bin` to the verifier.
3.  (Signer): Run ACTION=sign, setting PRIV_KEY and INFILE (or TEXT) to sign.
    This produces a Base64 signature. Set the SIGNATURE option.
4.  (Verifier): Run ACTION=verify, setting PUB_KEY, INFILE (or TEXT),
    and the SIGNATURE to verify.
"""