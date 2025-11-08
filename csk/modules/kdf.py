"""
All KDF and Password Hashing modules
"""
from .base import CryptoModule
from ..utils import Colors
from ..engine import KDFTools

class BcryptModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "kdf/bcrypt_hash"
        self.description = "Hash a password using bcrypt"
        self.detailed_description = """
bcrypt is a password hashing function designed to be slow and computationally intensive, which protects against brute-force attacks.

[+] How it works:
It uses a variant of the Blowfish cipher and an adaptive "cost" factor (rounds). A higher 'ROUNDS' value makes the hashing slower and more resistant to attacks.
It automatically generates and includes a salt within the final hash string.

[+] Usage:
- `bcrypt_hash`: Creates a new hash from a password.
- `bcrypt_verify`: Compares a plaintext password against an existing hash.

[+] Security:
bcrypt is a strong, industry-standard choice for password storage.
"""
        self.options = {
            'PASSWORD': {'value': '', 'description': 'Password to hash'},
            'ROUNDS': {'value': '12', 'description': 'Cost factor (rounds). 12 is a good default.'},
        }
        self.required_options = ['PASSWORD']

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"

        password = self.options['PASSWORD']['value']
        try:
            rounds = int(self.options['ROUNDS']['value'])
        except ValueError:
            return f"{Colors.FAIL}[-] ERROR: ROUNDS must be an integer.{Colors.ENDC}"
        
        result = KDFTools.bcrypt_hash(password, rounds)
        if result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {result}{Colors.ENDC}"
        return f"{Colors.OKGREEN}[+] Bcrypt Hash:{Colors.ENDC} {result}"

class BcryptVerifyModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "kdf/bcrypt_verify"
        self.description = "Verify a password against a bcrypt hash"
        self.detailed_description = "See 'info bcrypt_hash' for more details on bcrypt."
        self.options = {
            'PASSWORD': {'value': '', 'description': 'Password to check'},
            'HASH': {'value': '', 'description': 'The bcrypt hash to check against'},
        }
        self.required_options = ['PASSWORD', 'HASH']

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"

        password = self.options['PASSWORD']['value']
        hash_to_check = self.options['HASH']['value']
        
        success, message = KDFTools.bcrypt_verify(password, hash_to_check)
        if success:
            return f"{Colors.OKGREEN}[+] {message}{Colors.ENDC}"
        else:
            return f"{Colors.FAIL}[-] {message}{Colors.ENDC}"

class ScryptHashModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "kdf/scrypt_hash"
        self.description = "Hash a password using scrypt"
        self.detailed_description = """
scrypt is a password-based key derivation function (KDF) that is designed to be even more secure against hardware brute-force attacks than bcrypt.

[+] How it works:
It is "memory-hard," meaning it requires a large amount of RAM to compute, which makes it very expensive to parallelize on specialized hardware like FPGAs or ASICs.

[+] Usage:
- `scrypt_hash`: Creates a new hash from a password.
- `scrypt_verify`: Compares a plaintext password against an existing hash.

[+] Security:
scrypt is considered one of the strongest password hashing functions available.
"""
        self.options = {
            'PASSWORD': {'value': '', 'description': 'Password to hash'},
        }
        self.required_options = ['PASSWORD']

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"

        password = self.options['PASSWORD']['value']
        
        result = KDFTools.scrypt_hash(password)
        if result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {result}{Colors.ENDC}"
        return f"{Colors.OKGREEN}[+] scrypt Hash:{Colors.ENDC} {result}"

class ScryptVerifyModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "kdf/scrypt_verify"
        self.description = "Verify a password against an scrypt hash"
        self.detailed_description = "See 'info scrypt_hash' for more details on scrypt."
        self.options = {
            'PASSWORD': {'value': '', 'description': 'Password to check'},
            'HASH': {'value': '', 'description': 'The scrypt hash (in hex) to check against'},
        }
        self.required_options = ['PASSWORD', 'HASH']

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"

        password = self.options['PASSWORD']['value']
        hash_to_check = self.options['HASH']['value']

        success, message = KDFTools.scrypt_verify(password, hash_to_check)
        if success:
            return f"{Colors.OKGREEN}[+] {message}{Colors.ENDC}"
        else:
            return f"{Colors.FAIL}[-] {message}{Colors.ENDC}"

class Argon2HashModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "kdf/argon2_hash"
        self.description = "Hash a password using Argon2 (modern standard)"
        self.detailed_description = """
Argon2 is a password hashing function that won the Password Hashing Competition (PHC) in 2015.
It is designed to resist both brute-force attacks and side-channel attacks.

[+] How it works:
Argon2 is highly configurable, allowing adjustment of memory usage, iteration count, and parallelism,
making it adaptable to various threat models and hardware environments. It is memory-hard and CPU-hard.

[+] Usage:
- `argon2_hash`: Creates a new hash from a password.
- `argon2_verify`: Compares a plaintext password against an existing hash.

[+] Security:
Argon2 is currently considered the strongest password hashing algorithm and is recommended for all new applications.
"""
        self.options = {
            'PASSWORD': {'value': '', 'description': 'Password to hash'},
        }
        self.required_options = ['PASSWORD']

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"

        password = self.options['PASSWORD']['value']
        
        result = KDFTools.argon2_hash(password)
        if result.startswith("ERROR:"):
            return f"{Colors.FAIL}[-] {result}{Colors.ENDC}"
        return f"{Colors.OKGREEN}[+] Argon2 Hash:{Colors.ENDC} {result}"


class Argon2VerifyModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "kdf/argon2_verify"
        self.description = "Verify a password against an Argon2 hash"
        self.detailed_description = "See 'info argon2_hash' for more details on Argon2."
        self.options = {
            'PASSWORD': {'value': '', 'description': 'Password to check'},
            'HASH': {'value': '', 'description': 'The Argon2 hash to check against'},
        }
        self.required_options = ['PASSWORD', 'HASH']

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"

        password = self.options['PASSWORD']['value']
        hash_to_check = self.options['HASH']['value']
        
        success, message = KDFTools.argon2_verify(password, hash_to_check)
        if success:
            return f"{Colors.OKGREEN}[+] {message}{Colors.ENDC}"
        else:
            return f"{Colors.FAIL}[-] {message}{Colors.ENDC}"

class PBKDF2Module(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "kdf/pbkdf2"
        self.description = "Derive a key from a password using PBKDF2-HMAC-SHA256"
        self.detailed_description = """
PBKDF2 (Password-Based Key Derivation Function 2) is a key derivation function
that applies a pseudorandom function, such as HMAC, to a password or passphrase
along with a salt to produce a derived key.

[+] How it works:
The "iterations" parameter makes it computationally expensive to brute-force the password,
as an attacker would have to perform the same number of iterations for each guess.
A unique salt prevents pre-computation attacks (rainbow tables).

[+] Usage:
Used to securely derive cryptographic keys from passwords, often for symmetric encryption.

[+] Security:
PBKDF2 is a widely used and respected KDF. Ensure a sufficiently high number of iterations
and a unique, random salt for each password.
"""
        self.options = {
            'PASSWORD': {'value': '', 'description': 'Password to derive key from'},
            'SALT': {'value': '', 'description': 'Salt (hex-encoded). If empty, a random one is used.'},
            'ITERATIONS': {'value': '600000', 'description': 'Number of hash rounds (600k is a good 2024 default)'},
            'LENGTH': {'value': '32', 'description': 'Desired key length in bytes (e.g., 32 for AES-256)'},
        }
        self.required_options = ['PASSWORD']

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
        
        password = self.options['PASSWORD']['value']
        salt_hex = self.options['SALT']['value']
        
        try:
            iterations = int(self.options['ITERATIONS']['value'])
            length = int(self.options['LENGTH']['value'])
        except ValueError:
            return f"{Colors.FAIL}[-] ERROR: ITERATIONS and LENGTH must be integers.{Colors.ENDC}"

        key, salt = KDFTools.pbkdf2_derive(password, salt_hex, iterations, length)
        
        if key is None:
            return f"{Colors.FAIL}[-] {salt}{Colors.ENDC}"
            
        return (f"{Colors.OKGREEN}[+] Derived Key:{Colors.ENDC} {key}\n"
                f"{Colors.OKCYAN}[+] Salt (hex):{Colors.ENDC} {salt}\n"
                f"{Colors.OKCYAN}[+] Iterations:{Colors.ENDC} {iterations}")


class HKDFModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "kdf/hkdf"
        self.description = "Derive keys from a master secret using HKDF-SHA256"
        self.detailed_description = """
HKDF (HMAC-based Extract-and-Expand Key Derivation Function) is a key derivation function
specified in RFC 5869. It is used to convert a master secret (Input Keying Material - IKM)
into one or more cryptographically strong secret keys.

[+] How it works:
HKDF operates in two phases:
1.  **Extract**: A pseudorandom key (PRK) is extracted from the IKM and an optional salt.
2.  **Expand**: The PRK is expanded into several cryptographic keys of desired lengths,
    using an optional context-specific information string.

[+] Usage:
Ideal for deriving multiple keys from a single shared secret, ensuring that each derived
key is cryptographically separate and suitable for different purposes (e.g., encryption key,
authentication key).

[+] Security:
HKDF is a cryptographically strong KDF, widely used in protocols like TLS 1.3.
"""
        self.options = {
            'IKM': {'value': '', 'description': 'Input Keying Material (the master secret, in hex)'},
            'SALT': {'value': '', 'description': 'Salt (hex-encoded). If empty, a default is used.'},
            'INFO': {'value': 'my-app-keys', 'description': 'Context-specific info string'},
            'LENGTH': {'value': '32', 'description': 'Desired key length in bytes (e.g., 32 for AES-256)'},
        }
        self.required_options = ['IKM']

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
        
        info = self.options['INFO']['value']
        salt_hex = self.options['SALT']['value']
        
        try:
            ikm_hex = self.options['IKM']['value']
            length = int(self.options['LENGTH']['value'])
        except ValueError:
            return f"{Colors.FAIL}[-] ERROR: IKM must be hex and LENGTH must be an integer.{Colors.ENDC}"

        result = KDFTools.hkdf_derive(ikm_hex, salt_hex, info, length)
        if result.startswith("ERROR:"):
             return f"{Colors.FAIL}[-] {result}{Colors.ENDC}"
            
        return f"{Colors.OKGREEN}[+] Derived Key:{Colors.ENDC} {result}"