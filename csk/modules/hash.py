"""
All Hashing modules
"""
from .base import CryptoModule
from ..utils import Colors
from ..engine import HashFunctions

class HashModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "hash/digest"
        self.description = "Generate cryptographic hashes"
        self.detailed_description = """
A cryptographic hash function is a one-way function that takes an input (or 'message') and returns a fixed-size string of bytes. The output is called a 'hash' or 'digest'.

[+] Properties:
1.  **Deterministic**: The same message always produces the same hash.
2.  **Pre-image Resistant**: It's infeasible to find the input message from its hash.
3.  **Collision Resistant**: It's infeasible to find two different messages that produce the same hash.

[+] Usage:
This module supports all common hash functions built into Python's `hashlib`, including MD5, SHA-1, SHA-2, SHA-3, and BLAKE2. It will also dynamically include `ripemd160` and `whirlpool` if your system's OpenSSL library provides them.

Set the ALGORITHM option to choose which one to use.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to hash'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'ALGORITHM': {'value': 'sha256', 'description': 'Hash algorithm (md5, sha256, sha512, etc.)'},
        }
        self.required_options = ['ALGORITHM', ('TEXT', 'INFILE')]
    
    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
            
        _, data_bytes, err = self._get_input_data(read_as_bytes=True)
        if err:
            return err
            
        algorithm = self.options['ALGORITHM']['value']

        result = HashFunctions.hash_data(data_bytes, algorithm)
        if result.startswith("ERROR:"):
             return f"{Colors.FAIL}[-] {result}{Colors.ENDC}"
        
        return f"{Colors.OKGREEN}[+] Hash ({algorithm}):{Colors.ENDC} {result}"

class TigerHashModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "hash/tiger"
        self.description = "Generate a hash using the Tiger algorithm"
        self.detailed_description = """
Tiger is a cryptographic hash function designed in 1995. It was intended to be very fast on 64-bit systems.

While not as common as SHA-2, it is used in some peer-to-peer file sharing protocols (e.g., Gnutella) and is part of the TTH (Tiger Tree Hash) merkel-tree structure.

[+] Security:
Some weaknesses have been found in reduced-round versions, but the full 24-round Tiger is still considered generally secure.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to hash'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
        }
        self.required_options = [('TEXT', 'INFILE')]
    
    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
            
        _, data_bytes, err = self._get_input_data(read_as_bytes=True)
        if err:
            return err
        
        result = HashFunctions.tiger_hash(data_bytes)
        if result.startswith("ERROR:"):
             return f"{Colors.FAIL}[-] {result}{Colors.ENDC}"

        return f"{Colors.OKGREEN}[+] Tiger Hash:{Colors.ENDC} {result}"