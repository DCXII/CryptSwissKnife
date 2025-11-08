"""
All Classical Cipher modules
"""
from .base import CryptoModule
from ..utils import Colors
from ..engine import ClassicalCiphers, NUMPY_INSTALLED

class CaesarModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "classical/caesar"
        self.detailed_description = """
The Caesar cipher is one of the simplest and most widely known encryption techniques.
It is a type of substitution cipher in which each letter in the plaintext is
replaced by a letter some fixed number of positions down the alphabet.

[+] Workflow:
1.  Set the TEXT or INFILE option with the message to encrypt/decrypt.
2.  Set the SHIFT value (e.g., 3).
3.  Set MODE to 'encrypt' or 'decrypt'.
4.  Run the module.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'SHIFT': {'value': '3', 'description': 'Shift value (1-25)'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['SHIFT', ('TEXT', 'INFILE')]
    
    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"

        text, _, err = self._get_input_data()
        if err:
             return err

        shift_str = self.options['SHIFT']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        try:
            shift = int(shift_str)
        except ValueError:
            return f"{Colors.FAIL}[-] Invalid SHIFT: Must be an integer.{Colors.ENDC}"
        
        raw_result = ClassicalCiphers.caesar_cipher(text, shift, decrypt)
        return self._write_output_data(raw_result)

class AtbashModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "classical/atbash"
        self.detailed_description = """
The Atbash cipher is a monoalphabetic substitution cipher originally used for the Hebrew alphabet.
It works by substituting the first letter of the alphabet with the last, the second with the second to last, and so on.
It is a reciprocal cipher, meaning the same process is used for both encryption and decryption.

[+] Workflow:
1.  Set the TEXT or INFILE option with the message to encrypt/decrypt.
2.  Run the module.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = [('TEXT', 'INFILE')]

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"

        text, _, err = self._get_input_data()
        if err:
             return err

        raw_result = ClassicalCiphers.atbash_cipher(text)
        return self._write_output_data(raw_result)

class AffineModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "classical/affine"
        self.description = "Affine cipher: E(x) = (ax + b) mod 26"
        self.detailed_description = """
The Affine cipher is a type of monoalphabetic substitution cipher, where each letter in an alphabet
is mapped to its numeric equivalent, encrypted using a simple mathematical function, and converted
back to a letter. The formula used is E(x) = (ax + b) mod m, where 'm' is the size of the alphabet (26 for English).
For decryption, D(y) = a^-1(y - b) mod m, where a^-1 is the modular multiplicative inverse of 'a' modulo 'm'.
The value 'a' must be coprime with 'm'.

[+] Workflow:
1.  Set the TEXT or INFILE option with the message to encrypt/decrypt.
2.  Set the 'A' and 'B' coefficients. 'A' must be coprime with 26.
3.  Set MODE to 'encrypt' or 'decrypt'.
4.  Run the module.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'A': {'value': '5', 'description': 'Coefficient A (must be coprime with 26)'},
            'B': {'value': '8', 'description': 'Coefficient B (the shift)'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['A', 'B', ('TEXT', 'INFILE')]

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"

        text, _, err = self._get_input_data()
        if err:
             return err
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        try:
            a = int(self.options['A']['value'])
            b = int(self.options['B']['value'])
        except ValueError:
            return f"{Colors.FAIL}[-] ERROR: A and B must be integers.{Colors.ENDC}"

        raw_result = ClassicalCiphers.affine_cipher(text, a, b, decrypt)
        if raw_result.startswith("ERROR:"):
             return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
        return self._write_output_data(raw_result)

class ColumnarModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "classical/columnar"
        self.description = "Columnar transposition cipher"
        self.detailed_description = """
The Columnar Transposition cipher is a transposition cipher in which the plaintext is written
horizontally in rows and then read vertically in columns, but the order of the columns is
shuffled according to a keyword.

[+] Workflow:
1.  Set the TEXT or INFILE option with the message to encrypt/decrypt.
2.  Set the KEYword, which determines the order of columns.
3.  Set MODE to 'encrypt' or 'decrypt'.
4.  Run the module.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'KEY': {'value': '', 'description': 'Keyword for transposition'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['KEY', ('TEXT', 'INFILE')]

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
        
        text, _, err = self._get_input_data()
        if err:
             return err
        key = self.options['KEY']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        raw_result = ClassicalCiphers.columnar_transposition(text, key, decrypt)
        return self._write_output_data(raw_result)

class VigenereModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "classical/vigenere"
        self.description = "Vigenère cipher encryption/decryption"
        self.detailed_description = """
The Vigenère cipher is a method of encrypting alphabetic text by using a series of different
Caesar ciphers based on the letters of a keyword. It is a form of polyalphabetic substitution.

[+] Workflow:
1.  Set the TEXT or INFILE option with the message to encrypt/decrypt.
2.  Set the KEYword.
3.  Set MODE to 'encrypt' or 'decrypt'.
4.  Run the module.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'KEY': {'value': '', 'description': 'Encryption key'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['KEY', ('TEXT', 'INFILE')]
    
    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
            
        text, _, err = self._get_input_data()
        if err:
             return err
        key = self.options['KEY']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'

        if not key.isalpha():
            return f"{Colors.FAIL}[-] Invalid KEY: Must be alphabetic characters only.{Colors.ENDC}"
        
        raw_result = ClassicalCiphers.vigenere_cipher(text, key, decrypt)
        return self._write_output_data(raw_result)

class PlayfairModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "classical/playfair"
        self.description = "Playfair cipher - digraph substitution"
        self.detailed_description = """
The Playfair cipher is a manual symmetric encryption technique and was the first literal
digraph substitution cipher. The scheme encrypts pairs of letters (digraphs), instead of
single letters as in the case of simple substitution ciphers.

[+] Workflow:
1.  Set the TEXT or INFILE option with the message to encrypt/decrypt.
2.  Set the KEYword.
3.  Set MODE to 'encrypt' or 'decrypt'.
4.  Run the module.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'KEY': {'value': '', 'description': 'Encryption key (e.g., "MONARCHY")'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['KEY', ('TEXT', 'INFILE')]
    
    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
            
        text, _, err = self._get_input_data()
        if err:
             return err
        key = self.options['KEY']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'
        
        raw_result = ClassicalCiphers.playfair_cipher(text, key, decrypt)
        return self._write_output_data(raw_result)

class RailFenceModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "classical/railfence"
        self.description = "Rail fence cipher - transposition cipher"
        self.detailed_description = """
The Rail Fence cipher is a form of transposition cipher that gets its name from the way
in which the plaintext is written out. In the rail fence cipher, the plaintext is written
downwards and diagonally on successive "rails" of an imaginary fence, then moving up
when the bottom rail is reached, and so on. The message is then read off in rows.

[+] Workflow:
1.  Set the TEXT or INFILE option with the message to encrypt/decrypt.
2.  Set the number of RAILS.
3.  Set MODE to 'encrypt' or 'decrypt'.
4.  Run the module.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'RAILS': {'value': '3', 'description': 'Number of rails (e.g., 3)'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['RAILS', ('TEXT', 'INFILE')]
    
    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
            
        text, _, err = self._get_input_data()
        if err:
             return err
        rails_str = self.options['RAILS']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'
        
        try:
            rails = int(rails_str)
            if rails < 2:
                return f"{Colors.FAIL}[-] Invalid number of rails: Must be 2 or more.{Colors.ENDC}"
        except ValueError:
            return f"{Colors.FAIL}[-] Invalid RAILS value: Must be a number.{Colors.ENDC}"
        
        raw_result = ClassicalCiphers.rail_fence_cipher(text, rails, decrypt)
        return self._write_output_data(raw_result)
        
class MonoalphabeticModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "classical/monoalphabetic"
        self.description = "Monoalphabetic substitution cipher"
        self.detailed_description = "A simple substitution cipher where each letter of the alphabet is mapped to another unique letter. The KEY must be a 26-letter permutation of the alphabet."
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'KEY': {'value': 'QWERTYUIOPASDFGHJKLZXCVBNM', 'description': '26-letter alphabet permutation'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['KEY', ('TEXT', 'INFILE')]

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
        
        text, _, err = self._get_input_data()
        if err:
             return err
        key = self.options['KEY']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'
        
        raw_result = ClassicalCiphers.monoalphabetic_cipher(text, key, decrypt)
        if raw_result.startswith("ERROR:"):
             return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
        return self._write_output_data(raw_result)

class BeaufortModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "classical/beaufort"
        self.description = "Beaufort cipher (reciprocal Vigenere)"
        self.detailed_description = "A polyalphabetic substitution cipher similar to Vigenere, but it is reciprocal, meaning the same algorithm encrypts and decrypts. Formula: C = (k - p) mod 26"
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'KEY': {'value': '', 'description': 'Encryption/decryption key'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['KEY', ('TEXT', 'INFILE')]
    
    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
            
        text, _, err = self._get_input_data()
        if err:
             return err
        key = self.options['KEY']['value']
        
        raw_result = ClassicalCiphers.beaufort_cipher(text, key)
        return self._write_output_data(raw_result)

class AutokeyModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "classical/autokey"
        self.description = "Vigenere Autokey cipher"
        self.detailed_description = "A polyalphabetic cipher where the key is the keyword followed by the plaintext itself. This makes the key as long as the message."
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'KEY': {'value': '', 'description': 'Encryption/decryption key prefix'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['KEY', ('TEXT', 'INFILE')]
    
    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
            
        text, _, err = self._get_input_data()
        if err:
             return err
        key = self.options['KEY']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'
        
        raw_result = ClassicalCiphers.autokey_cipher(text, key, decrypt)
        return self._write_output_data(raw_result)

class HillModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "classical/hill"
        self.description = "Hill cipher (matrix-based)"
        self.detailed_description = "A polygraphic substitution cipher using linear algebra. Requires 'numpy' library. \nKey format: '1 2 3; 4 5 6; 7 8 9' for a 3x3 matrix."
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'KEY_MATRIX': {'value': '5 8; 17 3', 'description': "Square key matrix (e.g., '5 8; 17 3')"},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['KEY_MATRIX', ('TEXT', 'INFILE')]
    
    def run(self) -> str:
        if not NUMPY_INSTALLED:
            return f"{Colors.FAIL}[-] 'numpy' library not installed. Run: pip install numpy{Colors.ENDC}"
            
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
            
        text, _, err = self._get_input_data()
        if err:
             return err
        key_matrix = self.options['KEY_MATRIX']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'
        
        raw_result = ClassicalCiphers.hill_cipher(text, key_matrix, decrypt)
        if raw_result.startswith("ERROR:"):
             return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
        return self._write_output_data(raw_result)

class ScytaleModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "classical/scytale"
        self.description = "Scytale cipher (simple columnar transposition)"
        self.detailed_description = "Simulates an ancient Greek transposition cipher. Functionally identical to a columnar transposition where the key is just 'ABCD...'"
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'RAILS': {'value': '5', 'description': 'Number of rails/columns (diameter of the Scytale)'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['RAILS', ('TEXT', 'INFILE')]
    
    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
            
        text, _, err = self._get_input_data()
        if err:
             return err
        try:
            rails = int(self.options['RAILS']['value'])
        except ValueError:
            return f"{Colors.FAIL}[-] ERROR: RAILS must be an integer.{Colors.ENDC}"
            
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'
        
        raw_result = ClassicalCiphers.scytale_cipher(text, rails, decrypt)
        return self._write_output_data(raw_result)

class ADFGVXModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "classical/adfgvx"
        self.description = "ADFGVX cipher (WWI German cipher)"
        self.detailed_description = "A WWI German field cipher combining a substitution matrix with a columnar transposition. The 36-char MATRIX must contain A-Z and 0-9 (J is mapped to I)."
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'KEY': {'value': 'SECRET', 'description': 'Keyword for transposition'},
            'MATRIX': {'value': 'PH0QG64ME1A5D2N3FOB7R9LCI8KXSUZVWTY', 'description': '36-char substitution matrix (A-Z, 0-9)'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['KEY', 'MATRIX', ('TEXT', 'INFILE')]
    
    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
            
        text, _, err = self._get_input_data()
        if err:
             return err
        key = self.options['KEY']['value']
        matrix = self.options['MATRIX']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'
        
        raw_result = ClassicalCiphers.adfgvx_cipher(text, key, matrix, decrypt)
        if raw_result.startswith("ERROR:"):
             return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
        return self._write_output_data(raw_result)

class DoubleTranspositionModule(CryptoModule):
    def __init__(self):
        super().__init__()
        self.name = "classical/double_transposition"
        self.description = "Double columnar transposition cipher"
        self.detailed_description = """
The Double Columnar Transposition cipher is a more secure variant of the simple columnar
transposition cipher. It involves applying the columnar transposition process twice,
using two different keywords.

[+] Workflow:
1.  Set the TEXT or INFILE option with the message to encrypt/decrypt.
2.  Set KEY1 and KEY2 for the two transpositions.
3.  Set MODE to 'encrypt' or 'decrypt'.
4.  Run the module.
"""
        self.options = {
            'TEXT': {'value': '', 'description': 'Text to encrypt/decrypt'},
            'INFILE': {'value': '', 'description': 'Input file to read from (overrides TEXT)'},
            'KEY1': {'value': 'SECRET', 'description': 'First transposition key'},
            'KEY2': {'value': 'CIPHER', 'description': 'Second transposition key'},
            'MODE': {'value': 'encrypt', 'description': 'Mode: encrypt or decrypt'},
            'OUTFILE': {'value': '', 'description': 'Output file to write result to'}
        }
        self.required_options = ['KEY1', 'KEY2', ('TEXT', 'INFILE')]
    
    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"
            
        text, _, err = self._get_input_data()
        if err:
             return err
        key1 = self.options['KEY1']['value']
        key2 = self.options['KEY2']['value']
        decrypt = self.options['MODE']['value'].lower() == 'decrypt'
        
        raw_result = ClassicalCiphers.double_transposition(text, key1, key2, decrypt)
        return self._write_output_data(raw_result)