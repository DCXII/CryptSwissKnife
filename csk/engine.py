"""
The Cryptographic Engine.
All cipher, hash, and KDF logic lives here.
Modules in 'csk/modules/' will call these functions.
"""

import json
import time
import math
import string
from typing import Optional, Dict, List, Any
import hashlib
import secrets
import base64
import pickle
from .utils import Colors

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding, ec, dh, ed25519
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.types import EllipticCurvePublicKey, EllipticCurvePrivateKey
    from cryptography.exceptions import InvalidSignature
    CRYPTO_INSTALLED = True
except ImportError:
    CRYPTO_INSTALLED = False

try:
    import bcrypt
    BCRYPT_INSTALLED = True
except ImportError:
    BCRYPT_INSTALLED = False

try:
    import scrypt
    SCRYPT_INSTALLED = True
except ImportError:
    SCRYPT_INSTALLED = False

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    ARGON2_INSTALLED = True
except ImportError:
    ARGON2_INSTALLED = False
    
try:
    import tiger
    TIGER_INSTALLED = True
except ImportError:
    TIGER_INSTALLED = False

try:
    import numpy as np
    NUMPY_INSTALLED = True
except ImportError:
    NUMPY_INSTALLED = False
    
try:
    import stegano
    STEGO_INSTALLED = True
except ImportError:
    STEGO_INSTALLED = False

try:
    from Crypto.Cipher import IDEA, ARC2, RC5, RC6, Serpent, Salsa20, GOST
    from Crypto.PublicKey import ElGamal
    from Crypto.Util.Padding import pad, unpad
    PYCRYPTODOME_INSTALLED = True
except ImportError:
    PYCRYPTODOME_INSTALLED = False

SKIPJACK_INSTALLED = True

try:
    import oqs
    OQS_INSTALLED = True
except ImportError:
    OQS_INSTALLED = False

try:
    from phe import paillier
    PHE_INSTALLED = True
except ImportError:
    PHE_INSTALLED = False

try:
    from Pyfhel import Pyfhel
    PYFHEL_INSTALLED = True
except ImportError:
    PYFHEL_INSTALLED = False

try:
    import ascon
    ASCON_INSTALLED = True
except ImportError:
    ASCON_INSTALLED = False

try:
    from speck import SpeckCipher
    SPECK_INSTALLED = True
except ImportError:
    SPECK_INSTALLED = False

try:
    from simon import SimonCipher
    SIMON_INSTALLED = True
except ImportError:
    SIMON_INSTALLED = False

try:
    import gnupg
    GPG_INSTALLED = True
except ImportError:
    GPG_INSTALLED = False

PRESENT_INSTALLED = True

try:
    import ecdsa
    import base58
    WALLET_INSTALLED = True
except ImportError:
    WALLET_INSTALLED = False


class ClassicalCiphers:
    """Classical and historical cipher implementations"""
    
    @staticmethod
    def caesar_cipher(text: str, shift: int, decrypt: bool = False) -> str:
        """Caesar cipher with customizable shift"""
        if decrypt:
            shift = -shift
        result = []
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - base + shift) % 26
                result.append(chr(base + shifted))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def atbash_cipher(text: str) -> str:
        """Atbash cipher - reverses alphabet"""
        result = []
        for char in text:
            if char.isalpha():
                if char.isupper():
                    result.append(chr(ord('Z') - (ord(char) - ord('A'))))
                else:
                    result.append(chr(ord('z') - (ord(char) - ord('a'))))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def affine_cipher(text: str, a: int, b: int, decrypt: bool = False) -> str:
        """Affine cipher: E(x) = (ax + b) mod 26"""
        
        def mod_inverse(a: int, m: int) -> Optional[int]:
            """Find modular inverse of a mod m"""
            if math.gcd(a, m) != 1:
                return None
            for i in range(1, m):
                if (a * i) % m == 1:
                    return i
            return None
            
        result = []
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                x = ord(char) - base
                if decrypt:
                    a_inv = mod_inverse(a, 26)
                    if a_inv is None:
                        return f"ERROR: 'a' ({a}) is not coprime with 26. Decryption is impossible."
                    x = (a_inv * (x - b)) % 26
                else:
                    if mod_inverse(a, 26) is None:
                        return f"ERROR: 'a' ({a}) is not coprime with 26. Encryption will not be reversible."
                    x = (a * x + b) % 26
                result.append(chr(base + x))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def vigenere_cipher(text: str, key: str, decrypt: bool = False) -> str:
        """Vigenère cipher - polyalphabetic substitution"""
        result = []
        key = key.upper()
        key_index = 0
        
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shift = ord(key[key_index % len(key)]) - ord('A')
                if decrypt:
                    shift = -shift
                shifted = (ord(char) - base + shift) % 26
                result.append(chr(base + shifted))
                key_index += 1
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def rail_fence_cipher(text: str, rails: int, decrypt: bool = False) -> str:
        """Rail fence cipher - transposition cipher"""
        if rails < 2:
            return text
            
        if decrypt:
            fence = [['' for _ in range(len(text))] for _ in range(rails)]
            direction = -1
            row, col = 0, 0
            
            for i in range(len(text)):
                if row == 0 or row == rails - 1:
                    direction *= -1
                fence[row][col] = '*'
                col += 1
                row += direction
            
            index = 0
            for i in range(rails):
                for j in range(len(text)):
                    if fence[i][j] == '*' and index < len(text):
                        fence[i][j] = text[index]
                        index += 1
            
            result = []
            row, col = 0, 0
            direction = -1
            for i in range(len(text)):
                if row == 0 or row == rails - 1:
                    direction *= -1
                result.append(fence[row][col])
                col += 1
                row += direction
            return ''.join(result)
        else:
            fence = [[] for _ in range(rails)]
            rail = 0
            direction = 1
            
            for char in text:
                fence[rail].append(char)
                rail += direction
                if rail == 0 or rail == rails - 1:
                    direction *= -1
            
            return ''.join([''.join(rail) for rail in fence])
    
    @staticmethod
    def columnar_transposition(text: str, key: str, decrypt: bool = False) -> str:
        """Columnar transposition cipher"""
        text = text.replace(' ', '')
        key_order = sorted(range(len(key)), key=lambda k: key[k])
        
        if decrypt:
            n_cols = len(key)
            n_rows = len(text) // n_cols
            remainder = len(text) % n_cols
            
            grid = [['' for _ in range(n_cols)] for _ in range(n_rows + (1 if remainder else 0))]
            
            text_index = 0
            for col_index in key_order:
                col_height = n_rows + (1 if col_index < remainder else 0)
                for row in range(col_height):
                    if text_index < len(text):
                        grid[row][col_index] = text[text_index]
                        text_index += 1
            
            return ''.join([''.join(row) for row in grid])
        else:
            while len(text) % len(key) != 0:
                text += 'X'
            
            n_rows = len(text) // len(key)
            grid = [text[i:i+len(key)] for i in range(0, len(text), len(key))]
            
            result = []
            for col_index in key_order:
                for row in grid:
                    result.append(row[col_index])
            
            return ''.join(result)
    
    @staticmethod
    def playfair_cipher(text: str, key: str, decrypt: bool = False) -> str:
        """Playfair cipher - digraph substitution"""
        def create_matrix(key: str) -> List[List[str]]:
            key = key.upper().replace('J', 'I')
            matrix = []
            used = set()
            
            for char in key + 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
                if char not in used and char.isalpha():
                    used.add(char)
                    matrix.append(char)
            
            return [matrix[i:i+5] for i in range(0, 25, 5)]
        
        def find_position(matrix: List[List[str]], char: str) -> tuple:
            for i, row in enumerate(matrix):
                for j, c in enumerate(row):
                    if c == char:
                        return i, j
            return 0, 0
        
        matrix = create_matrix(key)
        text = text.upper().replace('J', 'I').replace(' ', '')
        
        digraphs = []
        i = 0
        while i < len(text):
            a = text[i]
            b = text[i+1] if i+1 < len(text) else 'X'
            if a == b:
                b = 'X'
                i += 1
            else:
                i += 2
            digraphs.append((a, b))
        
        result = []
        for a, b in digraphs:
            row1, col1 = find_position(matrix, a)
            row2, col2 = find_position(matrix, b)
            
            if row1 == row2:
                if decrypt:
                    result.append(matrix[row1][(col1 - 1) % 5])
                    result.append(matrix[row2][(col2 - 1) % 5])
                else:
                    result.append(matrix[row1][(col1 + 1) % 5])
                    result.append(matrix[row2][(col2 + 1) % 5])
            elif col1 == col2:
                if decrypt:
                    result.append(matrix[(row1 - 1) % 5][col1])
                    result.append(matrix[(row2 - 1) % 5][col2])
                else:
                    result.append(matrix[(row1 + 1) % 5][col1])
                    result.append(matrix[(row2 + 1) % 5][col2])
            else:
                result.append(matrix[row1][col2])
                result.append(matrix[row2][col1])
        
        return ''.join(result)

    @staticmethod
    def monoalphabetic_cipher(text: str, key: str, decrypt: bool = False) -> str:
        """Monoalphabetic substitution cipher"""
        alphabet = string.ascii_uppercase
        key = key.upper()

        if len(key) != 26 or len(set(key)) != 26:
            return "ERROR: Key must be a 26-letter permutation of the alphabet."

        mapping = {alphabet[i]: key[i] for i in range(26)}
        if decrypt:
            mapping = {v: k for k, v in mapping.items()}

        result = []
        for char in text:
            if char.isalpha():
                if char.isupper():
                    result.append(mapping[char])
                else:
                    result.append(mapping[char.upper()].lower())
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def beaufort_cipher(text: str, key: str) -> str:
        """Beaufort cipher (reciprocal Vigenere)"""
        result = []
        key = key.upper()
        key_index = 0

        for char in text:
            if char.isalpha():
                key_char = key[key_index % len(key)]
                
                if char.isupper():
                    encrypted_char_code = (ord(key_char) - ord('A') - (ord(char) - ord('A'))) % 26
                    result.append(chr(encrypted_char_code + ord('A')))
                else:
                    encrypted_char_code = (ord(key_char) - ord('A') - (ord(char) - ord('a'))) % 26
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def autokey_cipher(text: str, key: str, decrypt: bool = False) -> str:
        """Vigenere Autokey cipher"""
        result = []
        key = key.upper()
        
        if decrypt:
            decrypted_text_so_far = ""
            for i, char in enumerate(text):
                if char.isalpha():
                    key_char = key[i % len(key)] if i < len(key) else decrypted_text_so_far[i - len(key)]
                    
                    base = ord('A') if char.isupper() else ord('a')
                    shift = ord(key_char) - ord('A')
                    
                    shifted = (ord(char) - base - shift) % 26
                    decrypted_char = chr(base + shifted)
                    decrypted_text_so_far += decrypted_char.upper() if char.isupper() else decrypted_char.lower()
                    result.append(decrypted_char)
                else:
                    result.append(char)
                    decrypted_text_so_far += char
            return ''.join(result)
        else:
            full_key = key
            text_upper = "".join(filter(str.isalpha, text)).upper()
            full_key += text_upper[:len(text_upper) - len(key)]
            
            key_index = 0
            for char in text:
                if char.isalpha():
                    base = ord('A') if char.isupper() else ord('a')
                    shift = ord(full_key[key_index % len(full_key)]) - ord('A')
                    shifted = (ord(char) - base + shift) % 26
                    result.append(chr(base + shifted))
                    key_index += 1
                else:
                    result.append(char)
            return ''.join(result)

    @staticmethod
    def hill_cipher(text: str, key_matrix_str: str, decrypt: bool = False) -> str:
        """Hill cipher (matrix-based)"""
        if not NUMPY_INSTALLED:
            return "ERROR: 'numpy' library not installed."

        text = "".join(filter(str.isalpha, text)).upper()
        
        try:
            key_matrix = np.array([[int(n) for n in row.split()] for row in key_matrix_str.split(';')])
            if key_matrix.shape[0] != key_matrix.shape[1]:
                return "ERROR: Key matrix must be square."
        except Exception:
            return "ERROR: Invalid key matrix format. Use '1 2; 3 4'."

        matrix_size = key_matrix.shape[0]
        
        if len(text) % matrix_size != 0:
            text += 'X' * (matrix_size - (len(text) % matrix_size))

        text_nums = [ord(char) - ord('A') for char in text]

        result_nums = []
        for i in range(0, len(text_nums), matrix_size):
            block = np.array(text_nums[i:i+matrix_size])
            
            if decrypt:
                try:
                    det = round(np.linalg.det(key_matrix))
                    det_inv = pow(det, -1, 26)
                    adjugate = np.round(det * np.linalg.inv(key_matrix)).astype(int) % 26
                    inv_key_matrix = (det_inv * adjugate) % 26
                    
                    cipher_block = np.dot(inv_key_matrix, block) % 26
                except np.linalg.LinAlgError:
                    return "ERROR: Key matrix is singular (determinant is 0 mod 26). Cannot decrypt."
                except ValueError:
                    return "ERROR: Key matrix determinant has no modular inverse (not coprime with 26). Cannot decrypt."
            else:
                cipher_block = np.dot(key_matrix, block) % 26
            
            result_nums.extend(cipher_block)
        
        result = [chr(num + ord('A')) for num in result_nums]
        return ''.join(result)

    @staticmethod
    def scytale_cipher(text: str, rails: int, decrypt: bool = False) -> str:
        """Scytale cipher (simple columnar transposition)"""
        
        if decrypt:
            num_cols = math.ceil(len(text) / rails)
            num_rows = rails
            num_shaded_cells = (num_cols * num_rows) - len(text)
            
            grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]
            
            k = 0
            for col in range(num_cols):
                for row in range(num_rows):
                    if not (col == num_cols - 1 and row >= num_rows - num_shaded_cells):
                        grid[row][col] = text[k]
                        k += 1
            
            result = []
            for row in range(num_rows):
                for col in range(num_cols):
                    if grid[row][col] != '':
                        result.append(grid[row][col])
            return ''.join(result)
        else:
            result = [''] * len(text)
            k = 0
            for row in range(rails):
                for i in range(row, len(text), rails):
                    result[i] = text[k]
                    k += 1
            return ''.join(result)

    @staticmethod
    def adfgvx_cipher(text: str, key: str, matrix: str, decrypt: bool = False) -> str:
        """ADFGVX cipher"""
        polybius_square = {}
        reverse_polybius_square = {}
        coords = ['A', 'D', 'F', 'G', 'V', 'X']
        
        if len(matrix) != 36 or len(set(matrix)) != 36:
            return "ERROR: Polybius matrix must be 36 unique characters (A-Z, 0-9)."

        k = 0
        for r in coords:
            for c in coords:
                polybius_square[matrix[k].upper()] = r + c
                reverse_polybius_square[r + c] = matrix[k].upper()
                k += 1

        text = "".join(filter(str.isalnum, text)).upper().replace('J', 'I')

        if not decrypt:
            substituted_text = ""
            for char in text:
                if char in polybius_square:
                    substituted_text += polybius_square[char]
                else:
                    return f"ERROR: Character '{char}' not in Polybius square (A-Z, 0-9)."

            key_order = sorted(range(len(key)), key=lambda k_idx: key[k_idx])
            num_cols = len(key)
            num_rows = math.ceil(len(substituted_text) / num_cols)
            
            grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]
            
            k = 0
            for r in range(num_rows):
                for c in range(num_cols):
                    if k < len(substituted_text):
                        grid[r][c] = substituted_text[k]
                        k += 1
            
            cipher_text = ""
            for col_idx in key_order:
                for r in range(num_rows):
                    cipher_text += grid[r][col_idx]
            return cipher_text
        else:
            num_cols = len(key)
            num_rows = math.ceil(len(text) / num_cols)
            
            grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]
            
            key_order = sorted(range(len(key)), key=lambda k_idx: key[k_idx])
            
            text_idx = 0
            for original_col_idx in key_order:
                for r in range(num_rows):
                    if text_idx < len(text):
                        grid[r][original_col_idx] = text[text_idx]
                        text_idx += 1
            
            transposed_text = ""
            for r in range(num_rows):
                for c in range(num_cols):
                    transposed_text += grid[r][c]
            
            decrypted_text = ""
            for i in range(0, len(transposed_text), 2):
                pair = transposed_text[i:i+2]
                if pair in reverse_polybius_square:
                    decrypted_text += reverse_polybius_square[pair]
                else:
                    return f"ERROR: Invalid pair '{pair}' in ciphertext for reverse substitution."
            return decrypted_text

    @staticmethod
    def double_transposition(text: str, key1: str, key2: str, decrypt: bool = False) -> str:
        """Double columnar transposition cipher"""
        if decrypt:
            intermediate_text = ClassicalCiphers.columnar_transposition(text, key2, decrypt=True)
            final_text = ClassicalCiphers.columnar_transposition(intermediate_text, key1, decrypt=True)
            return final_text
        else:
            intermediate_text = ClassicalCiphers.columnar_transposition(text, key1, decrypt=False)
            final_text = ClassicalCiphers.columnar_transposition(intermediate_text, key2, decrypt=False)
            return final_text

class ModernCrypto:
    """Modern symmetric and asymmetric encryption"""
    
    
    @staticmethod
    def rsa_encrypt(public_key_path: str, plaintext: bytes) -> str:
        if not CRYPTO_INSTALLED:
            return "ERROR: 'cryptography' library not installed."
        try:
            with open(public_key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    password=None
                )
            
            ciphertext = public_key.encrypt(
                plaintext,
                rsa_padding.OAEP(
                    mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(ciphertext).decode()
        except FileNotFoundError:
            return f"ERROR: Public key file not found: {public_key_path}"
        except Exception as e:
            return f"ERROR: Encryption failed: {e}"

    @staticmethod
    def rsa_decrypt(private_key_path: str, ciphertext_b64: str, password: Optional[str]) -> str:
        if not CRYPTO_INSTALLED:
            return "ERROR: 'cryptography' library not installed."
        try:
            with open(private_key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=password.encode() if password else None
                )
            
            ciphertext = base64.b64decode(ciphertext_b64)
            
            plaintext = private_key.decrypt(
                ciphertext,
                rsa_padding.OAEP(
                    mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext.decode()
        except FileNotFoundError:
            return f"ERROR: Private key file not found: {private_key_path}"
        except (ValueError, TypeError):
            return "ERROR: Decryption failed. Check password or key."
        except Exception as e:
            return f"ERROR: Decryption failed: {e}"

    @staticmethod
    def rsa_sign(private_key_path: str, message: bytes, password: Optional[str]) -> str:
        if not CRYPTO_INSTALLED:
            return "ERROR: 'cryptography' library not installed."
        try:
            with open(private_key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=password.encode() if password else None
                )
            
            signature = private_key.sign(
                message,
                rsa_padding.PSS(
                    mgf=rsa_padding.MGF1(hashes.SHA256()),
                    salt_length=rsa_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return base64.b64encode(signature).decode()
        except FileNotFoundError:
            return f"ERROR: Private key file not found: {private_key_path}"
        except (ValueError, TypeError):
            return "ERROR: Signing failed. Check password or key."
        except Exception as e:
            return f"ERROR: Signing failed: {e}"

    @staticmethod
    def rsa_verify(public_key_path: str, message: bytes, signature_b64: str) -> (bool, str):
        if not CRYPTO_INSTALLED:
            return False, "ERROR: 'cryptography' library not installed."
        try:
            with open(public_key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    password=None
                )
            
            signature = base64.b64decode(signature_b64)
            
            public_key.verify(
                signature,
                message,
                rsa_padding.PSS(
                    mgf=rsa_padding.MGF1(hashes.SHA256()),
                    salt_length=rsa_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True, "Signature is valid."
        except FileNotFoundError:
            return False, f"ERROR: Public key file not found: {public_key_path}"
        except InvalidSignature:
            return False, "Signature is invalid."
        except Exception as e:
            return False, f"ERROR: Verification failed. Is signature/key correct? {e}"

    @staticmethod
    def idea_encrypt(plaintext: bytes, password: str) -> str:
        if not PYCRYPTODOME_INSTALLED:
            return "ERROR: 'pycryptodome' library not installed."
        try:
            key = hashlib.sha256(password.encode()).digest()[:16]
            iv = secrets.token_bytes(8)
            cipher = IDEA.new(key, IDEA.MODE_CBC, iv)
            padded_data = pad(plaintext, IDEA.block_size)
            ciphertext = cipher.encrypt(padded_data)
            return base64.b64encode(iv + ciphertext).decode()
        except Exception as e:
            return f"ERROR: Encryption failed: {e}"

    @staticmethod
    def idea_decrypt(ciphertext_b64: str, password: str) -> str:
        if not PYCRYPTODOME_INSTALLED:
            return "ERROR: 'pycryptodome' library not installed."
        try:
            data = base64.b64decode(ciphertext_b64)
            iv = data[:8]
            ciphertext = data[8:]
            key = hashlib.sha256(password.encode()).digest()[:16]
            cipher = IDEA.new(key, IDEA.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, IDEA.block_size)
            return plaintext.decode()
        except Exception as e:
            return f"ERROR: Decryption failed: {e}"

    @staticmethod
    def rc2_encrypt(plaintext: bytes, password: str) -> str:
        if not PYCRYPTODOME_INSTALLED:
            return "ERROR: 'pycryptodome' library not installed."
        try:
            key = hashlib.sha256(password.encode()).digest()[:16]
            iv = secrets.token_bytes(8)
            cipher = ARC2.new(key, ARC2.MODE_CBC, iv)
            padded_data = pad(plaintext, ARC2.block_size)
            ciphertext = cipher.encrypt(padded_data)
            return base64.b64encode(iv + ciphertext).decode()
        except Exception as e:
            return f"ERROR: Encryption failed: {e}"

    @staticmethod
    def rc2_decrypt(ciphertext_b64: str, password: str) -> str:
        if not PYCRYPTODOME_INSTALLED:
            return "ERROR: 'pycryptodome' library not installed."
        try:
            data = base64.b64decode(ciphertext_b64)
            iv = data[:8]
            ciphertext = data[8:]
            key = hashlib.sha256(password.encode()).digest()[:16]
            cipher = ARC2.new(key, ARC2.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, ARC2.block_size)
            return plaintext.decode()
        except Exception as e:
            return f"ERROR: Decryption failed: {e}"

    @staticmethod
    def rc5_encrypt(plaintext: bytes, password: str) -> str:
        if not PYCRYPTODOME_INSTALLED:
            return "ERROR: 'pycryptodome' library not installed."
        try:
            key = hashlib.sha256(password.encode()).digest()[:16]
            cipher = RC5.new(key, RC5.MODE_ECB)
            padded_data = pad(plaintext, RC5.block_size)
            ciphertext = cipher.encrypt(padded_data)
            return base64.b64encode(ciphertext).decode()
        except Exception as e:
            return f"ERROR: Encryption failed: {e}"

    @staticmethod
    def rc5_decrypt(ciphertext_b64: str, password: str) -> str:
        if not PYCRYPTODOME_INSTALLED:
            return "ERROR: 'pycryptodome' library not installed."
        try:
            data = base64.b64decode(ciphertext_b64)
            key = hashlib.sha256(password.encode()).digest()[:16]
            cipher = RC5.new(key, RC5.MODE_ECB)
            padded_plaintext = cipher.decrypt(data)
            plaintext = unpad(padded_plaintext, RC5.block_size)
            return plaintext.decode()
        except Exception as e:
            return f"ERROR: Decryption failed: {e}"

    @staticmethod
    def rc6_encrypt(plaintext: bytes, password: str) -> str:
        if not PYCRYPTODOME_INSTALLED:
            return "ERROR: 'pycryptodome' library not installed."
        try:
            key = hashlib.sha256(password.encode()).digest()[:32]
            cipher = RC6.new(key, RC6.MODE_ECB)
            padded_data = pad(plaintext, RC6.block_size)
            ciphertext = cipher.encrypt(padded_data)
            return base64.b64encode(ciphertext).decode()
        except Exception as e:
            return f"ERROR: Encryption failed: {e}"

    @staticmethod
    def rc6_decrypt(ciphertext_b64: str, password: str) -> str:
        if not PYCRYPTODOME_INSTALLED:
            return "ERROR: 'pycryptodome' library not installed."
        try:
            data = base64.b64decode(ciphertext_b64)
            key = hashlib.sha256(password.encode()).digest()[:32]
            cipher = RC6.new(key, RC6.MODE_ECB)
            padded_plaintext = cipher.decrypt(data)
            plaintext = unpad(padded_plaintext, RC6.block_size)
            return plaintext.decode()
        except Exception as e:
            return f"ERROR: Decryption failed: {e}"

    @staticmethod
    def serpent_encrypt(plaintext: bytes, password: str) -> str:
        if not PYCRYPTODOME_INSTALLED:
            return "ERROR: 'pycryptodome' library not installed."
        try:
            key = hashlib.sha256(password.encode()).digest()[:32]
            iv = secrets.token_bytes(16)
            cipher = Serpent.new(key, Serpent.MODE_CBC, iv)
            padded_data = pad(plaintext, Serpent.block_size)
            ciphertext = cipher.encrypt(padded_data)
            return base64.b64encode(iv + ciphertext).decode()
        except Exception as e:
            return f"ERROR: Encryption failed: {e}"

    @staticmethod
    def serpent_decrypt(ciphertext_b64: str, password: str) -> str:
        if not PYCRYPTODOME_INSTALLED:
            return "ERROR: 'pycryptodome' library not installed."
        try:
            data = base64.b64decode(ciphertext_b64)
            iv = data[:16]
            ciphertext = data[16:]
            key = hashlib.sha256(password.encode()).digest()[:32]
            cipher = Serpent.new(key, Serpent.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, Serpent.block_size)
            return plaintext.decode()
        except Exception as e:
            return f"ERROR: Decryption failed: {e}"

    @staticmethod
    def salsa20_encrypt(plaintext: bytes, password: str) -> str:
        if not PYCRYPTODOME_INSTALLED:
            return "ERROR: 'pycryptodome' library not installed."
        try:
            key = hashlib.sha256(password.encode()).digest()[:32]
            cipher = Salsa20.new(key=key)
            ciphertext = cipher.encrypt(plaintext)
            return base64.b64encode(cipher.nonce + ciphertext).decode()
        except Exception as e:
            return f"ERROR: Encryption failed: {e}"

    @staticmethod
    def salsa20_decrypt(ciphertext_b64: str, password: str) -> str:
        if not PYCRYPTODOME_INSTALLED:
            return "ERROR: 'pycryptodome' library not installed."
        try:
            data = base64.b64decode(ciphertext_b64)
            nonce = data[:8]
            ciphertext = data[8:]
            key = hashlib.sha256(password.encode()).digest()[:32]
            cipher = Salsa20.new(key=key, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)
            return plaintext.decode()
        except Exception as e:
            return f"ERROR: Decryption failed: {e}"


    _SKIPJACK_F_TABLE = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
    ]

    @staticmethod
    def _skipjack_g_function(w1: int, w2: int, w3: int, key_byte: int) -> (int, int):
        temp = (w3 ^ key_byte) & 0xFF
        output1 = ModernCrypto._SKIPJACK_F_TABLE[temp] ^ w1
        output2 = ModernCrypto._SKIPJACK_F_TABLE[output1 ^ w2]
        return output1, output2

    @staticmethod
    def _skipjack_rule_a(w1: int, w2: int, w3: int, w4: int, round_num: int, key: bytes) -> (int, int, int, int):
        key_byte = key[(round_num - 1) % len(key)]

        g1, g2 = ModernCrypto._skipjack_g_function(w1, w2, w3, key_byte)

        new_w1 = w4 ^ g2
        new_w2 = w1
        new_w3 = w2
        new_w4 = w3 ^ g1

        return new_w1, new_w2, new_w3, new_w4

    @staticmethod
    def _skipjack_rule_b(w1: int, w2: int, w3: int, w4: int, round_num: int, key: bytes) -> (int, int, int, int):
        key_byte = key[(round_num - 1) % len(key)]

        g1, g2 = ModernCrypto._skipjack_g_function(w1, w2, w3, key_byte)

        new_w1 = w4 ^ g1
        new_w2 = w1
        new_w3 = w2 ^ g2
        new_w4 = w3

        return new_w1, new_w2, new_w3, new_w4

    @staticmethod
    def _skipjack_split_block(block: int) -> (int, int, int, int):
        w1 = (block >> 48) & 0xFFFF
        w2 = (block >> 32) & 0xFFFF
        w3 = (block >> 16) & 0xFFFF
        w4 = block & 0xFFFF
        return w1, w2, w3, w4

    @staticmethod
    def _skipjack_combine_block(w1: int, w2: int, w3: int, w4: int) -> int:
        return (w1 << 48) | (w2 << 32) | (w3 << 16) | w4

    @staticmethod
    def skipjack_encrypt(plaintext: str, key: bytes) -> str:
        try:
            padded_plaintext_bytes = pad(plaintext.encode(), 8)
            plaintext_block = int.from_bytes(padded_plaintext_bytes, 'big')

            w1, w2, w3, w4 = ModernCrypto._skipjack_split_block(plaintext_block)

            for round_num in range(1, 33):
                if (1 <= round_num <= 8) or (17 <= round_num <= 24):
                    w1, w2, w3, w4 = ModernCrypto._skipjack_rule_a(w1, w2, w3, w4, round_num, key)
                else:
                    w1, w2, w3, w4 = ModernCrypto._skipjack_rule_b(w1, w2, w3, w4, round_num, key)

            ciphertext_block = ModernCrypto._skipjack_combine_block(w1, w2, w3, w4)
            return base64.b64encode(ciphertext_block.to_bytes(8, 'big')).decode()
        except Exception as e:
            return f"ERROR: Skipjack encryption failed: {e}"

    @staticmethod
    def skipjack_decrypt(ciphertext_b64: str, key: bytes) -> str:
        return "ERROR: Skipjack decryption is not implemented in this educational version."

    @staticmethod
    def gost_encrypt(plaintext: str, key: bytes) -> str:
        if not PYCRYPTODOME_INSTALLED:
            return "ERROR: 'pycryptodome' library not installed."
        try:
            padded_data = pad(plaintext.encode(), 8)
            cipher = GOST.new(key, GOST.MODE_ECB)
            ciphertext = cipher.encrypt(padded_data)
            return base64.b64encode(ciphertext).decode()
        except Exception as e:
            return f"ERROR: Encryption failed: {e}"

    @staticmethod
    def gost_decrypt(ciphertext_b64: str, key: bytes) -> str:
        if not PYCRYPTODOME_INSTALLED:
            return "ERROR: 'pycryptodome' library not installed."
        try:
            data = base64.b64decode(ciphertext_b64)
            cipher = GOST.new(key, GOST.MODE_ECB)
            padded_plaintext = cipher.decrypt(data)
            plaintext = unpad(padded_plaintext, 8)
            return plaintext.decode()
        except Exception as e:
            return f"ERROR: Decryption failed: {e}"

    @staticmethod
    def ascon_encrypt(plaintext: str, key: bytes, nonce: bytes, associated_data: bytes) -> str:
        if not ASCON_INSTALLED:
            return "ERROR: 'ascon' library not installed."
        try:
            ciphertext_and_tag = ascon.encrypt(key, nonce, associated_data, plaintext.encode(), variant="Ascon-128")
            return base64.b64encode(ciphertext_and_tag).decode()
        except Exception as e:
            return f"ERROR: Encryption failed: {e}"

    @staticmethod
    def ascon_decrypt(ciphertext_b64: str, key: bytes, nonce: bytes, associated_data: bytes) -> str:
        if not ASCON_INSTALLED:
            return "ERROR: 'ascon' library not installed."
        try:
            ciphertext_and_tag = base64.b64decode(ciphertext_b64)
            plaintext = ascon.decrypt(key, nonce, associated_data, ciphertext_and_tag, variant="Ascon-128")
            return plaintext.decode()
        except Exception as e:
            return f"ERROR: Decryption failed: {e}"


    _PRESENT_SBOX = [
        0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
    ]

    _PRESENT_SBOX_INV = [
        0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA
    ]

    @staticmethod
    def _present_apply_sbox(state: int, sbox: list) -> int:
        new_state = 0
        for i in range(16):
            nibble = (state >> (i * 4)) & 0xF
            new_state |= (sbox[nibble] << (i * 4))
        return new_state

    @staticmethod
    def _present_apply_p_layer(state: int) -> int:
        new_state = 0
        for i in range(64):
            if (state >> i) & 1:
                new_state |= (1 << ((i * 4) % 63 + (i // 16) * 4))
        return new_state

    @staticmethod
    def _present_key_schedule(key: bytes) -> list:
        if len(key) == 10:
            K = int.from_bytes(key, 'big')
            round_keys = []
            for i in range(31):
                round_keys.append((K >> 16) & 0xFFFFFFFFFFFFFFFF)
                
                K = ((K & ((1 << 80) - 1)) << 61) | (K >> (80 - 61))
                
                leftmost_nibble = (K >> 76) & 0xF
                K = (K & ~((0xF) << 76)) | (ModernCrypto._PRESENT_SBOX[leftmost_nibble] << 76)
                
                K ^= (i + 1) << 15
            return round_keys
        elif len(key) == 16:
            return [0] * 31
        else:
            raise ValueError("Invalid key length for PRESENT. Must be 10 or 16 bytes.")

    @staticmethod
    def present_encrypt(plaintext: str, key: bytes) -> str:
        try:
            padded_plaintext_bytes = pad(plaintext.encode(), 8)
            state = int.from_bytes(padded_plaintext_bytes, 'big')

            round_keys = ModernCrypto._present_key_schedule(key)

            for i in range(31):
                state ^= round_keys[i]
                state = ModernCrypto._present_apply_sbox(state, ModernCrypto._PRESENT_SBOX)
                state = ModernCrypto._present_apply_p_layer(state)
            
            state ^= round_keys[30]

            return base64.b64encode(state.to_bytes(8, 'big')).decode()
        except Exception as e:
            return f"ERROR: PRESENT encryption failed: {e}"

    @staticmethod
    def present_decrypt(ciphertext_b64: str, key: bytes) -> str:
        try:
            state = int.from_bytes(base64.b64decode(ciphertext_b64), 'big')
            round_keys = ModernCrypto._present_key_schedule(key)

            state ^= round_keys[30]

            for i in range(30, -1, -1):
                state = ModernCrypto._present_apply_p_layer(state)
                state = ModernCrypto._present_apply_sbox(state, ModernCrypto._PRESENT_SBOX_INV)
                state ^= round_keys[i]
            
            plaintext_bytes = unpad(state.to_bytes(8, 'big'), 8)
            return plaintext_bytes.decode()
        except Exception as e:
            return f"ERROR: PRESENT decryption failed: {e}"

    @staticmethod
    def speck_encrypt(plaintext: str, key_int: int) -> str:
        if not SPECK_INSTALLED:
            return "ERROR: 'simonspeckciphers' library not installed."
        try:
            padded_plaintext_bytes = pad(plaintext.encode(), 8)
            plaintext_int = int.from_bytes(padded_plaintext_bytes, 'big')

            cipher = SpeckCipher(key_int)
            ciphertext_int = cipher.encrypt(plaintext_int)
            
            return base64.b64encode(ciphertext_int.to_bytes(8, 'big')).decode()
        except Exception as e:
            return f"ERROR: Speck encryption failed: {e}"

    @staticmethod
    def speck_decrypt(ciphertext_b64: str, key_int: int) -> str:
        if not SPECK_INSTALLED:
            return "ERROR: 'simonspeckciphers' library not installed."
        try:
            ciphertext_bytes = base64.b64decode(ciphertext_b64)
            ciphertext_int = int.from_bytes(ciphertext_bytes, 'big')

            cipher = SpeckCipher(key_int)
            plaintext_int = cipher.decrypt(ciphertext_int)
            
            plaintext_bytes = unpad(plaintext_int.to_bytes(8, 'big'), 8)
            return plaintext_bytes.decode()
        except Exception as e:
            return f"ERROR: Speck decryption failed: {e}"

    @staticmethod
    def simon_encrypt(plaintext: str, key_int: int) -> str:
        if not SIMON_INSTALLED:
            return "ERROR: 'simonspeckciphers' library not installed."
        try:
            padded_plaintext_bytes = pad(plaintext.encode(), 8)
            plaintext_int = int.from_bytes(padded_plaintext_bytes, 'big')

            cipher = SimonCipher(key_int)
            ciphertext_int = cipher.encrypt(plaintext_int)
            
            return base64.b64encode(ciphertext_int.to_bytes(8, 'big')).decode()
        except Exception as e:
            return f"ERROR: Simon encryption failed: {e}"

    @staticmethod
    def simon_decrypt(ciphertext_b64: str, key_int: int) -> str:
        if not SIMON_INSTALLED:
            return "ERROR: 'simonspeckciphers' library not installed."
        try:
            ciphertext_bytes = base64.b64decode(ciphertext_b64)
            ciphertext_int = int.from_bytes(ciphertext_bytes, 'big')

            cipher = SimonCipher(key_int)
            plaintext_int = cipher.decrypt(ciphertext_int)
            
            plaintext_bytes = unpad(plaintext_int.to_bytes(8, 'big'), 8)
            return plaintext_bytes.decode()
        except Exception as e:
            return f"ERROR: Simon decryption failed: {e}"

    @staticmethod
    def _get_gpg_instance():
        import tempfile
        temp_dir = tempfile.mkdtemp()
        gpg = gnupg.GPG(gnupghome=temp_dir)
        gpg.encoding = 'utf-8'
        return gpg, temp_dir

    @staticmethod
    def pgp_genkeys(email: str, passphrase: str) -> (bool, str):
        if not GPG_INSTALLED:
            return False, "ERROR: 'python-gnupg' library not installed or GnuPG not found."
        gpg, temp_dir = ModernCrypto._get_gpg_instance()
        try:
            key_input = gpg.gen_key_input(
                name_email=email,
                passphrase=passphrase,
                key_type="RSA",
                key_length=2048
            )
            key = gpg.gen_key(key_input)
            if key.fingerprint:
                return True, f"PGP key generated. Fingerprint: {key.fingerprint}"
            else:
                return False, f"ERROR: PGP key generation failed: {key.status}"
        except Exception as e:
            return False, f"ERROR: PGP key generation failed: {e}"
        finally:
            import shutil
            shutil.rmtree(temp_dir)

    @staticmethod
    def pgp_import_key(key_data: str) -> (bool, str):
        if not GPG_INSTALLED:
            return False, "ERROR: 'python-gnupg' library not installed or GnuPG not found."
        gpg, temp_dir = ModernCrypto._get_gpg_instance()
        try:
            import_result = gpg.import_keys(key_data)
            if import_result.count > 0:
                return True, f"Successfully imported {import_result.count} key(s)."
            else:
                return False, f"ERROR: Key import failed: {import_result.stderr}"
        except Exception as e:
            return False, f"ERROR: Key import failed: {e}"
        finally:
            import shutil
            shutil.rmtree(temp_dir)

    @staticmethod
    def pgp_encrypt(plaintext: str, recipient_email: str) -> str:
        if not GPG_INSTALLED:
            return "ERROR: 'python-gnupg' library not installed or GnuPG not found."
        gpg, temp_dir = ModernCrypto._get_gpg_instance()
        try:
            encrypted_data = gpg.encrypt(plaintext, recipients=[recipient_email])
            if encrypted_data.ok:
                return str(encrypted_data)
            else:
                return f"ERROR: PGP encryption failed: {encrypted_data.status}"
        except Exception as e:
            return f"ERROR: PGP encryption failed: {e}"
        finally:
            import shutil
            shutil.rmtree(temp_dir)

    @staticmethod
    def pgp_decrypt(ciphertext: str, passphrase: str) -> str:
        if not GPG_INSTALLED:
            return "ERROR: 'python-gnupg' library not installed or GnuPG not found."
        gpg, temp_dir = ModernCrypto._get_gpg_instance()
        try:
            decrypted_data = gpg.decrypt(ciphertext, passphrase=passphrase)
            if decrypted_data.ok:
                return str(decrypted_data)
            else:
                return f"ERROR: PGP decryption failed: {decrypted_data.status}"
        except Exception as e:
            return f"ERROR: PGP decryption failed: {e}"
        finally:
            import shutil
            shutil.rmtree(temp_dir)

    @staticmethod
    def pgp_sign(plaintext: str, key_id: str, passphrase: str) -> str:
        if not GPG_INSTALLED:
            return "ERROR: 'python-gnupg' library not installed or GnuPG not found."
        gpg, temp_dir = ModernCrypto._get_gpg_instance()
        try:
            signed_data = gpg.sign(plaintext, default_key=key_id, passphrase=passphrase)
            if signed_data.ok:
                return str(signed_data)
            else:
                return f"ERROR: PGP signing failed: {signed_data.status}"
        except Exception as e:
            return f"ERROR: PGP signing failed: {e}"
        finally:
            import shutil
            shutil.rmtree(temp_dir)

    @staticmethod
    def pgp_verify(signed_data: str, key_id: str) -> (bool, str):
        if not GPG_INSTALLED:
            return False, "ERROR: 'python-gnupg' library not installed or GnuPG not found."
        gpg, temp_dir = ModernCrypto._get_gpg_instance()
        try:
            verified_data = gpg.verify(signed_data)
            if verified_data.valid:
                return True, f"PGP signature is valid for key ID: {verified_data.fingerprint}"
            else:
                return False, f"PGP signature is invalid: {verified_data.status}"
        except Exception as e:
            return False, f"ERROR: PGP verification failed: {e}"
        finally:
            import shutil
            shutil.rmtree(temp_dir)

    @staticmethod
    def eddsa_genkeys(priv_key_file: str, pub_key_file: str) -> (bool, str):
        if not CRYPTO_INSTALLED:
            return False, "ERROR: 'cryptography' library not installed."
        try:
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()

            with open(priv_key_file, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(pub_key_file, 'wb') as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            return True, f"Ed25519 keys generated and saved:\n  Private: {priv_key_file}\n  Public:  {pub_key_file}"
        except Exception as e:
            return False, f"ERROR: Could not generate keys: {e}"

    @staticmethod
    def eddsa_sign(priv_key_file: str, message: bytes) -> str:
        if not CRYPTO_INSTALLED:
            return "ERROR: 'cryptography' library not installed."
        try:
            with open(priv_key_file, 'rb') as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            
            if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                return "ERROR: Key is not a valid Ed25519 private key."

            signature = private_key.sign(message)
            return base64.b64encode(signature).decode()
        except FileNotFoundError:
            return f"ERROR: Private key file not found: {priv_key_file}"
        except Exception as e:
            return f"ERROR: Signing failed: {e}"

    @staticmethod
    def eddsa_verify(pub_key_file: str, message: bytes, signature_b64: str) -> (bool, str):
        if not CRYPTO_INSTALLED:
            return False, "ERROR: 'cryptography' library not installed."
        try:
            with open(pub_key_file, 'rb') as f:
                public_key = serialization.load_pem_public_key(f.read())
            
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                return False, "ERROR: Key is not a valid Ed25519 public key."

            signature = base64.b64decode(signature_b64)
            public_key.verify(signature, message)
            return True, "Signature is valid."
        except FileNotFoundError:
            return False, f"ERROR: Public key file not found: {pub_key_file}"
        except InvalidSignature:
            return False, "Signature is invalid."
        except Exception as e:
            return False, f"ERROR: Verification failed: {e}"

    @staticmethod
    def elgamal_genkeys(key_size: int, priv_key_file: str, pub_key_file: str) -> (bool, str):
        if not PYCRYPTODOME_INSTALLED:
            return False, "ERROR: 'pycryptodome' library not installed."
        try:
            key = ElGamal.generate(key_size, secrets.randbits)
            
            with open(priv_key_file, 'wb') as f:
                f.write(key.export_key(format='PEM'))
            with open(pub_key_file, 'wb') as f:
                f.write(key.public_key().export_key(format='PEM'))
            return True, f"ElGamal keys ({key_size}-bit) generated and saved:\n  Private: {priv_key_file}\n  Public:  {pub_key_file}"
        except Exception as e:
            return False, f"ERROR: Could not generate keys: {e}"

    @staticmethod
    def elgamal_encrypt(public_key_file: str, plaintext: bytes) -> str:
        if not PYCRYPTODOME_INSTALLED:
            return "ERROR: 'pycryptodome' library not installed."
        try:
            with open(public_key_file, 'rb') as f:
                public_key = ElGamal.import_key(f.read())
            
            ciphertext_components = public_key.encrypt(plaintext, public_key.p - 1)
            
            c1_str = str(ciphertext_components[0])
            c2_str = str(ciphertext_components[1])
            return base64.b64encode(f"{c1_str},{c2_str}".encode()).decode()
        except FileNotFoundError:
            return f"ERROR: Public key file not found: {public_key_file}"
        except Exception as e:
            return f"ERROR: Encryption failed: {e}"

    @staticmethod
    def elgamal_decrypt(private_key_file: str, ciphertext_b64: str) -> str:
        if not PYCRYPTODOME_INSTALLED:
            return "ERROR: 'pycryptodome' library not installed."
        try:
            with open(private_key_file, 'rb') as f:
                private_key = ElGamal.import_key(f.read())
            
            decoded_str = base64.b64decode(ciphertext_b64).decode()
            c1_str, c2_str = decoded_str.split(',')
            ciphertext_components = (int(c1_str), int(c2_str))
            
            plaintext = private_key.decrypt(ciphertext_components)
            return plaintext.decode()
        except FileNotFoundError:
            return f"ERROR: Private key file not found: {private_key_file}"
        except Exception as e:
            return f"ERROR: Decryption failed: {e}"

    @staticmethod
    def kyber_genkeys(priv_key_file: str, pub_key_file: str, algorithm: str = "Kyber768") -> (bool, str):
        if not OQS_INSTALLED:
            return False, "ERROR: 'liboqs-python' library not installed."
        try:
            client_kem = oqs.KeyEncapsulation(algorithm)
            public_key = client_kem.generate_keypair()
            private_key = client_kem.export_secret_key()

            with open(priv_key_file, 'wb') as f:
                f.write(private_key)
            with open(pub_key_file, 'wb') as f:
                f.write(public_key)
            return True, f"Kyber ({algorithm}) keys generated and saved:\n  Private: {priv_key_file}\n  Public:  {pub_key_file}"
        except Exception as e:
            return False, f"ERROR: Could not generate keys: {e}"

    @staticmethod
    def kyber_encapsulate(public_key_file: str, algorithm: str = "Kyber768") -> (str, str):
        if not OQS_INSTALLED:
            return "ERROR: 'liboqs-python' library not installed.", ""
        try:
            with open(public_key_file, 'rb') as f:
                public_key = f.read()
            
            server_kem = oqs.KeyEncapsulation(algorithm)
            ciphertext, shared_secret = server_kem.encap_secret(public_key)
            
            return base64.b64encode(ciphertext).decode(), base64.b64encode(shared_secret).decode()
        except FileNotFoundError:
            return f"ERROR: Public key file not found: {public_key_file}", ""
        except Exception as e:
            return f"ERROR: Encapsulation failed: {e}", ""

    @staticmethod
    def kyber_decapsulate(private_key_file: str, ciphertext_b64: str, algorithm: str = "Kyber768") -> str:
        if not OQS_INSTALLED:
            return "ERROR: 'liboqs-python' library not installed."
        try:
            with open(private_key_file, 'rb') as f:
                private_key = f.read()
            
            ciphertext = base64.b64decode(ciphertext_b64)
            
            client_kem = oqs.KeyEncapsulation(algorithm)
            client_kem.import_secret_key(private_key)
            shared_secret = client_kem.decap_secret(ciphertext)
            
            return base64.b64encode(shared_secret).decode()
        except FileNotFoundError:
            return f"ERROR: Private key file not found: {private_key_file}"
        except Exception as e:
            return f"ERROR: Decapsulation failed: {e}"

    @staticmethod
    def dilithium_genkeys(priv_key_file: str, pub_key_file: str, algorithm: str = "Dilithium3") -> (bool, str):
        if not OQS_INSTALLED:
            return False, "ERROR: 'liboqs-python' library not installed."
        try:
            signer = oqs.Signature(algorithm)
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()

            with open(priv_key_file, 'wb') as f:
                f.write(private_key)
            with open(pub_key_file, 'wb') as f:
                f.write(public_key)
            return True, f"Dilithium ({algorithm}) keys generated and saved:\n  Private: {priv_key_file}\n  Public:  {pub_key_file}"
        except Exception as e:
            return False, f"ERROR: Could not generate keys: {e}"

    @staticmethod
    def dilithium_sign(priv_key_file: str, message: bytes, algorithm: str = "Dilithium3") -> str:
        if not OQS_INSTALLED:
            return "ERROR: 'liboqs-python' library not installed."
        try:
            with open(priv_key_file, 'rb') as f:
                private_key = f.read()
            
            signer = oqs.Signature(algorithm)
            signer.import_secret_key(private_key)
            signature = signer.sign(message)
            
            return base64.b64encode(signature).decode()
        except FileNotFoundError:
            return f"ERROR: Private key file not found: {priv_key_file}"
        except Exception as e:
            return f"ERROR: Signing failed: {e}"

    @staticmethod
    def dilithium_verify(pub_key_file: str, message: bytes, signature_b64: str, algorithm: str = "Dilithium3") -> (bool, str):
        if not OQS_INSTALLED:
            return False, "ERROR: 'liboqs-python' library not installed."
        try:
            with open(pub_key_file, 'rb') as f:
                public_key = f.read()
            
            signature = base64.b64decode(signature_b64)
            
            verifier = oqs.Signature(algorithm)
            is_valid = verifier.verify(message, signature, public_key)
            
            if is_valid:
                return True, "Signature is valid."
            else:
                return False, "Signature is invalid."
        except FileNotFoundError:
            return False, f"ERROR: Public key file not found: {pub_key_file}"
        except Exception as e:
            return False, f"ERROR: Verification failed: {e}"

    @staticmethod
    def falcon_genkeys(priv_key_file: str, pub_key_file: str, algorithm: str = "Falcon512") -> (bool, str):
        if not OQS_INSTALLED:
            return False, "ERROR: 'liboqs-python' library not installed."
        try:
            signer = oqs.Signature(algorithm)
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()

            with open(priv_key_file, 'wb') as f:
                f.write(private_key)
            with open(pub_key_file, 'wb') as f:
                f.write(public_key)
            return True, f"Falcon ({algorithm}) keys generated and saved:\n  Private: {priv_key_file}\n  Public:  {pub_key_file}"
        except Exception as e:
            return False, f"ERROR: Could not generate keys: {e}"

    @staticmethod
    def falcon_sign(priv_key_file: str, message: bytes, algorithm: str = "Falcon512") -> str:
        if not OQS_INSTALLED:
            return "ERROR: 'liboqs-python' library not installed."
        try:
            with open(priv_key_file, 'rb') as f:
                private_key = f.read()
            
            signer = oqs.Signature(algorithm)
            signer.import_secret_key(private_key)
            signature = signer.sign(message)
            
            return base64.b64encode(signature).decode()
        except FileNotFoundError:
            return f"ERROR: Private key file not found: {priv_key_file}"
        except Exception as e:
            return f"ERROR: Signing failed: {e}"

    @staticmethod
    def falcon_verify(pub_key_file: str, message: bytes, signature_b64: str, algorithm: str = "Falcon512") -> (bool, str):
        if not OQS_INSTALLED:
            return False, "ERROR: 'liboqs-python' library not installed."
        try:
            with open(pub_key_file, 'rb') as f:
                public_key = f.read()
            
            signature = base64.b64decode(signature_b64)
            
            verifier = oqs.Signature(algorithm)
            is_valid = verifier.verify(message, signature, public_key)
            
            if is_valid:
                return True, "Signature is valid."
            else:
                return False, "Signature is invalid."
        except FileNotFoundError:
            return False, f"ERROR: Public key file not found: {pub_key_file}"
        except Exception as e:
            return False, f"ERROR: Verification failed: {e}"

    @staticmethod
    def sphincs_genkeys(priv_key_file: str, pub_key_file: str, algorithm: str = "SPHINCS+-SHA2-128f-simple") -> (bool, str):
        if not OQS_INSTALLED:
            return False, "ERROR: 'liboqs-python' library not installed."
        try:
            signer = oqs.Signature(algorithm)
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()

            with open(priv_key_file, 'wb') as f:
                f.write(private_key)
            with open(pub_key_file, 'wb') as f:
                f.write(public_key)
            return True, f"SPHINCS+ ({algorithm}) keys generated and saved:\n  Private: {priv_key_file}\n  Public:  {pub_key_file}"
        except Exception as e:
            return False, f"ERROR: Could not generate keys: {e}"

    @staticmethod
    def sphincs_sign(priv_key_file: str, message: bytes, algorithm: str = "SPHINCS+-SHA2-128f-simple") -> str:
        if not OQS_INSTALLED:
            return "ERROR: 'liboqs-python' library not installed."
        try:
            with open(priv_key_file, 'rb') as f:
                private_key = f.read()
            
            signer = oqs.Signature(algorithm)
            signer.import_secret_key(private_key)
            signature = signer.sign(message)
            
            return base64.b64encode(signature).decode()
        except FileNotFoundError:
            return f"ERROR: Private key file not found: {priv_key_file}"
        except Exception as e:
            return f"ERROR: Signing failed: {e}"

    @staticmethod
    def sphincs_verify(pub_key_file: str, message: bytes, signature_b64: str, algorithm: str = "SPHINCS+-SHA2-128f-simple") -> (bool, str):
        if not OQS_INSTALLED:
            return False, "ERROR: 'liboqs-python' library not installed."
        try:
            with open(pub_key_file, 'rb') as f:
                public_key = f.read()
            
            signature = base64.b64decode(signature_b64)
            
            verifier = oqs.Signature(algorithm)
            is_valid = verifier.verify(message, signature, public_key)
            
            if is_valid:
                return True, "Signature is valid."
            else:
                return False, "Signature is invalid."
        except FileNotFoundError:
            return False, f"ERROR: Public key file not found: {pub_key_file}"
        except Exception as e:
            return False, f"ERROR: Verification failed: {e}"

    @staticmethod
    def paillier_genkeys(priv_key_file: str, pub_key_file: str, n_length: int = 2048) -> (bool, str):
        if not PHE_INSTALLED:
            return False, "ERROR: 'phe' library not installed."
        try:
            public_key, private_key = paillier.generate_paillier_keypair(n_length=n_length)
            
            with open(pub_key_file, 'wb') as f:
                pickle.dump(public_key, f)
            with open(priv_key_file, 'wb') as f:
                pickle.dump(private_key, f)
            return True, f"Paillier keys ({n_length}-bit) generated and saved:\n  Private: {priv_key_file}\n  Public:  {pub_key_file}"
        except Exception as e:
            return False, f"ERROR: Could not generate keys: {e}"

    @staticmethod
    def paillier_encrypt(public_key_file: str, plaintext: int) -> str:
        if not PHE_INSTALLED:
            return "ERROR: 'phe' library not installed."
        try:
            with open(public_key_file, 'rb') as f:
                public_key = pickle.load(f)
            
            encrypted_number = public_key.encrypt(plaintext)
            return base64.b64encode(pickle.dumps(encrypted_number)).decode()
        except FileNotFoundError:
            return f"ERROR: Public key file not found: {public_key_file}"
        except Exception as e:
            return f"ERROR: Encryption failed: {e}"

    @staticmethod
    def paillier_decrypt(private_key_file: str, ciphertext_b64: str) -> int:
        if not PHE_INSTALLED:
            return "ERROR: 'phe' library not installed."
        try:
            with open(private_key_file, 'rb') as f:
                private_key = pickle.load(f)
            
            encrypted_number = pickle.loads(base64.b64decode(ciphertext_b64))
            decrypted_number = private_key.decrypt(encrypted_number)
            return decrypted_number
        except FileNotFoundError:
            return f"ERROR: Private key file not found: {private_key_file}"
        except Exception as e:
            return f"ERROR: Decryption failed: {e}"

    @staticmethod
    def bfv_genkeys(context_file: str, public_key_file: str, secret_key_file: str) -> (bool, str):
        if not PYFHEL_INSTALLED:
            return False, "ERROR: 'Pyfhel' library not installed."
        try:
            HE = Pyfhel()
            HE.contextGen(p=65537, m=2**13, base=2, flagBatching=True)
            HE.keyGen()
            HE.saveContext(context_file)
            HE.savepublicKey(public_key_file)
            HE.savesecretKey(secret_key_file)
            return True, f"BFV keys generated and saved:\n  Context: {context_file}\n  Public Key: {public_key_file}\n  Secret Key: {secret_key_file}"
        except Exception as e:
            return False, f"ERROR: Could not generate keys: {e}"

    @staticmethod
    def bfv_encrypt(context_file: str, public_key_file: str, plaintext: list) -> str:
        if not PYFHEL_INSTALLED:
            return "ERROR: 'Pyfhel' library not installed."
        try:
            HE = Pyfhel()
            HE.loadContext(context_file)
            HE.loadpublicKey(public_key_file)
            
            ptxt = HE.encodeInt(plaintext)
            ctxt = HE.encrypt(ptxt)
            return base64.b64encode(ctxt.to_bytes()).decode()
        except FileNotFoundError:
            return "ERROR: Key file not found."
        except Exception as e:
            return f"ERROR: Encryption failed: {e}"

    @staticmethod
    def bfv_decrypt(context_file: str, secret_key_file: str, ciphertext_b64: str) -> list:
        if not PYFHEL_INSTALLED:
            return "ERROR: 'Pyfhel' library not installed."
        try:
            HE = Pyfhel()
            HE.loadContext(context_file)
            HE.loadsecretKey(secret_key_file)
            
            ctxt = HE.Ciphertext()
            ctxt.from_bytes(base64.b64decode(ciphertext_b64))
            
            decrypted_ptxt = HE.decrypt(ctxt)
            return decrypted_ptxt.tolist()
        except FileNotFoundError:
            return "ERROR: Key file not found."
        except Exception as e:
            return f"ERROR: Decryption failed: {e}"

    @staticmethod
    def bfv_add(context_file: str, ctxt1_b64: str, ctxt2_b64: str) -> str:
        if not PYFHEL_INSTALLED:
            return "ERROR: 'Pyfhel' library not installed."
        try:
            HE = Pyfhel()
            HE.loadContext(context_file)
            
            ctxt1 = HE.Ciphertext()
            ctxt1.from_bytes(base64.b64decode(ctxt1_b64))
            ctxt2 = HE.Ciphertext()
            ctxt2.from_bytes(base64.b64decode(ctxt2_b64))
            
            ctxt_sum = ctxt1 + ctxt2
            return base64.b64encode(ctxt_sum.to_bytes()).decode()
        except FileNotFoundError:
            return "ERROR: Context file not found."
        except Exception as e:
            return f"ERROR: Addition failed: {e}"

    @staticmethod
    def bfv_mul(context_file: str, ctxt1_b64: str, ctxt2_b64: str) -> str:
        if not PYFHEL_INSTALLED:
            return "ERROR: 'Pyfhel' library not installed."
        try:
            HE = Pyfhel()
            HE.loadContext(context_file)
            
            ctxt1 = HE.Ciphertext()
            ctxt1.from_bytes(base64.b64decode(ctxt1_b64))
            ctxt2 = HE.Ciphertext()
            ctxt2.from_bytes(base64.b64decode(ctxt2_b64))
            
            ctxt_prod = ctxt1 * ctxt2
            return base64.b64encode(ctxt_prod.to_bytes()).decode()
        except FileNotFoundError:
            return "ERROR: Context file not found."
        except Exception as e:
            return f"ERROR: Multiplication failed: {e}"

    @staticmethod
    def ckks_genkeys(context_file: str, public_key_file: str, secret_key_file: str, relin_key_file: str, rotate_key_file: str) -> (bool, str):
        if not PYFHEL_INSTALLED:
            return False, "ERROR: 'Pyfhel' library not installed."
        try:
            HE = Pyfhel()
            HE.contextGen(scheme='CKKS', n=2**14, scale=2**30, qi=[60, 30, 30, 30, 60])
            HE.keyGen()
            HE.relinKeyGen()
            HE.rotateKeyGen()
            HE.saveContext(context_file)
            HE.savepublicKey(public_key_file)
            HE.savesecretKey(secret_key_file)
            HE.saverelinKey(relin_key_file)
            HE.saverotateKey(rotate_key_file)
            return True, f"CKKS keys generated and saved:\n  Context: {context_file}\n  Public Key: {public_key_file}\n  Secret Key: {secret_key_file}\n  Relin Key: {relin_key_file}\n  Rotate Key: {rotate_key_file}"
        except Exception as e:
            return False, f"ERROR: Could not generate keys: {e}"

    @staticmethod
    def ckks_encrypt(context_file: str, public_key_file: str, plaintext: list) -> str:
        if not PYFHEL_INSTALLED:
            return "ERROR: 'Pyfhel' library not installed."
        try:
            HE = Pyfhel()
            HE.loadContext(context_file)
            HE.loadpublicKey(public_key_file)
            
            ptxt = HE.encodeFrac(plaintext)
            ctxt = HE.encrypt(ptxt)
            return base64.b64encode(ctxt.to_bytes()).decode()
        except FileNotFoundError:
            return "ERROR: Key file not found."
        except Exception as e:
            return f"ERROR: Encryption failed: {e}"

    @staticmethod
    def ckks_decrypt(context_file: str, secret_key_file: str, ciphertext_b64: str) -> list:
        if not PYFHEL_INSTALLED:
            return "ERROR: 'Pyfhel' library not installed."
        try:
            HE = Pyfhel()
            HE.loadContext(context_file)
            HE.loadsecretKey(secret_key_file)
            
            ctxt = HE.Ciphertext()
            ctxt.from_bytes(base64.b64decode(ciphertext_b64))
            
            decrypted_ptxt = HE.decryptFrac(ctxt)
            return decrypted_ptxt.tolist()
        except FileNotFoundError:
            return "ERROR: Key file not found."
        except Exception as e:
            return f"ERROR: Decryption failed: {e}"

    @staticmethod
    def ckks_add(context_file: str, ctxt1_b64: str, ctxt2_b64: str) -> str:
        if not PYFHEL_INSTALLED:
            return "ERROR: 'Pyfhel' library not installed."
        try:
            HE = Pyfhel()
            HE.loadContext(context_file)
            
            ctxt1 = HE.Ciphertext()
            ctxt1.from_bytes(base64.b64decode(ctxt1_b64))
            ctxt2 = HE.Ciphertext()
            ctxt2.from_bytes(base64.b64decode(ctxt2_b64))
            
            ctxt_sum = ctxt1 + ctxt2
            return base64.b64encode(ctxt_sum.to_bytes()).decode()
        except FileNotFoundError:
            return "ERROR: Context file not found."
        except Exception as e:
            return f"ERROR: Addition failed: {e}"

    @staticmethod
    def ckks_mul(context_file: str, ctxt1_b64: str, ctxt2_b64: str) -> str:
        if not PYFHEL_INSTALLED:
            return "ERROR: 'Pyfhel' library not installed."
        try:
            HE = Pyfhel()
            HE.loadContext(context_file)
            HE.loadrelinKey(context_file.replace("context.bin", "relin_key.bin"))
            
            ctxt1 = HE.Ciphertext()
            ctxt1.from_bytes(base64.b64decode(ctxt1_b64))
            ctxt2 = HE.Ciphertext()
            ctxt2.from_bytes(base64.b64decode(ctxt2_b64))
            
            ctxt_prod = ctxt1 * ctxt2
            return base64.b64encode(ctxt_prod.to_bytes()).decode()
        except FileNotFoundError:
            return "ERROR: Key file not found."
        except Exception as e:
            return f"ERROR: Multiplication failed: {e}"

    @staticmethod
    def ckks_rotate(context_file: str, rotate_key_file: str, ciphertext_b64: str, steps: int) -> str:
        if not PYFHEL_INSTALLED:
            return "ERROR: 'Pyfhel' library not installed."
        try:
            HE = Pyfhel()
            HE.loadContext(context_file)
            HE.loadrotateKey(rotate_key_file)
            
            ctxt = HE.Ciphertext()
            ctxt.from_bytes(base64.b64decode(ciphertext_b64))
            
            ctxt_rotated = ctxt << steps
            return base64.b64encode(ctxt_rotated.to_bytes()).decode()
        except FileNotFoundError:
            return "ERROR: Key file not found."
        except Exception as e:
            return f"ERROR: Rotation failed: {e}"

    @staticmethod
    def qkd_bb84_simulate(key_length: int, eavesdropper: bool = False) -> (str, bytes):
        alice_bits = np.random.randint(0, 2, key_length)
        alice_bases = np.random.randint(0, 2, key_length)

        bob_bases = np.random.randint(0, 2, key_length)

        alice_photons = alice_bits.copy()

        eve_eavesdrops = False
        if eavesdropper:
            eve_eavesdrops = True
            eve_bases = np.random.randint(0, 2, key_length)
            for i in range(key_length):
                if eve_bases[i] == alice_bases[i]:
                    pass
                else:
                    alice_photons[i] = np.random.randint(0, 2)

        bob_measurements = np.zeros(key_length, dtype=int)
        for i in range(key_length):
            if bob_bases[i] == alice_bases[i]:
                bob_measurements[i] = alice_photons[i]
            else:
                bob_measurements[i] = np.random.randint(0, 2)

        matching_bases_indices = np.where(alice_bases == bob_bases)[0]
        
        alice_sifted_key = alice_bits[matching_bases_indices]
        bob_sifted_key = bob_measurements[matching_bases_indices]

        check_length = min(len(alice_sifted_key) // 2, 10)
        
        if check_length == 0:
            return "Not enough matching bits to form a key or perform error checking.", None

        alice_check_bits = alice_sifted_key[:check_length]
        bob_check_bits = bob_sifted_key[:check_length]

        errors = np.sum(alice_check_bits != bob_check_bits)
        qber = errors / check_length if check_length > 0 else 0

        result_str = f"  Initial Key Length: {key_length}\n"
        result_str += f"  Matching Bases Count: {len(matching_bases_indices)}\n"
        result_str += f"  Bits for Error Check: {check_length}\n"
        result_str += f"  Errors in Check Bits: {errors}\n"
        result_str += f"  Quantum Bit Error Rate (QBER): {qber:.2f}\n"

        if qber > 0.1 and eve_eavesdrops:
            result_str += f"{Colors.FAIL}[-] Eavesdropping detected! QBER is too high. Key is compromised.{Colors.ENDC}"
            return result_str, None
        elif qber > 0.1 and not eve_eavesdrops:
            result_str += f"{Colors.WARNING}[!] High QBER detected, but no eavesdropper simulated. This might indicate a noisy channel.{Colors.ENDC}"
            result_str += f"{Colors.WARNING}[!] Key might be compromised due to noise.{Colors.ENDC}"
            return result_str, None
        else:
            result_str += f"{Colors.OKGREEN}[+] No significant eavesdropping detected. Key can be established.{Colors.ENDC}"
            final_key_bits = alice_sifted_key[check_length:]
            
            final_key_bytes = np.packbits(final_key_bits)
            return result_str, final_key_bytes

    @staticmethod
    def _hash_block(block) -> str:
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @staticmethod
    def _create_genesis_block() -> dict:
        return {
            'index': 0,
            'timestamp': time.time(),
            'transactions': [],
            'proof': 1,
            'previous_hash': '0',
            'hash': ModernCrypto._hash_block({
                'index': 0,
                'timestamp': time.time(),
                'transactions': [],
                'proof': 1,
                'previous_hash': '0'
            })
        }

    @staticmethod
    def blockchain_new_chain(chain_file: str) -> (bool, str):
        chain = [ModernCrypto._create_genesis_block()]
        current_transactions = []
        
        try:
            with open(chain_file, 'w') as f:
                json.dump({'chain': chain, 'current_transactions': current_transactions}, f, indent=4)
            return True, f"New blockchain created and saved to {chain_file}"
        except Exception as e:
            return False, f"ERROR: Could not create new chain: {e}"

    @staticmethod
    def blockchain_add_transaction(chain_file: str, sender: str, recipient: str, amount: float) -> (bool, str):
        try:
            with open(chain_file, 'r') as f:
                data = json.load(f)
            chain = data['chain']
            current_transactions = data['current_transactions']
        except FileNotFoundError:
            return False, f"ERROR: Blockchain file not found: {chain_file}. Create a new chain first."
        except Exception as e:
            return False, f"ERROR: Could not load chain: {e}"

        current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })

        try:
            with open(chain_file, 'w') as f:
                json.dump({'chain': chain, 'current_transactions': current_transactions}, f, indent=4)
            return True, "Transaction added to the next block."
        except Exception as e:
            return False, f"ERROR: Could not add transaction: {e}"

    @staticmethod
    def blockchain_mine_block(chain_file: str) -> (bool, str):
        try:
            with open(chain_file, 'r') as f:
                data = json.load(f)
            chain = data['chain']
            current_transactions = data['current_transactions']
        except FileNotFoundError:
            return False, f"ERROR: Blockchain file not found: {chain_file}. Create a new chain first."
        except Exception as e:
            return False, f"ERROR: Could not load chain: {e}"

        last_block = chain[-1]
        last_proof = last_block['proof']
        
        proof = 0
        while not ModernCrypto._valid_proof(last_proof, proof):
            proof += 1

        previous_hash = ModernCrypto._hash_block(last_block)
        block = {
            'index': len(chain),
            'timestamp': time.time(),
            'transactions': current_transactions,
            'proof': proof,
            'previous_hash': previous_hash,
            'hash': ''
        }
        block['hash'] = ModernCrypto._hash_block(block)

        chain.append(block)
        current_transactions = []

        try:
            with open(chain_file, 'w') as f:
                json.dump({'chain': chain, 'current_transactions': current_transactions}, f, indent=4)
            return True, f"New block mined: {block['index']}. Proof: {proof}"
        except Exception as e:
            return False, f"ERROR: Could not mine block: {e}"

    @staticmethod
    def _valid_proof(last_proof: int, proof: int) -> bool:
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    @staticmethod
    def blockchain_validate(chain_file: str) -> (bool, str):
        try:
            with open(chain_file, 'r') as f:
                data = json.load(f)
            chain = data['chain']
        except FileNotFoundError:
            return False, f"ERROR: Blockchain file not found: {chain_file}. Create a new chain first."
        except Exception as e:
            return False, f"ERROR: Could not load chain: {e}"

        if not chain:
            return False, "ERROR: Blockchain is empty."

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            if block['previous_hash'] != ModernCrypto._hash_block(last_block):
                return False, f"Chain invalid: Previous hash mismatch at block {current_index}."

            if not ModernCrypto._valid_proof(last_block['proof'], block['proof']):
                return False, f"Chain invalid: Invalid Proof of Work at block {current_index}."

            last_block = block
            current_index += 1

        return True, "Blockchain is valid."

    @staticmethod
    def wallet_gen_privkey(priv_key_file: str) -> (bool, str):
        if not WALLET_INSTALLED:
            return False, "ERROR: 'ecdsa' and 'base58' libraries not installed."
        try:
            private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
            with open(priv_key_file, 'wb') as f:
                f.write(private_key.to_string())
            return True, f"Private key generated and saved to {priv_key_file}"
        except Exception as e:
            return False, f"ERROR: Could not generate private key: {e}"

    @staticmethod
    def wallet_derive_pubkey(priv_key_file: str, pub_key_file: str) -> (bool, str):
        if not WALLET_INSTALLED:
            return False, "ERROR: 'ecdsa' and 'base58' libraries not installed."
        try:
            with open(priv_key_file, 'rb') as f:
                private_key_bytes = f.read()
            private_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
            public_key = private_key.get_verifying_key()
            with open(pub_key_file, 'wb') as f:
                f.write(public_key.to_string())
            return True, f"Public key derived and saved to {pub_key_file}"
        except FileNotFoundError:
            return False, f"ERROR: Private key file not found: {priv_key_file}"
        except Exception as e:
            return False, f"ERROR: Could not derive public key: {e}"

    @staticmethod
    def wallet_derive_address(pub_key_file: str, address_file: str) -> (bool, str):
        if not WALLET_INSTALLED:
            return False, "ERROR: 'ecdsa' and 'base58' libraries not installed."
        try:
            with open(pub_key_file, 'rb') as f:
                public_key_bytes = f.read()
            
            sha256_hash = hashlib.sha256(public_key_bytes).digest()
            ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
            
            versioned_hash = b'\x00' + ripemd160_hash
            
            checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]
            
            address = base58.b58encode(versioned_hash + checksum).decode()
            
            with open(address_file, 'w') as f:
                f.write(address)
            return True, f"Address derived and saved to {address_file}: {address}"
        except FileNotFoundError:
            return False, f"ERROR: Public key file not found: {pub_key_file}"
        except Exception as e:
            return False, f"ERROR: Could not derive address: {e}"

    @staticmethod
    def wallet_sign_message(priv_key_file: str, message: bytes) -> str:
        if not WALLET_INSTALLED:
            return "ERROR: 'ecdsa' and 'base58' libraries not installed."
        try:
            with open(priv_key_file, 'rb') as f:
                private_key_bytes = f.read()
            private_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
            
            message_hash = hashlib.sha256(message).digest()
            signature = private_key.sign(message_hash)
            return base64.b64encode(signature).decode()
        except FileNotFoundError:
            return f"ERROR: Private key file not found: {priv_key_file}"
        except Exception as e:
            return f"ERROR: Could not sign message: {e}"

    @staticmethod
    def wallet_verify_message(pub_key_file: str, message: bytes, signature_b64: str) -> (bool, str):
        if not WALLET_INSTALLED:
            return False, "ERROR: 'ecdsa' and 'base58' libraries not installed."
        try:
            with open(pub_key_file, 'rb') as f:
                public_key_bytes = f.read()
            public_key = ecdsa.VerifyingKey.from_string(public_key_bytes, curve=ecdsa.SECP256k1)
            
            signature = base64.b64decode(signature_b64)
            message_hash = hashlib.sha256(message).digest()
            
            public_key.verify(signature, message_hash)
            return True, "Signature is valid."
        except FileNotFoundError:
            return False, f"ERROR: Public key file not found: {pub_key_file}"
        except ecdsa.BadSignatureError:
            return False, "Signature is invalid."
        except Exception as e:
            return False, f"ERROR: Could not verify message: {e}"


















    @staticmethod
    def dh_genparams(key_size: int, param_file: str) -> (bool, str):
        if not CRYPTO_INSTALLED:
            return False, "ERROR: 'cryptography' library not installed."
        try:
            parameters = dh.generate_parameters(generator=2, key_size=key_size)
            pem = parameters.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            )
            with open(param_file, 'wb') as f:
                f.write(pem)
            return True, f"DH parameters ({key_size}-bit) saved to {param_file}"
        except Exception as e:
            return False, f"ERROR: Could not generate parameters: {e}"

    @staticmethod
    def dh_genkeys(param_file: str, priv_key_file: str, pub_key_file: str) -> (bool, str):
        if not CRYPTO_INSTALLED:
            return False, "ERROR: 'cryptography' library not installed."
        try:
            with open(param_file, 'rb') as f:
                parameters = serialization.load_pem_parameters(f.read())
            
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()
            
            with open(priv_key_file, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            with open(pub_key_file, 'wb') as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            return True, f"DH keys generated and saved:\n  Private: {priv_key_file}\n  Public:  {pub_key_file}"
        except FileNotFoundError:
            return False, f"ERROR: Parameter file not found: {param_file}"
        except Exception as e:
            return False, f"ERROR: Could not generate keys: {e}"

    @staticmethod
    def dh_derive(priv_key_file: str, peer_pub_key_file: str) -> str:
        if not CRYPTO_INSTALLED:
            return "ERROR: 'cryptography' library not installed."
        try:
            with open(priv_key_file, 'rb') as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            
            with open(peer_pub_key_file, 'rb') as f:
                public_key = serialization.load_pem_public_key(f.read())
            
            shared_key = private_key.exchange(public_key)
            return shared_key.hex()
            
        except FileNotFoundError:
            return "ERROR: Key file not found."
        except Exception as e:
            return f"ERROR: Could not derive shared secret: {e}"


    @staticmethod
    def ecdh_genkeys(curve: str, priv_key_file: str, pub_key_file: str) -> (bool, str):
        if not CRYPTO_INSTALLED:
            return False, "ERROR: 'cryptography' library not installed."
        try:
            curve_obj = getattr(ec, curve.upper())()
            private_key = ec.generate_private_key(curve_obj)
            public_key = private_key.public_key()
            
            with open(priv_key_file, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            with open(pub_key_file, 'wb') as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            return True, f"ECDH keys ({curve}) generated and saved:\n  Private: {priv_key_file}\n  Public:  {pub_key_file}"
        except Exception as e:
            return False, f"ERROR: Could not generate keys: {e}"
            
    @staticmethod
    def ecdh_derive(priv_key_file: str, peer_pub_key_file: str) -> str:
        if not CRYPTO_INSTALLED:
            return "ERROR: 'cryptography' library not installed."
        try:
            with open(priv_key_file, 'rb') as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            
            with open(peer_pub_key_file, 'rb') as f:
                public_key = serialization.load_pem_public_key(f.read())
            
            if not isinstance(private_key, EllipticCurvePrivateKey) or not isinstance(public_key, EllipticCurvePublicKey):
                 return "ERROR: Keys are not valid Elliptic Curve keys."
                 
            shared_key = private_key.exchange(ec.ECDH(), public_key)
            return shared_key.hex()
            
        except FileNotFoundError:
            return "ERROR: Key file not found."
        except Exception as e:
            return f"ERROR: Could not derive shared secret: {e}"


    @staticmethod
    def ecdsa_genkeys(curve: str, priv_key_file: str, pub_key_file: str) -> (bool, str):
        if not CRYPTO_INSTALLED:
            return False, "ERROR: 'cryptography' library not installed."
        try:
            curve_obj = getattr(ec, curve.upper())()
            private_key = ec.generate_private_key(curve_obj)
            public_key = private_key.public_key()
            
            with open(priv_key_file, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            with open(pub_key_file, 'wb') as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            return True, f"ECDSA keys ({curve}) generated and saved:\n  Private: {priv_key_file}\n  Public:  {pub_key_file}"
        except Exception as e:
            return False, f"ERROR: Could not generate keys: {e}"

    @staticmethod
    def ecdsa_sign(priv_key_file: str, data: bytes) -> str:
        if not CRYPTO_INSTALLED:
            return "ERROR: 'cryptography' library not installed."
        try:
            with open(priv_key_file, 'rb') as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            
            if not isinstance(private_key, EllipticCurvePrivateKey):
                 return "ERROR: Key is not a valid Elliptic Curve private key."
            
            signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
            return base64.b64encode(signature).decode()
        except FileNotFoundError:
            return f"ERROR: Private key file not found: {priv_key_file}"
        except Exception as e:
            return f"ERROR: Signing failed: {e}"

    @staticmethod
    def ecdsa_verify(pub_key_file: str, data: bytes, signature_b64: str) -> (bool, str):
        if not CRYPTO_INSTALLED:
            return False, "ERROR: 'cryptography' library not installed."
        try:
            with open(pub_key_file, 'rb') as f:
                public_key = serialization.load_pem_public_key(f.read())
            
            if not isinstance(public_key, EllipticCurvePublicKey):
                 return False, "ERROR: Key is not a valid Elliptic Curve public key."
                 
            sig = base64.b64decode(signature_b64.encode())
            
            public_key.verify(sig, data, ec.ECDSA(hashes.SHA256()))
            return True, "Signature is valid."
        except FileNotFoundError:
            return False, f"ERROR: Public key file not found: {pub_key_file}"
        except InvalidSignature:
            return False, "Signature is invalid."
        except Exception as e:
            return False, f"ERROR: Verification failed. Is signature/key correct? {e}"


class HashFunctions:
    """Various hashing algorithms"""
    
    @staticmethod
    def get_available_algorithms() -> Dict[str, Any]:
        """Returns a dictionary of available hash algorithms."""
        algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
            'blake2b': hashlib.blake2b,
            'blake2s': hashlib.blake2s,
        }
        for algo in ['sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'ripemd160', 'whirlpool']:
            if hasattr(hashlib, algo):
                algorithms[algo] = getattr(hashlib, algo)
        return algorithms

    @staticmethod
    def hash_data(data: bytes, algorithm: str) -> str:
        """Hash data using specified algorithm"""
        algorithms = HashFunctions.get_available_algorithms()
        
        if algorithm.lower() not in algorithms:
            return f"ERROR: Unknown or unsupported algorithm '{algorithm}'"
        
        hash_obj = algorithms[algorithm.lower()]()
        hash_obj.update(data)
        return hash_obj.hexdigest()

    @staticmethod
    def tiger_hash(data: bytes) -> str:
        """Hash data using the Tiger algorithm."""
        if not TIGER_INSTALLED:
            return "ERROR: 'pytiger' library not installed. Run: pip install pytiger"
        
        hash_obj = tiger.Tiger()
        hash_obj.update(data)
        return hash_obj.hexdigest()

class KDFTools:
    """Key Derivation and Password Hashing Functions"""

    @staticmethod
    def bcrypt_hash(password: str, rounds: int) -> str:
        """Hashes a password using bcrypt."""
        if not BCRYPT_INSTALLED:
            return "ERROR: 'bcrypt' library not installed. Run: pip install bcrypt"
        try:
            salt = bcrypt.gensalt(rounds=rounds)
            hashed = bcrypt.hashpw(password.encode(), salt)
            return hashed.decode()
        except Exception as e:
            return f"ERROR: {str(e)}"

    @staticmethod
    def bcrypt_verify(password: str, hash_to_check: str) -> (bool, str):
        """Verifies a password against a bcrypt hash."""
        if not BCRYPT_INSTALLED:
            return False, "ERROR: 'bcrypt' library not installed. Run: pip install bcrypt"
        try:
            if bcrypt.checkpw(password.encode(), hash_to_check.encode()):
                return True, "SUCCESS: Passwords match!"
            else:
                return False, "FAILURE: Passwords do NOT match."
        except Exception as e:
            return False, f"ERROR: Invalid hash format? {str(e)}"

    @staticmethod
    def scrypt_hash(password: str) -> str:
        """Hashes a password using scrypt."""
        if not SCRYPT_INSTALLED:
            return "ERROR: 'scrypt' library not installed. Run: pip install scrypt"
        try:
            hashed = scrypt.hash(password.encode())
            return hashed.hex()
        except Exception as e:
            return f"ERROR: {str(e)}"

    @staticmethod
    def scrypt_verify(password: str, hash_to_check: str) -> (bool, str):
        """Verifies a password against an scrypt hash."""
        if not SCRYPT_INSTALLED:
            return False, "ERROR: 'scrypt' library not installed. Run: pip install scrypt"
        try:
            hash_bytes = bytes.fromhex(hash_to_check)
            if scrypt.verify(password.encode(), hash_bytes):
                return True, "SUCCESS: Passwords match!"
            else:
                return False, "FAILURE: Passwords do NOT match."
        except scrypt.error:
            return False, "FAILURE: Passwords do NOT match."
        except Exception as e:
            return False, f"ERROR: {str(e)}"

    @staticmethod
    def argon2_hash(password: str) -> str:
        """Hashes a password using Argon2."""
        if not ARGON2_INSTALLED:
            return "ERROR: 'argon2-cffi' library not installed. Run: pip install argon2-cffi"
        try:
            ph = PasswordHasher()
            hashed = ph.hash(password.encode())
            return hashed
        except Exception as e:
            return f"ERROR: {str(e)}"

    @staticmethod
    def argon2_verify(password: str, hash_to_check: str) -> (bool, str):
        """Verifies a password against an Argon2 hash."""
        if not ARGON2_INSTALLED:
            return False, "ERROR: 'argon2-cffi' library not installed. Run: pip install argon2-cffi"
        try:
            ph = PasswordHasher()
            ph.verify(hash_to_check.encode(), password.encode())
            return True, "SUCCESS: Passwords match!"
        except VerifyMismatchError:
            return False, "FAILURE: Passwords do NOT match."
        except Exception as e:
            return False, f"ERROR: {str(e)}"

    @staticmethod
    def pbkdf2_derive(password: str, salt_hex: str, iterations: int, length: int) -> (Optional[str], str):
        """Derives a key from a password using PBKDF2-HMAC-SHA256."""
        if not CRYPTO_INSTALLED:
            return None, "ERROR: 'cryptography' library not installed."
        try:
            salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
            kdf = PBKDF2(
                algorithm=hashes.SHA256(),
                length=length,
                salt=salt,
                iterations=iterations,
            )
            key = kdf.derive(password.encode())
            return key.hex(), salt.hex()
        except Exception as e:
            return None, f"ERROR: {str(e)}"

    @staticmethod
    def hkdf_derive(ikm_hex: str, salt_hex: str, info: str, length: int) -> str:
        """Derives keys from a master secret using HKDF-SHA256."""
        if not CRYPTO_INSTALLED:
            return "ERROR: 'cryptography' library not installed."
        try:
            ikm = bytes.fromhex(ikm_hex)
            salt = bytes.fromhex(salt_hex) if salt_hex else None
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=length,
                salt=salt,
                info=info.encode(),
            )
            key = hkdf.derive(ikm)
            return key.hex()
        except Exception as e:
            return f"ERROR: {str(e)}"
    
class StegoTools:
    """Steganography tools"""

    @staticmethod
    def lsb_image_hide(infile: str, outfile: str, text_to_hide: Optional[str], file_to_hide: Optional[str]) -> (bool, str):
        """Hides data in a PNG image using LSB."""
        if not STEGO_INSTALLED:
            return False, "ERROR: 'stegano' and 'Pillow' libraries not installed. Run: pip install stegano Pillow"
        
        try:
            if file_to_hide:
                secret = stegano.lsb.hide(infile, file_to_hide)
                secret.save(outfile)
                return True, f"Successfully hid file '{file_to_hide}' in '{outfile}'"
            elif text_to_hide:
                secret = stegano.lsb.hide(infile, text_to_hide)
                secret.save(outfile)
                return True, f"Successfully hid message in '{outfile}'"
            else:
                return False, "ERROR: No data provided to hide."
        except FileNotFoundError:
            return False, f"ERROR: Input file not found: {infile}"
        except Exception as e:
            return False, f"ERROR: Could not hide data: {e}"

    @staticmethod
    def lsb_image_reveal(infile: str, outfile: Optional[str]) -> (bool, str):
        """Reveals data from an LSB PNG image."""
        if not STEGO_INSTALLED:
            return False, "ERROR: 'stegano' and 'Pillow' libraries not installed. Run: pip install stegano Pillow"
            
        try:
            clear_message = stegano.lsb.reveal(infile)
            
            if outfile:
                try:
                    message_text = clear_message
                    if isinstance(clear_message, bytes):
                        message_text = clear_message.decode('utf-8', errors='ignore')

                    if all(c in string.printable for c in message_text):
                         with open(outfile, "w") as f:
                            f.write(message_text)
                    else:
                         with open(outfile, "wb") as f:
                            f.write(clear_message)

                    return True, f"Successfully extracted hidden data to '{outfile}'"
                except Exception as e:
                    return False, f"ERROR: Could not write to output file: {e}"
            else:
                message_text = clear_message
                if isinstance(clear_message, bytes):
                    try:
                        message_text = clear_message.decode('utf-8')
                    except UnicodeDecodeError:
                        message_text = f"(Binary data, {len(clear_message)} bytes, hex): {clear_message.hex()}"

                return True, f"Revealed Message: {message_text}"

        except FileNotFoundError:
            return False, f"ERROR: Input file not found: {infile}"
        except Exception as e:
            return False, f"ERROR: Could not reveal data: {e}"