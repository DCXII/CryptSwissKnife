"""
All Quantum Cryptography modules
"""
from .base import CryptoModule
from ..utils import Colors
from ..engine import ModernCrypto

class QKDModule(CryptoModule):
    """Quantum Key Distribution (BB84 Protocol) Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "quantum/qkd"
        self.description = "Quantum Key Distribution (BB84 Protocol) Simulation"
        self.detailed_description = """
This module simulates the BB84 Quantum Key Distribution (QKD) protocol.
It demonstrates how two parties (Alice and Bob) can establish a shared
secret key with the ability to detect eavesdropping.

[+] Workflow:
1.  Alice generates random bits and random bases.
2.  Alice sends polarized photons to Bob based on her bits and bases.
3.  Bob measures the incoming photons with random bases.
4.  Alice and Bob publicly compare their bases to keep only matching ones.
5.  Alice and Bob publicly compare a subset of their remaining bits to detect eavesdropping.
6.  If no eavesdropping is detected, the remaining bits form the shared secret key.

NOTE: This is a simplified simulation and does not involve actual quantum mechanics.
"""
        self.options = {
            'ACTION': {'value': 'simulate', 'description': 'Action: simulate'},
            'KEY_LENGTH': {'value': '128', 'description': 'Desired length of the final shared key (approximate)'},
            'EAVESDROPPER': {'value': 'False', 'description': 'Simulate an eavesdropper (True/False)'},
        }
        self.required_options = ['ACTION']
    
    def run(self) -> str:
        action = self.options['ACTION']['value'].lower()
        
        if action == 'simulate':
            try:
                key_length = int(self.options['KEY_LENGTH']['value'])
                eavesdropper = self.options['EAVESDROPPER']['value'].lower() == 'true'
            except ValueError:
                return f"{Colors.FAIL}[-] ERROR: KEY_LENGTH must be an integer and EAVESDROPPER a boolean.{Colors.ENDC}"
            
            result, shared_key = ModernCrypto.qkd_bb84_simulate(key_length, eavesdropper)
            
            if result.startswith("ERROR:"):
                return f"{Colors.FAIL}[-] {result}{Colors.ENDC}"
            
            output = f"{Colors.OKGREEN}[+] QKD BB84 Simulation Complete:{Colors.ENDC}\n"
            output += result
            if shared_key:
                output += f"\n{Colors.OKGREEN}[+] Shared Secret Key (hex):{Colors.ENDC} {shared_key.hex()}"
            return output
            
        else:
            return f"{Colors.FAIL}[-] Unknown action: {action}{Colors.ENDC}"