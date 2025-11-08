"""
All Cryptocurrency modules
"""
from .base import CryptoModule
from ..utils import Colors
from ..engine import ModernCrypto, CRYPTO_INSTALLED

class WalletModule(CryptoModule):
    """Cryptocurrency Wallet Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "cryptocurrency/wallet"
        self.description = "Generate and manage cryptocurrency wallets (simplified)"
        self.detailed_description = """
This module provides basic functionalities for a cryptocurrency wallet,
including generating private/public key pairs, deriving addresses,
and signing messages/transactions.

[+] Workflow:
1.  Generate a new private key (ACTION=gen_privkey).
2.  Derive the public key from the private key (ACTION=derive_pubkey).
3.  Derive a wallet address from the public key (ACTION=derive_address).
4.  Sign a message or transaction with the private key (ACTION=sign_message).
5.  Verify a signed message (ACTION=verify_message).
"""
        self.options = {
            'ACTION': {'value': 'gen_privkey', 'description': 'Action: gen_privkey, derive_pubkey, derive_address, sign_message, verify_message'},
            'PRIV_KEY_FILE': {'value': 'wallet_priv.pem', 'description': 'Path to private key file (IN/OUT)'},
            'PUB_KEY_FILE': {'value': 'wallet_pub.pem', 'description': 'Path to public key file (IN/OUT)'},
            'ADDRESS_FILE': {'value': 'wallet_address.txt', 'description': 'Path to address file (OUT)'},
            'MESSAGE': {'value': '', 'description': 'Message to sign or verify'},
            'SIGNATURE': {'value': '', 'description': 'Base64 signature to verify'},
        }
        self.required_options = ['ACTION']
    
    def run(self) -> str:
        if not CRYPTO_INSTALLED:
            return f"{Colors.FAIL}[-] 'cryptography' library not installed.{Colors.ENDC}"
            
        action = self.options['ACTION']['value'].lower()
        priv_key_file = self.options['PRIV_KEY_FILE']['value']
        pub_key_file = self.options['PUB_KEY_FILE']['value']
        address_file = self.options['ADDRESS_FILE']['value']
        message = self.options['MESSAGE']['value']
        signature = self.options['SIGNATURE']['value']

        try:
            if action == 'gen_privkey':
                success, msg = ModernCrypto.wallet_gen_privkey(priv_key_file)
                return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"

            elif action == 'derive_pubkey':
                if not priv_key_file:
                    return f"{Colors.FAIL}[-] Missing required option: PRIV_KEY_FILE{Colors.ENDC}"
                success, msg = ModernCrypto.wallet_derive_pubkey(priv_key_file, pub_key_file)
                return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"

            elif action == 'derive_address':
                if not pub_key_file:
                    return f"{Colors.FAIL}[-] Missing required option: PUB_KEY_FILE{Colors.ENDC}"
                success, msg = ModernCrypto.wallet_derive_address(pub_key_file, address_file)
                return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"

            elif action == 'sign_message':
                if not priv_key_file:
                    return f"{Colors.FAIL}[-] Missing required option: PRIV_KEY_FILE{Colors.ENDC}"
                if not message:
                    return f"{Colors.FAIL}[-] Missing required option: MESSAGE{Colors.ENDC}"
                
                raw_result = ModernCrypto.wallet_sign_message(priv_key_file, message.encode())
                if raw_result.startswith("ERROR:"):
                    return f"{Colors.FAIL}[-] {raw_result}{Colors.ENDC}"
                
                self.options['SIGNATURE']['value'] = raw_result
                return (f"{Colors.OKGREEN}[+] Message signed. Signature (Base64):{Colors.ENDC} {raw_result}\n"
                        f"{Colors.OKCYAN}[*] SIGNATURE option has been updated.{Colors.ENDC}")

            elif action == 'verify_message':
                if not pub_key_file:
                    return f"{Colors.FAIL}[-] Missing required option: PUB_KEY_FILE{Colors.ENDC}"
                if not message:
                    return f"{Colors.FAIL}[-] Missing required option: MESSAGE{Colors.ENDC}"
                if not signature:
                    return f"{Colors.FAIL}[-] Missing required option: SIGNATURE{Colors.ENDC}"
                
                success, msg = ModernCrypto.wallet_verify_message(pub_key_file, message.encode(), signature)
                if success:
                    return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}"
                else:
                    return f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"
                
            else:
                return f"{Colors.FAIL}[-] Unknown action: {action}{Colors.ENDC}"
        
        except Exception as e:
            return f"{Colors.FAIL}[-] ERROR: {str(e)}{Colors.ENDC}"