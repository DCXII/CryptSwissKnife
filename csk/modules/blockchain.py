"""
All Blockchain modules
"""
from .base import CryptoModule
from ..utils import Colors
from ..engine import ModernCrypto

class SimpleBlockchainModule(CryptoModule):
    """Simple Blockchain Module"""
    
    def __init__(self):
        super().__init__()
        self.name = "blockchain/simple_blockchain"
        self.description = "A simplified blockchain implementation"
        self.detailed_description = """
This module provides a basic implementation of a blockchain.
It allows you to create a new blockchain, add blocks with transactions,
and validate the integrity of the chain.

[+] Workflow:
1.  Initialize a new blockchain (ACTION=new_chain).
2.  Add transactions to the current block (ACTION=add_transaction).
3.  Mine a new block (ACTION=mine_block).
4.  Validate the entire blockchain (ACTION=validate).
"""
        self.options = {
            'ACTION': {'value': 'new_chain', 'description': 'Action: new_chain, add_transaction, mine_block, validate'},
            'SENDER': {'value': 'Alice', 'description': 'Sender of the transaction'},
            'RECIPIENT': {'value': 'Bob', 'description': 'Recipient of the transaction'},
            'AMOUNT': {'value': '10', 'description': 'Amount of the transaction'},
            'CHAIN_FILE': {'value': 'blockchain.json', 'description': 'File to store the blockchain'},
        }
        self.required_options = ['ACTION']
    
    def run(self) -> str:
        action = self.options['ACTION']['value'].lower()
        chain_file = self.options['CHAIN_FILE']['value']

        if action == 'new_chain':
            success, msg = ModernCrypto.blockchain_new_chain(chain_file)
            return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"

        elif action == 'add_transaction':
            sender = self.options['SENDER']['value']
            recipient = self.options['RECIPIENT']['value']
            amount_str = self.options['AMOUNT']['value']
            try:
                amount = float(amount_str)
            except ValueError:
                return f"{Colors.FAIL}[-] ERROR: AMOUNT must be a number.{Colors.ENDC}"
            
            success, msg = ModernCrypto.blockchain_add_transaction(chain_file, sender, recipient, amount)
            return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"

        elif action == 'mine_block':
            success, msg = ModernCrypto.blockchain_mine_block(chain_file)
            return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"

        elif action == 'validate':
            success, msg = ModernCrypto.blockchain_validate(chain_file)
            return f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}" if success else f"{Colors.FAIL}[-] {msg}{Colors.ENDC}"
            
        else:
            return f"{Colors.FAIL}[-] Unknown action: {action}{Colors.ENDC}"