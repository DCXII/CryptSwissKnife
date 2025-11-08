#!/usr/bin/env python3
"""
CryptSwissKnife v3.0
Main entry point for the console.
"""

import sys
from csk.console import CryptoConsole

def main():
    """Main entry point"""
    try:
        console = CryptoConsole()
        console.main_loop()
    except Exception as e:
        print(f"Fatal error: {e}")
        # import traceback
        # traceback.print_exc() # Uncomment for debugging
        sys.exit(1)

if __name__ == '__main__':
    main()
