"""
All Steganography modules
"""
from .base import CryptoModule
from ..utils import Colors
from ..engine import StegoTools

class LSBImageHideModule(CryptoModule):
    """Hide data in a PNG image using LSB"""
    
    def __init__(self):
        super().__init__()
        self.name = "stego/lsb_image_hide"
        self.description = "Hide a secret message or file in a PNG image via LSB"
        self.detailed_description = """
Hides data within the least-significant bits (LSB) of the pixels in an image.
This module requires a lossless image format like PNG.

[+] Usage:
Set the INFILE (the 'carrier' image) and the OUTFILE (the new 'stego' image).
Then, set *either* a TEXT message or a FILE_TO_HIDE.
The 'lsb_image_reveal' module can be used to extract the data.
"""
        self.options = {
            'INFILE': {'value': '', 'description': 'Input PNG image (the carrier)'},
            'OUTFILE': {'value': '', 'description': 'Output PNG image (the new stego file)'},
            'TEXT': {'value': '', 'description': 'Text message to hide'},
            'FILE_TO_HIDE': {'value': '', 'description': 'Path to a file to hide (e.g., secret.txt)'},
        }
        self.required_options = ['INFILE', 'OUTFILE', ('TEXT', 'FILE_TO_HIDE')]

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"

        infile = self.options['INFILE']['value']
        outfile = self.options['OUTFILE']['value']
        text = self.options['TEXT']['value']
        file_to_hide = self.options['FILE_TO_HIDE']['value']

        success, message = StegoTools.lsb_image_hide(infile, outfile, text, file_to_hide)

        if success:
            return f"{Colors.OKGREEN}[+] {message}{Colors.ENDC}"
        else:
            return f"{Colors.FAIL}[-] {message}{Colors.ENDC}"

class LSBImageRevealModule(CryptoModule):
    """Reveal data from an LSB PNG image"""
    
    def __init__(self):
        super().__init__()
        self.name = "stego/lsb_image_reveal"
        self.description = "Reveal a secret message or file from an LSB stego image"
        self.detailed_description = """
Extracts data hidden using the LSB (least-significant bit) method.
This module is the counterpart to 'stego/lsb_image_hide'.

[+] Usage:
Set the INFILE (the 'stego' image).
If you set OUTFILE, the module will try to save the hidden data as a file.
If you do not set OUTFILE, it will print the hidden text message to the console.
"""
        self.options = {
            'INFILE': {'value': '', 'description': 'Input stego PNG image'},
            'OUTFILE': {'value': '', 'description': 'File to save extracted data to (optional)'},
        }
        self.required_options = ['INFILE']

    def run(self) -> str:
        valid, missing_groups = self.check_required()
        if not valid:
            return f"{Colors.FAIL}[-] Missing required options: {', '.join(missing_groups)}{Colors.ENDC}"

        infile = self.options['INFILE']['value']
        outfile = self.options['OUTFILE']['value']

        success, message = StegoTools.lsb_image_reveal(infile, outfile)

        if success:
            return f"{Colors.OKGREEN}[+] {message}{Colors.ENDC}"
        else:
            return f"{Colors.FAIL}[-] {message}{Colors.ENDC}"