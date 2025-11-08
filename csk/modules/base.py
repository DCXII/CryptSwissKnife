"""
The Base Class for all modules.
"""
from typing import Optional, Any
from rich.table import Table
from ..utils import Colors

class CryptoModule:
    """Base class for all crypto modules"""
    
    def __init__(self):
        self.name = ""
        self.description = ""
        self.detailed_description = "No details provided for this module."
        self.author = "CryptoSwissKnife Team"
        self.options = {}
        self.required_options = []
    
    def info(self) -> Table:
        """Display module information in a rich Table"""
        table = Table(title=f"Module: {self.name}", show_header=True, header_style="bold magenta")
        table.add_column("Option", style="cyan", no_wrap=True)
        table.add_column("Current Setting", style="white")
        table.add_column("Required", style="yellow")
        table.add_column("Description", style="green")

        flat_required = []
        for opt_group in self.required_options:
            if isinstance(opt_group, tuple):
                flat_required.extend(opt_group)
            else:
                flat_required.append(opt_group)

        for opt_name, opt_data in self.options.items():
            required_str = "no"
            if opt_name in flat_required:
                for opt_group in self.required_options:
                    if isinstance(opt_group, tuple) and opt_name in opt_group:
                        required_str = "yes (or)"
                        break
                else:
                    required_str = "yes"

            current = str(opt_data.get('value', ''))
            desc = opt_data.get('description', '')
            table.add_row(opt_name, current, required_str, desc)
        
        return table
    
    def set_option(self, name: str, value: str) -> bool:
        """Set an option value"""
        if name in self.options:
            self.options[name]['value'] = value
            return True
        return False
    
    def check_required(self) -> tuple:
        """Check if all required options are set.
        Supports tuples for OR logic (e.g., ('TEXT', 'INFILE'))
        """
        missing_groups = []
        for opt_group in self.required_options:
            if isinstance(opt_group, tuple):
                group_has_value = False
                for opt in opt_group:
                    if self.options[opt].get('value'):
                        group_has_value = True
                        break
                if not group_has_value:
                    missing_groups.append(" OR ".join(opt_group))
            else:
                if not self.options[opt_group].get('value'):
                    missing_groups.append(opt_group)
        
        return len(missing_groups) == 0, missing_groups
    
    def run(self) -> str:
        """Execute the module"""
        raise NotImplementedError("Subclasses must implement run()")

    def _get_input_data(self, read_as_bytes: bool = False) -> (Optional[str], Optional[bytes], Optional[str]):
        """Helper to read TEXT or INFILE.
        Returns (text_data, bytes_data, error_string)
        """
        text = self.options['TEXT']['value']
        infile = self.options['INFILE']['value']
        
        if infile:
            try:
                read_mode = 'rb' if read_as_bytes else 'r'
                with open(infile, read_mode) as f:
                    data = f.read()
                
                if read_as_bytes:
                    return None, data, None
                else:
                    try:
                        text_data = data.decode()
                        return text_data, data, None
                    except UnicodeDecodeError:
                        return None, data, f"{Colors.FAIL}[-] ERROR: File is not valid UTF-8. Use a bytes-compatible module.{Colors.ENDC}"
            except FileNotFoundError:
                return None, None, f"{Colors.FAIL}[-] ERROR: Input file not found: {infile}{Colors.ENDC}"
            except Exception as e:
                return None, None, f"{Colors.FAIL}[-] ERROR: Could not read file: {e}{Colors.ENDC}"
        
        if text:
            return text, text.encode(), None
            
        return None, None, f"{Colors.FAIL}[-] Missing required options: Set TEXT or INFILE{Colors.ENDC}"

    def _get_data_input(self, read_as_bytes: bool = False) -> (Optional[str], Optional[bytes], Optional[str]):
        """Helper to read DATA or INFILE.
        Returns (text_data, bytes_data, error_string)
        """
        data_val = self.options['DATA']['value']
        infile = self.options['INFILE']['value']
        
        if infile:
            try:
                read_mode = 'rb' if read_as_bytes else 'r'
                with open(infile, read_mode) as f:
                    data = f.read()
                
                if read_as_bytes:
                    return None, data, None
                else:
                    try:
                        text_data = data.decode()
                        return text_data, data, None
                    except UnicodeDecodeError:
                        return None, data, f"{Colors.FAIL}[-] ERROR: File is not valid UTF-8. Use a bytes-compatible module.{Colors.ENDC}"
            except FileNotFoundError:
                return None, None, f"{Colors.FAIL}[-] ERROR: Input file not found: {infile}{Colors.ENDC}"
            except Exception as e:
                return None, None, f"{Colors.FAIL}[-] ERROR: Could not read file: {e}{Colors.ENDC}"
        
        if data_val:
            return data_val, data_val.encode(), None
            
        return None, None, f"{Colors.FAIL}[-] Missing required options: Set DATA or INFILE{Colors.ENDC}"

    def _write_output_data(self, raw_result: Any) -> str:
        """Helper to write to OUTFILE or return as string"""
        outfile = self.options['OUTFILE']['value']
        
        if isinstance(raw_result, bytes):
            raw_result_str = raw_result.hex()
        else:
            raw_result_str = str(raw_result)

        if outfile:
            try:
                with open(outfile, 'w') as f:
                    f.write(raw_result_str)
                return f"{Colors.OKGREEN}[+] Output successfully written to: {outfile}{Colors.ENDC}"
            except Exception as e:
                return f"{Colors.FAIL}[-] ERROR: Could not write file: {e}{Colors.ENDC}"
        else:
            return f"{Colors.OKGREEN}[+] Result:{Colors.ENDC} {raw_result_str}"