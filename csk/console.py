"""
The Console UI.
Holds the CryptoConsole and CryptoCompleter classes that
manage the user interface and command dispatch.
"""

import sys
import shlex
import os
from typing import Optional, Iterable

from rich.console import Console
from rich.table import Table
from rich.padding import Padding

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion, CompleteEvent, PathCompleter
from prompt_toolkit.document import Document
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.styles import Style
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.output import ColorDepth
from pygments.lexers.shell import BashLexer

from .utils import Colors
from .engine import HashFunctions
from .modules import ALL_MODULES


class CryptoCompleter(Completer):
    """
    Custom completer for prompt-toolkit that is context-aware.
    v2.10: New "hybrid" logic for path completion.
    """
    def __init__(self, console):
        self.console = console
        self.main_commands = ['use', 'show', 'search', 'set', 'run', 'back', 'info', 'help', 'banner', 'clear', 'version', 'exit', 'quit']
        self.show_options = ['modules', 'options']
        
        self.hash_algorithms = list(HashFunctions.get_available_algorithms().keys())
        if "hash/tiger" in self.console.modules:
             self.hash_algorithms.append('tiger')
        self.hash_algorithms = sorted(list(set(self.hash_algorithms)))
        
        self.modes = ['encrypt', 'decrypt']
        self.path_completer = PathCompleter(expanduser=True) 
        self.file_options = ['INFILE', 'OUTFILE', 'PUB_KEY', 'PRIV_KEY', 'FILE_TO_HIDE', 'PARAM_FILE', 'PEER_PUB_KEY']

    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        text = document.text_before_cursor
        word_before_cursor = document.get_word_before_cursor(WORD=True)
        
        
        
        text_lstrip = text.lstrip()
        simple_parts = text_lstrip.split()
        is_file_path_context = False
        
        if self.console.current_module and len(simple_parts) >= 2:
            cmd_lower = simple_parts[0].lower()
            opt_upper = simple_parts[1].upper()
            
            if cmd_lower == 'set' and opt_upper in self.file_options:
                if len(simple_parts) > 2 or (len(simple_parts) == 2 and text.endswith(' ')):
                    is_file_path_context = True

        if is_file_path_context:
            try:
                space1_index = text_lstrip.index(' ')
                space2_index = text_lstrip.index(' ', space1_index + 1)
                path_prefix_start_index = space2_index + 1
                
                path_text = text_lstrip[path_prefix_start_index:]
                
                if path_text.startswith('"') and not path_text.endswith('"'):
                    path_text = path_text[1:]
                elif path_text.startswith("'") and not path_text.endswith("'"):
                    path_text = path_text[1:]
                
                path_document = Document(
                    text=path_text, 
                    cursor_position=len(path_text)
                )
                
                for completion in self.path_completer.get_completions(path_document, complete_event):
                    yield completion
                return
            except ValueError:
                return

        
        try:
            parts = shlex.split(text)
            if text.endswith(' '):
                arg_index = len(parts)
            else:
                arg_index = len(parts) - 1
        except ValueError:
            return 

        if arg_index == 0:
            for cmd in self.main_commands:
                if cmd.startswith(word_before_cursor):
                    yield Completion(cmd, start_position=-len(word_before_cursor),
                                     display=cmd, display_meta='Command')
            return
        
        if not parts:
             return
             
        cmd = parts[0].lower()

        
        if (cmd == 'use' or cmd == 'info' or cmd == 'search') and arg_index == 1:
            seen_short_names = set()
            for full_name in self.console.modules:
                short_name = full_name.split('/')[-1]
                category = full_name.split('/')[0]
                
                if short_name in seen_short_names:
                    if full_name.startswith(word_before_cursor):
                         yield Completion(full_name, 
                                     start_position=-len(word_before_cursor),
                                     display=f"{full_name:<20}",
                                     display_meta=category)
                    continue
                
                seen_short_names.add(short_name)
                
                if short_name.startswith(word_before_cursor):
                    yield Completion(short_name, 
                                     start_position=-len(word_before_cursor),
                                     display=f"{short_name:<20}",
                                     display_meta=category)
            return

        elif cmd == 'show' and arg_index == 1:
            for opt in self.show_options:
                if opt.startswith(word_before_cursor):
                    yield Completion(opt, start_position=-len(word_before_cursor))
            return

        elif cmd == 'set':
            if not self.console.current_module:
                return

            options = self.console.current_module.options.keys()
            
            if arg_index == 1:
                for opt in options:
                    if opt.startswith(word_before_cursor.upper()):
                         yield Completion(opt, start_position=-len(word_before_cursor))
                return
            
            if arg_index == 2:
                opt_name = parts[1].upper()
                
                if opt_name == 'MODE':
                    for mode in self.modes:
                        if mode.startswith(word_before_cursor):
                            yield Completion(mode, start_position=-len(word_before_cursor))
                    return
                
                elif opt_name == 'ALGORITHM':
                     for algo in self.hash_algorithms:
                        if algo.startswith(word_before_cursor):
                            yield Completion(algo, start_position=-len(word_before_cursor))
                     return
                            
                elif opt_name == 'ACTION':
                    if self.console.current_module.name == 'asymmetric/rsa':
                         actions = ['genkeys', 'encrypt', 'decrypt', 'sign', 'verify']
                    elif self.console.current_module.name == 'asymmetric/dh':
                         actions = ['genparams', 'genkeys', 'derive']
                    elif self.console.current_module.name == 'asymmetric/ecdh':
                         actions = ['genkeys', 'derive']
                    elif self.console.current_module.name == 'asymmetric/ecdsa':
                         actions = ['genkeys', 'sign', 'verify']
                    else:
                         actions = []
                         
                    for action in actions:
                         if action.startswith(word_before_cursor):
                            yield Completion(action, start_position=-len(word_before_cursor))
                    return
                
                elif opt_name == 'CURVE':
                    curves = ['SECP192R1', 'SECP224R1', 'SECP256R1', 'SECP384R1', 'SECP521R1']
                    for curve in curves:
                        if curve.startswith(word_before_cursor.upper()):
                            yield Completion(curve, start_position=-len(word_before_cursor))
                    return

        
        return


class CryptoConsole:
    """
    Interactive cryptography console built with prompt-toolkit.
    """
    
    def __init__(self):
        self.console = Console()
        self.current_module = None
        
        self.modules = {}
        for module_class in ALL_MODULES:
            instance = module_class()
            if instance.name:
                self.modules[instance.name] = module_class
        
        self.workspace = os.path.expanduser("~/.cryptoswissknife")
        os.makedirs(self.workspace, exist_ok=True)
        
        self.intro = rf"""
{Colors.OKCYAN}
██████╗██████╗ ██╗   ██╗██████╗ ████████╗
██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   
██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   
╚██████╗██║  ██║   ██║   ██║        ██║   
 ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   
                                          
███████╗██╗    ██╗██╗███████╗███████╗     
██╔════╝██║    ██║██║██╔════╝██╔════╝     
███████╗██║ █╗ ██║██║███████╗███████╗     
╚════██║██║███╗██║██║╚════██║╚════██║     
███████║╚███╔███╔╝██║███████║███████║     
╚══════╝ ╚══╝╚══╝ ╚═╝╚══════╝╚══════╝     
                                          
██╗  ██╗███╗   ██╗██╗███████╗███████╗     
██║ ██╔╝████╗  ██║██║██╔════╝██╔════╝     
█████╔╝ ██╔██╗ ██║██║█████╗  █████╗       
██╔═██╗ ██║╚██╗██║██║██╔══╝  ██╔══╝       
██║  ██╗██║ ╚████║██║██║     ███████╗     
╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝     ╚══════╝   
{Colors.ENDC}
{Colors.OKGREEN}CryptoSwissKnife v1 | 63 Modules{Colors.ENDC}
{Colors.WARNING}"One tool to encrypt, decrypt, and sign them all."{Colors.ENDC}
{Colors.WARNING}Type 'help' for available commands or 'banner' to display banner again{Colors.ENDC}
    """
        
        self.pt_style = Style.from_dict({
            'prompt.main': 'ansired bold',
            'prompt.module': 'ansiblue bold',
            
            'completion-menu.completion': 'bg:ansibrightblack fg:ansiwhite',
            'completion-menu.completion.current': 'bg:ansiblue fg:ansiwhite',
            'completion-menu.completion.meta': 'bg:ansibrightblack fg:ansigray',
            'completion-menu.completion.meta.completion.current': 'bg:ansiblue fg:ansiwhite',
            'completion-menu.border': 'bg:ansibrightblack fg:ansibrightblack',
            'completion-menu.scrollbar': 'bg:ansibrightblack fg:ansigray',
            'bottom-toolbar': 'bg:ansibrightblack fg:ansigray',
            'bottom-toolbar.text': 'bg:ansibrightblack fg:ansigray', 
            'auto-suggestion': 'ansigray',
        })
        
        self.completer = CryptoCompleter(self)
        self.session = PromptSession(
            completer=self.completer,
            auto_suggest=AutoSuggestFromHistory(),
            key_bindings=self.get_key_bindings(),
            lexer=PygmentsLexer(BashLexer),
            style=self.pt_style,
            color_depth=ColorDepth.ANSI_COLORS_ONLY
        )

    def get_prompt(self):
        """Dynamically create the prompt"""
        if self.current_module:
            mod_name = self.current_module.name.split('/')[-1]
            return [
                ('class:prompt.main', 'crypto '),
                ('class:prompt.module', f'({mod_name})'),
                ('class:prompt.main', ' > '),
            ]
        else:
            return [('class:prompt.main', 'crypto > ')]

    def get_bottom_toolbar(self):
        """Dynamically create the bottom toolbar"""
        if self.current_module:
            return f"Module: {self.current_module.name} | {self.current_module.description}"
        else:
            return "CryptoSwissKnife v2.20 | No module selected"
            
    def get_key_bindings(self):
        """Setup custom keybindings (e.g., Ctrl+C, Ctrl+D)"""
        kb = KeyBindings()

        @kb.add('c-c')
        def _(event):
            """Handle Ctrl+C (NOW EXITS)"""
            pass

        return kb
    
    def _find_module_full_name(self, search_name: str) -> (Optional[str], Optional[str]):
        """Finds a module's full name from its short name"""
        if '/' in search_name:
            if search_name in self.modules:
                return search_name, None
            else:
                return None, f"{Colors.FAIL}[-] Module '{search_name}' not found{Colors.ENDC}"

        matches = []
        for full_name in self.modules:
            short_name = full_name.split('/')[-1]
            if short_name == search_name:
                matches.append(full_name)
        
        if len(matches) == 1:
            return matches[0], None
        elif len(matches) > 1:
            error_msg = f"{Colors.FAIL}[-] Ambiguous module name '{search_name}'. Found multiple matches:{Colors.ENDC}\n"
            for name in matches:
                error_msg += f"    - {name}\n"
            error_msg += f"{Colors.WARNING}[!] Please use the full path to be specific.{Colors.ENDC}"
            return None, error_msg
        else:
            return None, f"{Colors.FAIL}[-] Module '{search_name}' not found{Colors.ENDC}"
        
    def _execute_command(self, line: str):
        """Parse and execute a command"""
        
        if line is None:
            return
        if not line.strip():
            return
            
        try:
            parts = shlex.split(line)
        except ValueError as e:
            print(f"{Colors.FAIL}[-] Syntax Error: {e}{Colors.ENDC}")
            return
            
        command = parts[0].lower()
        args = parts[1:]
        
        if command == 'help':
            self._handle_help(args)
        elif command == 'banner':
            print(self.intro)
        elif command == 'use':
            self._handle_use(args)
        elif command == 'info':
            self._handle_info(args)
        elif command == 'set':
            self._handle_set(args)
        elif command == 'run':
            self._handle_run(args)
        elif command == 'back':
            self._handle_back(args)
        elif command == 'show':
            if not args:
                print(f"{Colors.WARNING}[!] Usage: show <modules|options>{Colors.ENDC}")
                return
            sub_command = args[0]
            if sub_command == 'options':
                self._handle_show_options(args[1:])
            elif sub_command == 'modules':
                self._handle_show_modules(args[1:])
            else:
                print(f"{Colors.FAIL}[-] Unknown 'show' command: {sub_command}{Colors.ENDC}")
                print(f"{Colors.WARNING}[!] Usage: show <modules|options>{Colors.ENDC}")
        elif command == 'search':
            self._handle_search(args)
        elif command == 'clear':
            os.system('clear' if os.name != 'nt' else 'cls')
        elif command == 'version':
            self._handle_version(args)
        elif command == 'exit' or command == 'quit':
            raise EOFError
        else:
            print(f"{Colors.FAIL}[-] Unknown command: {command}{Colors.ENDC}")

    
    def _handle_help(self, args):
        """Display help message in a table"""
        table = Table(title="CryptoSwissKnife Core Commands", show_header=True, header_style="bold magenta")
        table.add_column("Command", style="cyan", no_wrap=True)
        table.add_column("Description", style="green")
        
        help_text = {
            'help': 'Show this help menu',
            'use <module>': 'Select a module (e.g., use caesar)',
            'show modules': 'List all available modules',
            'show options': 'Show options for the *current* module',
            'info <module>': 'Show detailed info for a specific module (e.g., info aes)',
            'search <keyword>': 'Search for modules',
            'set <OPTION> <VALUE>': 'Set an option value (e.g., set TEXT "Hello")',
            'run': 'Execute the current module',
            'back': 'Deselect the current module',
            'banner': 'Display the welcome banner',
            'clear': 'Clear the screen',
            'version': 'Show version information',
            'exit / quit / Ctrl+D': 'Exit the console',
        }
        for cmd, desc in help_text.items():
            table.add_row(cmd, desc)
        
        self.console.print(table)
    
    def _handle_use(self, args):
        """Select a module to use (by short name ONLY)"""
        if not args:
            print(f"{Colors.WARNING}[!] Please specify a module{Colors.ENDC}")
            return
        
        search_name = args[0]
        full_name, error_msg = self._find_module_full_name(search_name)

        if error_msg:
            print(error_msg)
            return
        
        self.current_module = self.modules[full_name]()
        print(f"{Colors.OKGREEN}[+] Module '{full_name}' loaded{Colors.ENDC}")

    def _handle_info(self, args):
        """Display detailed information about a module."""
        if not args:
            print(f"{Colors.WARNING}[!] Please specify a module.{Colors.ENDC}")
            print("Usage: 'info <module_name>' (e.g., info caesar)")
            return

        search_name = args[0]
        full_name, error_msg = self._find_module_full_name(search_name)
        
        if error_msg:
            print(error_msg)
            return

        module_instance = self.modules[full_name]()
        print(f"\n{Colors.BOLD}Detailed Info for: {full_name}{Colors.ENDC}")
        self.console.print(Padding(module_instance.detailed_description.strip(), (1, 4)))

    def _handle_show_options(self, args):
        """Show options for the current module"""
        if self.current_module:
            self.console.print(self.current_module.info())
        else:
            print(f"{Colors.WARNING}[!] No module selected. Use 'use <module>' first.{Colors.ENDC}")

    def _handle_set(self, args):
        """Set an option value"""
        if not self.current_module:
            print(f"{Colors.WARNING}[!] No module selected. Use 'use <module>' first{Colors.ENDC}")
            return
        
        if len(args) < 2:
            print(f"{Colors.WARNING}[!] Usage: set <OPTION> <VALUE>{Colors.ENDC}")
            return
        
        option = args[0].upper()
        value = ' '.join(args[1:])
        
        if self.current_module.set_option(option, value):
            print(f"{Colors.OKGREEN}[+] {option} => {value}{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}[-] Unknown option '{option}'{Colors.ENDC}")

    def _handle_run(self, args):
        """Execute the current module"""
        if not self.current_module:
            print(f"{Colors.WARNING}[!] No module selected. Use 'use <module>' first{Colors.ENDC}")
            return
        
        print(f"{Colors.OKCYAN}[*] Running module...{Colors.ENDC}")
        result = self.current_module.run()
        print(result)

    def _handle_back(self, args):
        """Deselect the current module"""
        if self.current_module:
            self.current_module = None
            print(f"{Colors.OKGREEN}[+] Module deselected{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}[!] No module currently selected{Colors.ENDC}")

    def _handle_show_modules(self, args):
        """Show available modules (reverted to full path)"""
        table = Table(title="Available Modules", show_header=True, header_style="bold magenta")
        table.add_column("Module Path", style="cyan", no_wrap=True)
        table.add_column("Description", style="green")
        
        categories = {}
        for module_name, module_class in self.modules.items():
            category = module_name.split('/')[0]
            if category not in categories:
                categories[category] = []
            categories[category].append((module_name, module_class().description))
        
        for category in sorted(categories.keys()):
            table.add_section()
            for module_name, desc in sorted(categories[category]):
                table.add_row(module_name, desc)
        
        self.console.print(table)
        self.console.print(f"\nTotal modules: {len(self.modules)}")

    def _handle_search(self, args):
        """Search for modules"""
        if not args:
            print(f"{Colors.WARNING}[!] Please specify a search keyword{Colors.ENDC}")
            return
        
        keyword = args[0]
        table = Table(title=f"Search Results for '{keyword}'", show_header=True, header_style="bold magenta")
        table.add_column("Module", style="cyan", no_wrap=True)
        table.add_column("Category", style="yellow")
        table.add_column("Description", style="green")

        found_count = 0
        module_list = []
        for full_name, module_class in self.modules.items():
            short_name = full_name.split('/')[-1]
            category = full_name.split('/')[0]
            desc = module_class().description
            
            if keyword.lower() in short_name.lower() or keyword.lower() in category.lower() or keyword.lower() in desc.lower():
                module_list.append((short_name, category, desc))
                found_count += 1
        
        if found_count > 0:
            for short_name, category, desc in sorted(module_list):
                table.add_row(short_name, category, desc)
            self.console.print(table)
        else:
            print(f"{Colors.WARNING}[!] No modules found matching '{keyword}'{Colors.ENDC}")

    def _handle_version(self, args):
        """Display version information"""
        print(f"\n{Colors.BOLD}CryptoSwissKnife v2.20 (Asymmetric Modules){Colors.ENDC}")
        print("Author: CryptoSwissKnife Team")
        print(f"Python Version: {sys.version.split()[0]}")
        print(f"Workspace: {self.workspace}\n")

    def main_loop(self):
        """
        The new main loop, replacing cmdloop().
        """
        print(self.intro)
        
        while True:
            try:
                line = self.session.prompt(
                    self.get_prompt,
                    bottom_toolbar=self.get_bottom_toolbar,
                    refresh_interval=0.5
                )
                self._execute_command(line)
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[!] Command cancelled.{Colors.ENDC}")
                continue
            except EOFError:
                print(f"\n{Colors.OKGREEN}[+] Thanks for using CryptoSwissKnife!{Colors.ENDC}")
                break
            except Exception as e:
                print(f"{Colors.FAIL}[-] An unexpected error occurred: {e}{Colors.ENDC}")

def main():
    """Main entry point"""
    try:
        console = CryptoConsole()
        console.main_loop()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()