#====== SC send BY > VASCO 
#====== TELIGERM : H2 VASCO 

import base64
import zlib
import gzip
import marshal
import pickle
import json
import binascii
import uu
import quopri
import bz2
import lzma
import struct
import re
import os
import sys
import time
import tempfile
import subprocess
import ast
from io import BytesIO
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

# Define 7 colors for the rainbow effect
RAINBOW_COLORS = [
    Fore.RED,
    Fore.YELLOW,
    Fore.GREEN,
    Fore.CYAN,
    Fore.BLUE,
    Fore.MAGENTA,
    Fore.WHITE 
]

def rainbow_print(text):
    """Prints text with a 7-color rainbow effect, cycling through characters."""
    colored_text = ""
    for i, char in enumerate(text):
        if char == '\n':
            colored_text += char
            continue
        color = RAINBOW_COLORS[i % len(RAINBOW_COLORS)]
        colored_text += color + char
    print(colored_text)

# Python version magic numbers (Used for both decompilation and compilation)
MAGIC_NUMBERS = {
    '3.6': b'3\r\r\n\x8bq\x98d\x0c\x00\x00\x00\xe3\x00\x00\x00',
    '3.7': b'B\r\r\n\x00\x00\x00\x00\x8bq\x98d\x0c\x00\x00\x00',
    '3.8': b'U\r\r\n\x00\x00\x00\x00\tq\x98d\x0b\x00\x00\x00',
    '3.9': b'a\r\r\n\x00\x00\x00\x00\tq\x98d\x0b\x00\x00\x00',
    '3.10': b'o\r\r\n\x00\x00\x00\x00\tq\x98d\x0b\x00\x00\x00',
    '3.11': b'\xa7\r\r\n\x00\x00\x00\x00\x04\x94\x90d\xd4`\x00\x00',
    '3.12': b'\xcb\r\r\n\x00\x00\x00\x00\tq\x98d\x0b\x00\x00\x00',
    '3.13': b'\xee\r\r\n\x00\x00\x00\x00*\x80\xb4e\x0b\x00\x00\x00'
}

# --- Display Functions (Modified to keep rainbow ONLY in banner ASCII art) ---

def display_banner():
    """Display colorful banner using rainbow effect ONLY for ASCII art."""
    banner = f"""
██╗   ██╗ █████╗ ███████╗ ██████╗ ██████╗ 
██║   ██║██╔══██╗██╔════╝██╔════╝██╔═══██╗
██║   ██║███████║███████╗██║     ██║   ██║
╚██╗ ██╔╝██╔══██║╚════██║██║     ██║   ██║
 ╚████╔╝ ██║  ██║███████║╚██████╗╚██████╔╝
  ╚═══╝  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ \x1b[1;92m[\x1b[1;97mV 0.2 \x1b[1;31mFIXED\x1b[1;92m]
    """
    # Only the ASCII art uses rainbow_print
    rainbow_print(banner)

    # Rest of the info remains static colored
    print(f"\033[1;32m──────────────────────────────────────────────────")
    print(f"\033[1;32m[\033[1;31m✓\033[1;32m] AUTHOR    : HAMIDUL ")
    print(f"\033[1;32m[\033[1;31m✓\033[1;32m] GITHUB    : MDHAMIDUL30")
    print(f"\033[1;32m[\033[1;31m✓\033[1;32m] STATUS    : \033[1;36mACTIVE (FIXED)")
    print(f"\033[1;32m[\033[1;31m✓\033[1;32m] TOOL TYPE : \033[1;33mpython Decode ")
    print(f"\033[1;32m[\033[1;31m✓\033[1;32m] VERSION   : \033[1;34m0.2 \033[1;34mPAID (Compiled)")
    print(f"\033[1;32m──────────────────────────────────────────────────")


def display_menu():
    # Using static color for menu borders and titles
    print(f"\n{Fore.CYAN}╔══════════════════════════════ MAIN MENU ══════════════════════════════╗")
    print(f"{Fore.CYAN}║                                                              ║")
    print(f"{Fore.CYAN}║  {Fore.WHITE}[1]  {Fore.GREEN}Decode Base64                    {Fore.WHITE}[2]  {Fore.GREEN}Decode Base32    {Fore.CYAN}║")
    print(f"{Fore.CYAN}║  {Fore.WHITE}[3]  {Fore.GREEN}Decode Base16/Hex                {Fore.WHITE}[4]  {Fore.GREEN}Decode Marshal   {Fore.CYAN}║")
    print(f"{Fore.CYAN}║  {Fore.WHITE}[5]  {Fore.GREEN}Decode Zlib                      {Fore.WHITE}[6]  {Fore.GREEN}Decode Gzip      {Fore.CYAN}║")
    print(f"{Fore.CYAN}║  {Fore.WHITE}[7]  {Fore.GREEN}Decode Lzma                      {Fore.WHITE}[8]  {Fore.GREEN}Decode BZ2       {Fore.CYAN}║")
    print(f"{Fore.CYAN}║  {Fore.WHITE}[9]  {Fore.GREEN}Decode Pickle                    {Fore.WHITE}[10] {Fore.GREEN}Decode UU        {Fore.CYAN}║")
    print(f"{Fore.CYAN}║  {Fore.WHITE}[11] {Fore.GREEN}Decode Quoted-Printable          {Fore.WHITE}[12] {Fore.GREEN}Decode JSON      {Fore.CYAN}║")
    print(f"{Fore.CYAN}║  {Fore.WHITE}[13] {Fore.GREEN}Auto Detect All Layers           {Fore.WHITE}[14] {Fore.GREEN}Decompile Pyc    {Fore.CYAN}║")
    print(f"{Fore.CYAN}║  {Fore.WHITE}[15] {Fore.GREEN}Full Obfuscation Decode + Pyc    {Fore.WHITE}[16] {Fore.GREEN}Source to Bytecode (.pyc){Fore.CYAN}║") 
    print(f"{Fore.CYAN}║  {Fore.WHITE}[99] {Fore.RED}Exit                             {Fore.CYAN}║")
    print(f"{Fore.CYAN}║                                                              ║")
    # Using static color for bottom border
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════╝")

def display_loading(message):
    """Display loading animation using a static color."""
    print(f"\n{Fore.YELLOW}⏳ {message}", end="", flush=True)
    for i in range(3):
        time.sleep(0.1)
        print(f"{Fore.YELLOW}.", end="", flush=True)
    print()

def display_success(message):
    """Display success message (Green)"""
    print(f"{Fore.GREEN}✅ {message}")

def display_error(message):
    """Display error message (Red)"""
    print(f"{Fore.RED}❌ {message}")

def display_warning(message):
    """Display warning message (Yellow)"""
    print(f"{Fore.YELLOW}⚠️  {message}")

# --- File/Input/Output Functions ---

def get_file_input_with_selector():
    """Get file input from user with file selector"""
    py_files = [f for f in os.listdir('.') if os.path.isfile(f) and f.endswith(('.py', '.pyc', '.txt', '.dat'))] 
    
    if not py_files:
        display_warning(f"No processable files found in the current directory ({os.getcwd()}).")
        print(f"\n{Fore.CYAN}📁 Please enter your filename manually:")
        filename = input(f"{Fore.WHITE}➤ {Fore.GREEN}").strip()
        return filename

    # Using static color for file selection border
    print(f"\n{Fore.CYAN}╔════════════════════════════ SELECT FILE ════════════════════════════╗")
    for i, file in enumerate(py_files):
        print(f"{Fore.CYAN}║  {Fore.WHITE}[{i+1}]  {Fore.GREEN}{file:<53}{Fore.CYAN}║")
    print(f"{Fore.CYAN}║  {Fore.WHITE}[0]  {Fore.RED}Enter filename manually  {Fore.CYAN}║")
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════╝")

    while True:
        try:
            choice = input(f"\n{Fore.CYAN}🎯 Enter the number of the file to process (0-{len(py_files)}): {Fore.GREEN}").strip()
            
            if choice == '0':
                print(f"\n{Fore.CYAN}📁 Please enter your filename manually:")
                filename = input(f"{Fore.WHITE}➤ {Fore.GREEN}").strip()
                return filename
            
            file_index = int(choice) - 1
            if 0 <= file_index < len(py_files):
                return py_files[file_index]
            else:
                display_error("Invalid number. Please try again.")
        except ValueError:
            display_error("Invalid input. Please enter a number.")


def get_output_filename(default_extension=""):
    """Get output filename from user"""
    print(f"\n{Fore.CYAN}💾 Please enter output filename (e.g., output{default_extension}):")
    output_file = input(f"{Fore.WHITE}➤ {Fore.GREEN}").strip()
    return output_file

def read_file(filename):
    """Read file content (always read as binary)"""
    try:
        with open(filename, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        display_error(f"File '{filename}' not found.")
        return None
    except Exception as e:
        display_error(f"Error reading file: {e}")
        return None

def save_result(result, filename):
    """Save result to file"""
    try:
        if isinstance(result, bytes):
            with open(filename, 'wb') as f:
                f.write(result)
        else:
            output_content = str(result)
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(output_content)
        display_success(f"Result saved to {filename}")
        return True
    except Exception as e:
        display_error(f"Error saving file: {e}")
        return False

# --- New Conversion Function ---

def compile_to_pyc(source_code, python_version='3.8'):
    """Compile Python source code (string or bytes) into a valid .pyc byte stream (modern header format)."""
    if isinstance(source_code, bytes):
        source_code = source_code.decode('utf-8')
    
    try:
        code_object = compile(source_code, '<string>', 'exec')
    except Exception as e:
        raise Exception(f"Compilation failed: {e}")

    marshaled_code = marshal.dumps(code_object)
    
    pyc_constant = MAGIC_NUMBERS.get(python_version, MAGIC_NUMBERS['3.8'])
    magic_prefix = pyc_constant[:4]
    
    bit_field = struct.pack('<L', 0)
    
    timestamp = int(time.time())
    timestamp_bytes = struct.pack('<L', timestamp)
    
    source_size = len(source_code.encode('utf-8'))
    source_size_bytes = struct.pack('<L', source_size)
    
    pyc_header = magic_prefix + bit_field + timestamp_bytes + source_size_bytes
    
    return pyc_header + marshaled_code

# --- Existing Decompilation and Decoding Functions ---

def create_pyc_file(code_bytes, output_path, python_version='3.8'):
    """Create a valid Python .pyc file from code bytes"""
    if python_version in MAGIC_NUMBERS:
        pyc_header = MAGIC_NUMBERS[python_version]
    else:
        pyc_header = MAGIC_NUMBERS['3.8']
    
    with open(output_path, 'wb') as f:
        f.write(pyc_header)
        f.write(code_bytes)

def decompile_with_pycdc(pyc_path):
    """Decompile Python bytecode using pycdc"""
    try:
        pycdc_path = "pycdc"
        result = subprocess.run([pycdc_path, pyc_path], 
                              capture_output=True, text=True, timeout=90)
        
        if result.returncode == 0:
            return result.stdout
        else:
            if "not a supported pyc file" in result.stderr:
                 return "Decompilation failed: Not a supported Python bytecode format or version. (pycdc error)"
            if result.stdout and len(result.stdout) > 10:
                return result.stdout
            
            return f"Decompilation failed: {result.stderr.strip()}"
    except FileNotFoundError:
        return "pycdc not found. Please install it (e.g., 'pip install pycdc' or check system package manager)."
    except subprocess.TimeoutExpired:
        return "Decompilation timed out."
    except Exception as e:
        return f"Error during pycdc execution: {str(e)}"

def decode_base64(data):
    if isinstance(data, str): data = data.encode('utf-8')
    data = data.strip()
    missing_padding = len(data) % 4
    if missing_padding: data += b'=' * (4 - missing_padding)
    return base64.b64decode(data, validate=True)

def decode_base32(data):
    if isinstance(data, str): data = data.encode('utf-8')
    data = data.strip()
    missing_padding = len(data) % 8
    if missing_padding: data += b'=' * (8 - missing_padding)
    return base64.b32decode(data, casefold=True, validate=True)

def decode_base16(data):
    if isinstance(data, bytes): data = data.decode('utf-8').strip()
    data = data.replace('0x', '').replace('\\x', '')
    return bytes.fromhex(data)

def decode_gzip(data): return gzip.decompress(data)
def decode_zlib(data): return zlib.decompress(data)
def decode_bz2(data): return bz2.decompress(data)
def decode_lzma(data): return lzma.decompress(data)
def decode_marshal(data): return marshal.loads(data)
def decode_pickle(data): return pickle.loads(data)

def decode_uu(data):
    display_warning("UU Decoding with standard library can be unreliable/incomplete. Returning input data.")
    return data 

def decode_quopri(data): return quopri.decodestring(data)

def decode_json(data):
    if isinstance(data, bytes): data = data.decode('utf-8')
    return json.loads(data)

def extract_encoded_data(data_str):
    patterns = [
        r'exec\(\(_\)\(([^)]+)\)\)', r'\(_\)\(([^)]+)\)', 
        r'b64decode\(([^)]+)\)', r'\(([^)]+)\)\[::-1\]',
    ]
    for pattern in patterns:
        match = re.search(pattern, data_str, re.DOTALL)
        if match:
            extracted = match.group(1).strip()
            try:
                return ast.literal_eval(extracted)
            except:
                return extracted
    return None

def decode_lambda_obfuscation(data_str):
    display_loading("Decoding lambda obfuscation")
    encoded_data = extract_encoded_data(data_str)
    if encoded_data is None:
        display_error("Could not extract encoded data"); return None, "Extraction failed"
    display_warning(f"Extracted encoded data: {repr(encoded_data)[:100]}...")
    current_data = encoded_data
    if isinstance(current_data, str):
        try: current_data = current_data.encode('utf-8')
        except UnicodeEncodeError as e: display_error(f"Failed to encode extracted string: {e}. Aborting."); return None, "Encoding error"
    
    try:
        display_loading("Reversing string/bytes"); current_data = current_data[::-1]
        display_warning(f"After reverse: {repr(current_data)[:50]}...")
    except Exception as e:
        display_error(f"Reversing failed: {e}. Aborting."); return None, "Reversing failed"
    
    decoders = [("Base64", decode_base64), ("Zlib", decode_zlib), ("LZMA", decode_lzma), ("Gzip", decode_gzip)]
    for name, decoder_func in decoders:
        if not isinstance(current_data, bytes): break
        display_loading(f"Attempting to decode/decompress: {name}")
        should_try = True
        if name == "Zlib" and not (current_data.startswith(b'\x78') and len(current_data) > 2): should_try = False
        elif name == "LZMA" and not (current_data.startswith(b'\xfd7zXZ') or current_data.startswith(b']\x00\x00')): should_try = False
        elif name == "Gzip" and not current_data.startswith(b'\x1f\x8b'): should_try = False
        
        if not should_try and name in ["Zlib", "LZMA", "Gzip"]: display_warning(f"{name} magic bytes not found, skipping."); continue
            
        try:
            new_data = decoder_func(current_data)
            if new_data != current_data and len(new_data) > 0:
                current_data = new_data
                display_success(f"Successfully decoded {name}")
                display_warning(f"After {name}: {repr(current_data)[:50]}...")
        except Exception as e:
            display_warning(f"{name} decoding failed: {e}. Continuing.")

    if isinstance(current_data, bytes) and len(current_data) > 0:
        display_loading("Attempting to load Marshal data")
        try:
            marshal_loaded = decode_marshal(current_data)
            if isinstance(marshal_loaded, type(compile('1', 'a', 'exec'))):
                display_success("Detected Python code object after Marshal load.")
                try:
                    bytecode_payload = marshal.dumps(marshal_loaded)
                    return bytecode_payload, "Python bytecode detected (Marshal successful)"
                except Exception as e:
                    display_warning(f"Re-marshaling failed: {e}. Trying to use original data.")
                    return current_data, "Python bytecode detected (Marshal failed, returning raw bytes)"
            if isinstance(marshal_loaded, (bytes, str)): return marshal_loaded, "Lambda obfuscation fully decoded (via Marshal)"
            return repr(marshal_loaded), "Lambda obfuscation fully decoded (via Marshal object)"
            
        except Exception as e:
            display_warning(f"Marshal loading failed: {e}")
            is_bytecode_start = any(current_data.startswith(magic) for magic in MAGIC_NUMBERS.values())
            if is_bytecode_start:
                display_warning("Likely raw Python bytecode detected (Marshal failed).")
                return current_data, "Python bytecode detected (Raw bytes)"
            try:
                final_result = current_data.decode('utf-8')
                return final_result, "Final decoded text (Marshal failed)"
            except UnicodeDecodeError:
                return current_data, "Final decoded binary data (Marshal failed)"
    return current_data, "Decoding process finished"

def process_python_bytecode(bytecode_data):
    display_loading("Processing Python bytecode for decompilation")
    is_raw_code_object = not any(bytecode_data.startswith(magic) for magic in MAGIC_NUMBERS.values())
    if not is_raw_code_object: display_warning("Input data already contains Python bytecode header. Attempting to decompile directly.")
            
    with tempfile.NamedTemporaryFile(suffix='.pyc', delete=False) as tmp: temp_pyc = tmp.name
    decompiled_code = "Decompilation failed for all versions."
    versions_to_try = ['3.8', '3.9', '3.10', '3.11', '3.6', '3.7', '3.12', '3.13']
    
    for version in versions_to_try:
        try:
            if is_raw_code_object: create_pyc_file(bytecode_data, temp_pyc, version)
            else: 
                with open(temp_pyc, 'wb') as f: f.write(bytecode_data)
                    
            display_loading(f"Decompiling with pycdc (Python {version})")
            decompiled_code = decompile_with_pycdc(temp_pyc)
            
            if "Decompilation failed" not in decompiled_code and "Error" not in decompiled_code and len(decompiled_code) > 10:
                display_success(f"Successfully decompiled with Python {version}"); break
            else:
                display_warning(f"Decompilation failed for Python {version} (Output snippet: {decompiled_code.strip()[:50]}...)")
        except Exception as e:
            display_warning(f"Failed with Python {version}: {e}")
            continue
        finally:
            if os.path.exists(temp_pyc): os.unlink(temp_pyc)
    return decompiled_code

def decode_advanced_obfuscation(data):
    if not isinstance(data, bytes): return None, "Input must be bytes"
        
    try: data_str = data.decode('utf-8')
    except UnicodeDecodeError: data_str = None; display_error("Cannot decode bytes to string for pattern analysis. Trying direct pyc decompilation.")

    display_loading("Analyzing obfuscation patterns")
    
    is_bytecode_start = any(data.startswith(magic) for magic in MAGIC_NUMBERS.values())
    if is_bytecode_start:
        display_warning("Raw Python bytecode detected at input. Starting Pyc decompilation.")
        return process_python_bytecode(data), "Raw Pyc Decompilation"
    
    if data_str and "lambda" in data_str and ("exec" in data_str or "eval" in data_str):
        display_warning("Lambda-based obfuscation detected")
        result, status = decode_lambda_obfuscation(data_str)
        
        if isinstance(result, bytes) and len(result) > 20:
            display_warning(f"Detected potential final Python bytecode payload (Size: {len(result)} bytes). Attempting Pyc decompilation.")
            decompiled_code = process_python_bytecode(result)
            if decompiled_code: return decompiled_code, "Pyc decompilation successful after Lambda decode"
        
        return result, status
    
    if data_str: return data_str, "No supported obfuscation pattern detected (Text)"
    else: return data, "No supported obfuscation pattern detected (Binary)"


def auto_decode(data, depth=0, max_depth=20):
    if depth > max_depth: return repr(data), "Max depth reached"
    
    if isinstance(data, str): data_bytes = data.encode('utf-8', errors='ignore')
    elif isinstance(data, bytes): data_bytes = data
    else: return repr(data), "Object"

    methods = [("Base64", decode_base64), ("Base32", decode_base32), ("Gzip", decode_gzip), ("Zlib", decode_zlib), ("BZ2", decode_bz2), ("LZMA", decode_lzma), ("Pickle", decode_pickle), ("Marshal", decode_marshal)]
    
    for name, method in methods:
        try:
            should_try = True
            if name == "Gzip" and not data_bytes.startswith(b'\x1f\x8b'): should_try = False
            elif name == "Zlib" and not (data_bytes.startswith(b'\x78') and len(data_bytes) > 2): should_try = False
            elif name == "BZ2" and not data_bytes.startswith(b'BZh'): should_try = False
            elif name == "LZMA" and not
