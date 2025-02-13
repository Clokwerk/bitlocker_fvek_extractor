import mmap
import argparse
import os
import sys


SIGNATURE_DB = [
    {
        'sig': b'\x83\x64\x24\x30\x00\x44\x8b\x4c\x24\x48\x48\x8b\x0d',
        'os': 'Windows Vista/7/8/10/11',
        'arch': 'x64',
        'build_range': 'NT6+',
    },
    {
        'sig': b'\x83\x64\x24\x30\x00\x44\x8b\x4d\xd8\x48\x8b\x0d',
        'os': 'Windows 8.1/10',
        'arch': 'x64',
        'build_range': 'WIN_BLUE+',
    },
    {
        'sig': b'\x83\x64\x24\x30\x00\x48\x8d\x45\xe0\x44\x8b\x4d\xd8\x48\x8d\x15',
        'os': 'Windows 10/11',
        'arch': 'x64',
        'build_range': 'WIN_10_1809+',
    },
    {
        'sig': b'\x6a\x02\x6a\x10\x68',
        'os': 'Windows Vista/7/8/10',
        'arch': 'x86',
        'build_range': 'NT6+',
    },
    
]



bitlocker_encryption_mode_headers = {
"AES-CBC 128-bit encryption with Elephant Diffuser":'00 80',
"AES-CBC 256-bit encryption with Elephant Diffuser":'01 80',
"AES-CBC 128-bit encryption":'02 80',
"AES-CBC 256-bit encryption":'03 80',
"AES-XTS 128-bit encryption":'04 80'
}

bitlocker_memory_pool_tags = [ b'dFVE',
b'FVE?',
b'FVE0',
b'FVEc',
b'FVE1',
b'FVEp',
b'FVEr',
b'FVEv',
b'FVEw',
b'FVEx',
b'Cngb'
]

def lsass_key_signature_search(file_path):
    with open(file_path, 'rb') as f:
        # Memory-map the file, accessing it as bytes
        mmapped_file = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        for signature in SIGNATURE_DB:
            pos = mmapped_file.find(signature['sig'])
            if pos != -1:
                print("Potential Windows OS version identified!")
                print(signature['os'] + " "+signature['arch'] + " "+signature['build_range'])
                return signature
        mmapped_file.close()
    print("Could not determine Windows OS version")
    return -1

def get_key_from_value(dictionary, target_value):
    for key, value in dictionary.items():
        if value == target_value:
            return key
    return None  # Return None if value not found

def find_memory_pool_tag_in_dump(file_path, memory_pool_tag):
    """
    Searches for all occurrences of a Windows memory pool tag in a binary file and returns its position.
    
    :param file_path: Path to the binary file
    :param memory pool tag: Memory pool tag to search for (must be bytes)
    :return: List of occurences of memory pool tag in binary file.
    """
    # Open the file and memory-map it
    with open(file_path, 'rb') as f:
        # Memory-map the file, accessing it as bytes
        mmapped_file = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        
        # Initialize the starting position for the search
        start_pos = 0
        positions = []
        
        while True:
            # Find the next occurrence of the memory pool tag
            pos = mmapped_file.find(memory_pool_tag, start_pos)
            if pos == -1:
                break
            positions.append(pos)
            # Update the starting position to search for the next occurrence
            start_pos = pos + len(memory_pool_tag)
        
        # Close the memory-mapped file
        mmapped_file.close()
    
    return positions

def fvek_pattern_search(file_path,positions,bitlocker_header_value):

    bitlocker_header  = bytes.fromhex(bitlocker_header_value)
    key_copy_size = 66
    if bitlocker_header_value == '00 80' or bitlocker_header_value == '02 80' or bitlocker_header_value == '04 80':
        key_copy_size = 36

    
    with open(file_path, 'rb') as f:
        # Memory-map the file, accessing it as bytes
        mmapped_file = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        
        for x in positions:
            search_region = mmapped_file[x:x+100].find(bitlocker_header)
            if search_region != -1:
                fvek = mmapped_file[x+search_region:x+search_region+36].hex()
                fvek = bitlocker_header_value.replace(" ","") + fvek[8:]
                return fvek
            
        mmapped_file.close()
        
    return -1


def main():
     # Set up argument parser with flag-based argument
     parser = argparse.ArgumentParser(description='Process a file given its path.')
     parser.add_argument('-f', '--file', 
                       required=True,
                       help='Path to the input file (required)')
     args = parser.parse_args()

     # Validate file existence
     if not os.path.isfile(args.file):
         print(f"Error: '{args.file}' is not a valid file or does not exist.", file=sys.stderr)
         sys.exit(1)
     
     file_path = args.file
     signature = lsass_key_signature_search(file_path)
     position = -1
     if signature != -1:
         if signature['os'] == 'Windows 10/11' and signature['build_range'] == 'WIN_10_1809+' and signature['arch'] == 'x64':
             position = find_memory_pool_tag_in_dump(file_path, bitlocker_memory_pool_tags[0])
         elif signature['os'] == 'Windows 8.1/10' and signature['build_range'] == 'WIN_BLUE+' and signature['arch'] == 'x64':
             #TO-DO
             position = -1
         elif signature['os'] == 'Windows Vista/7/8/10/11' and signature['build_range'] == 'NT6+' and signature['arch'] == 'x64':
             #TO-DO
             position = -1
         elif signature['os'] == 'Windows Vista/7/8/10/11' and signature['build_range'] == 'NT6+' and signature['arch'] == 'x86':
             #TO-DO
             position = -1
          

         if position != -1:
                 for x in bitlocker_encryption_mode_headers.values():
                     fvek_search_result = fvek_pattern_search(file_path,position,x)
                     if fvek_search_result != -1:
                         print("Potential key found: " + fvek_search_result)
                         bitlocker_mode = get_key_from_value(bitlocker_encryption_mode_headers,x)
                         print("BitLocker encryption mode: " + bitlocker_mode)
                         break
     else:
          print("Cannot identify Windows version from dump. Aborting!")

if __name__ == "__main__":
    main()


 