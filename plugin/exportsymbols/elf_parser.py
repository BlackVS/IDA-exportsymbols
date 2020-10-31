#!/usr/bin/env python
import sys, os
from elf import *
# sys.path[0:0] = ['.', '..']


if __name__ == '__main__':
    if len(sys.argv)==3:
        filename = sys.argv[1]
        output_dir = sys.argv[2]
#        process_file0(filename)
        print('Processing file:', filename)
        with open(filename, 'rb') as f:
            elffile=ELFParser(f, output_dir, True)
            elffile.dump_program_headers(True)
            elffile.dump_section_headers(True)
            elffile.write_structure()
        print("done...")
    else:
        print("Incorrect params. Usage:")
        print("elf_parser.py <input_bin_file> <output_folder>")
