#!/usr/bin/env python
import sys, os
from elf import *
# sys.path[0:0] = ['.', '..']


if __name__ == '__main__':
    if len(sys.argv)==3:
        input_dir = sys.argv[1]
        filename  = sys.argv[2]
        #print('Processing file:', filename)
        #with open(filename, 'rb') as f:
        elffile=ELFAssembler(input_dir)
        elffile.read_segments_info()
        elffile.read_sections_info()
        elffile.update_data()
        elffile.write(filename)
        print("done...")
    else:
        print("Incorrect params. Usage:")
        print("elf_parser.py <input_folder> <output_file>")
