#!/usr/bin/env python
from binstruct2 import *
from elf_exceptions import *

class ELF_e_ident(BinStruct):
    __DEFINE_STRUCT__ = """
        uint8 EI_MAG[4];
        uint8 EI_CLASS;   
        uint8 EI_DATA;    
        uint8 EI_VERSION; 
        uint8 EI_OSABI;   
        uint8 EI_ABIVERSION;
        uint8 _padding[7];
    """
assert(len(ELF_e_ident)==16)

## size = 52 for 32-bit
#
# ELF_e_ident    	e_ident;
class ELF32_Ehdr(BinStruct):
    __DEFINE_STRUCT__ = """
        uint8       EI_MAG[4];
        uint8       EI_CLASS;   
        uint8       EI_DATA;    
        uint8       EI_VERSION; 
        uint8       EI_OSABI;   
        uint8       EI_ABIVERSION;
        uint8       _padding[7];
        uint16		e_type;
        uint16		e_machine;
        uint32		e_version;
        uint32		e_entry;
        uint32		e_phoff;
        uint32		e_shoff;
        uint32		e_flags;
        uint16		e_ehsize;
        uint16		e_phentsize;
        uint16		e_phnum;
        uint16		e_shentsize;
        uint16		e_shnum;
        uint16		e_shstrndx;
    """
assert(len(ELF32_Ehdr)==52)

class ELF32_ProgramHeader(BinStruct):
    __DEFINE_STRUCT__ = """
        uint32      p_type;
        uint32      p_offset;
        uint32      p_vaddr;
        uint32      p_paddr;
        uint32      p_filesz;
        uint32      p_memsz;
        uint32      p_flags;
        uint32      p_align;
    """
assert(len(ELF32_ProgramHeader)==32)

class ELF32_SectionHeader(BinStruct):
    __DEFINE_STRUCT__ = """
        uint32      sh_name;
        uint32      sh_type;
        uint32      sh_flags;
        uint32      sh_addr;
        uint32      sh_offset;
        uint32      sh_size;
        uint32      sh_link;
        uint32      sh_info;
        uint32      sh_addralign;
        uint32      sh_entsize;
    """
