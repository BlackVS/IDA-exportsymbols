#!/usr/bin/python
# -*- coding: utf-8 -*-

#  Export symbols
#  2020 
#
#  Volodymyr Sydorenko <vvs [at] coders.in.ua>
#  www: coders.in.ua
#  git: github.com/BlackVS 
#       gitlab.com/BlackVS
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software  Foundation, either  version 3 of  the License, or
#  (at your option) any later version.


import os,sys

from exportsymbols.elf import *
from ctypes import *
from struct import unpack

DEBUG = False
PLUG_NAME    = "Export symbols to file"

sys.path.append('..\\python')
sys.path.append('..\\python\\lib\\python2.7\\lib-dynload\\ida_64')

import idc
import idaapi
import idautils


from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt

def dummy_breakpoint():
    return

BREAK = dummy_breakpoint
if DEBUG:
    import ptvsd
    try:
        ptvsd.enable_attach(address=('127.0.0.1', 5678))
        ptvsd.wait_for_attach()
        BREAK = ptvsd.break_into_debugger
    except:
        pass


LOG_ENABLE=True
def logger(arg):
    if LOG_ENABLE:
        print(arg)



###################################################################################################

def show_proc_info():
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        bits = 64
    elif info.is_32bit():
        bits = 32
    else:
        bits = 16

    try:
        is_be = info.is_be()
    except:
        is_be = info.mf
    endian = "big" if is_be else "little"

    print("Processor: {}, {}-bit, {} endian".format(info.procName, bits, endian))


###################################################################################################
#  ELF parser - based on the lib of ROPgadget tool by Jonathan Salwan
#  http://shell-storm.org/project/ROPgadget/
#  taken from https://github.com/danigargu/syms2elf

SHN_UNDEF = 0
STB_GLOBAL_FUNC = 0x12

class SHTypes:
    SHT_NULL      = 0
    SHT_PROGBITS  = 1
    SHT_SYMTAB    = 2
    SHT_STRTAB    = 3
    SHT_RELA      = 4
    SHT_HASH      = 5
    SHT_DYNAMIC   = 6
    SHT_NOTE      = 7
    SHT_NOBITS    = 8
    SHT_REL       = 9
    SHT_SHLIB     = 10
    SHT_DYNSYM    = 11
    SHT_NUM       = 12
    SHT_LOPROC    = 0x70000000
    SHT_HIPROC    = 0x7fffffff
    SHT_LOUSER    = 0x80000000
    SHT_HIUSER    = 0xffffffff

class ELFFlags:
    ELFCLASS32  = 0x01
    ELFCLASS64  = 0x02
    EI_CLASS    = 0x04
    EI_DATA     = 0x05
    ELFDATA2LSB = 0x01
    ELFDATA2MSB = 0x02
    EM_386      = 0x03
    EM_X86_64   = 0x3e
    EM_ARM      = 0x28
    EM_MIPS     = 0x08
    EM_SPARCv8p = 0x12
    EM_PowerPC  = 0x14
    EM_ARM64    = 0xb7

class SymFlags:
    STB_LOCAL   = 0
    STB_GLOBAL  = 1
    STB_WEAK    = 2
    STT_NOTYPE  = 0
    STT_OBJECT  = 1
    STT_FUNC    = 2
    STT_SECTION = 3
    STT_FILE    = 4
    STT_COMMON  = 5
    STT_TLS     = 6

class Elf32_Ehdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_uint),
                    ("e_phoff",         c_uint),
                    ("e_shoff",         c_uint),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]
 
class Elf64_Ehdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_ulonglong),
                    ("e_phoff",         c_ulonglong),
                    ("e_shoff",         c_ulonglong),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]

class Elf32_Phdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_offset",        c_uint),
                    ("p_vaddr",         c_uint),
                    ("p_paddr",         c_uint),
                    ("p_filesz",        c_uint),
                    ("p_memsz",         c_uint),
                    ("p_flags",         c_uint),
                    ("p_align",         c_uint)
                ]

class Elf64_Phdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_flags",         c_uint),
                    ("p_offset",        c_ulonglong),
                    ("p_vaddr",         c_ulonglong),
                    ("p_paddr",         c_ulonglong),
                    ("p_filesz",        c_ulonglong),
                    ("p_memsz",         c_ulonglong),
                    ("p_align",         c_ulonglong)
                ]

class Elf32_Shdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_uint),
                    ("sh_addr",         c_uint),
                    ("sh_offset",       c_uint),
                    ("sh_size",         c_uint),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_uint),
                    ("sh_entsize",      c_uint)
                ]

class Elf64_Shdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_ulonglong),
                    ("sh_addr",         c_ulonglong),
                    ("sh_offset",       c_ulonglong),
                    ("sh_size",         c_ulonglong),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_ulonglong),
                    ("sh_entsize",      c_ulonglong)
                ]

class Elf32_Ehdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_uint),
                    ("e_phoff",         c_uint),
                    ("e_shoff",         c_uint),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]
 
class Elf64_Ehdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_ulonglong),
                    ("e_phoff",         c_ulonglong),
                    ("e_shoff",         c_ulonglong),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]

class Elf32_Phdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_offset",        c_uint),
                    ("p_vaddr",         c_uint),
                    ("p_paddr",         c_uint),
                    ("p_filesz",        c_uint),
                    ("p_memsz",         c_uint),
                    ("p_flags",         c_uint),
                    ("p_align",         c_uint)
                ]

class Elf64_Phdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_flags",         c_uint),
                    ("p_offset",        c_ulonglong),
                    ("p_vaddr",         c_ulonglong),
                    ("p_paddr",         c_ulonglong),
                    ("p_filesz",        c_ulonglong),
                    ("p_memsz",         c_ulonglong),
                    ("p_align",         c_ulonglong)
                ]

class Elf32_Shdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_uint),
                    ("sh_addr",         c_uint),
                    ("sh_offset",       c_uint),
                    ("sh_size",         c_uint),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_uint),
                    ("sh_entsize",      c_uint)
                ]

class Elf64_Shdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_ulonglong),
                    ("sh_addr",         c_ulonglong),
                    ("sh_offset",       c_ulonglong),
                    ("sh_size",         c_ulonglong),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_ulonglong),
                    ("sh_entsize",      c_ulonglong)
                ]

class Elf32_Sym_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("st_name",         c_uint),
                    ("st_value",        c_uint),
                    ("st_size",         c_uint),
                    ("st_info",         c_ubyte),
                    ("st_other",        c_ubyte),
                    ("st_shndx",        c_ushort)
                ]

class Elf64_Sym_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("st_name",         c_uint),
                    ("st_info",         c_ubyte),
                    ("st_other",        c_ubyte),
                    ("st_shndx",        c_ushort),
                    ("st_value",        c_ulonglong),
                    ("st_size",         c_ulonglong)
                ]

class Elf32_Sym_MSB(BigEndianStructure):
    _fields_ =  [
                    ("st_name",         c_uint),
                    ("st_value",        c_uint),
                    ("st_size",         c_uint),
                    ("st_info",         c_ubyte),
                    ("st_other",        c_ubyte),
                    ("st_shndx",        c_ushort)
                ]

class Elf64_Sym_MSB(BigEndianStructure):
    _fields_ =  [
                    ("st_name",         c_uint),
                    ("st_info",         c_ubyte),
                    ("st_other",        c_ubyte),
                    ("st_shndx",        c_ushort),
                    ("st_value",        c_ulonglong),
                    ("st_size",         c_ulonglong)
                ]


""" This class parses the ELF """
class ELF:
    def __init__(self, binary):
        self.binary    = bytearray(binary)
        self.ElfHeader = None
        self.shdr_l    = []
        self.phdr_l    = []
        self.syms_l    = []
        self.e_ident   = self.binary[:15]
        self.ei_data   = unpack("<B", self.e_ident[ELFFlags.EI_DATA:ELFFlags.EI_DATA+1])[0] # LSB/MSB
        
        self.__setHeaderElf()
        self.__setShdr()
        self.__setPhdr()

    def is_stripped(self):
        if not self.get_symtab():
            return True
        if not self.get_strtab():
            return True
        return False

    def strip_symbols(self):        
        sh2delete = 2
        size2dec  = 0
        end_shdr  = self.ElfHeader.e_shoff + (self.sizeof_sh() * self.ElfHeader.e_shnum)

        symtab = self.get_symtab()
        strtab = self.get_strtab()

        if not symtab or not strtab:
            return False

        log("Stripping binary...")

        if symtab.sh_offset < end_shdr:
            size2dec += symtab.sh_size

        if strtab.sh_offset < end_shdr:
            size2dec += strtab.sh_size

        self.ElfHeader.e_shoff -= size2dec
        self.ElfHeader.e_shnum -= sh2delete

        e_shnum = self.ElfHeader.e_shnum
        e_shoff = self.ElfHeader.e_shoff
        sz_striped = (e_shoff + (e_shnum * self.sizeof_sh()))        

        if strtab.sh_offset > symtab.sh_offset:
            self.cut_at_offset(strtab.sh_offset, strtab.sh_size)  
            self.cut_at_offset(symtab.sh_offset, symtab.sh_size)
        else:
            self.cut_at_offset(symtab.sh_offset, symtab.sh_size)
            self.cut_at_offset(strtab.sh_offset, strtab.sh_size)

        self.binary = self.binary[0:sz_striped]
        self.write(0, self.ElfHeader)
        return True

    def get_symtab(self):
        shstrtab = bytes(self.get_shstrtab_data())
        for sh in self.shdr_l:
            sh_name = shstrtab[sh.sh_name:].split(b"\0")[0]
            if  sh.sh_type == SHTypes.SHT_SYMTAB and \
                (sh.sh_name == SHN_UNDEF or sh_name == ".symtab"):
                return sh
        return None

    def get_strtab(self):
        shstrtab = bytes(self.get_shstrtab_data())
        for sh in self.shdr_l:
            sh_name = shstrtab[sh.sh_name:].split(b"\0")[0]
            if  sh.sh_type == SHTypes.SHT_STRTAB and \
                (sh.sh_name == SHN_UNDEF or sh_name == ".strtab"):
                return sh
        return None

    def getArchMode(self):
        if self.ElfHeader.e_ident[ELFFlags.EI_CLASS] == ELFFlags.ELFCLASS32: 
            return 32
        elif self.ElfHeader.e_ident[ELFFlags.EI_CLASS] == ELFFlags.ELFCLASS64: 
            return 64
        else:
            log("[Error] ELF.getArchMode() - Bad Arch size")
            return None

    """ Parse ELF header """
    def __setHeaderElf(self):
        e_ident = self.binary[:15]

        ei_class = unpack("<B", e_ident[ELFFlags.EI_CLASS:ELFFlags.EI_CLASS+1])[0]
        ei_data  = unpack("<B", e_ident[ELFFlags.EI_DATA:ELFFlags.EI_DATA+1])[0]

        if ei_class != ELFFlags.ELFCLASS32 and ei_class != ELFFlags.ELFCLASS64:
            log("[Error] ELF.__setHeaderElf() - Bad Arch size")
            return None

        if ei_data != ELFFlags.ELFDATA2LSB and ei_data != ELFFlags.ELFDATA2MSB:
            log("[Error] ELF.__setHeaderElf() - Bad architecture endian")
            return None

        if ei_class == ELFFlags.ELFCLASS32: 
            if   ei_data == ELFFlags.ELFDATA2LSB: self.ElfHeader = Elf32_Ehdr_LSB.from_buffer_copy(self.binary)
            elif ei_data == ELFFlags.ELFDATA2MSB: self.ElfHeader = Elf32_Ehdr_MSB.from_buffer_copy(self.binary)
        elif ei_class == ELFFlags.ELFCLASS64: 
            if   ei_data == ELFFlags.ELFDATA2LSB: self.ElfHeader = Elf64_Ehdr_LSB.from_buffer_copy(self.binary)
            elif ei_data == ELFFlags.ELFDATA2MSB: self.ElfHeader = Elf64_Ehdr_MSB.from_buffer_copy(self.binary)

    """ Write the section header to self.binary """
    def write_shdr(self):
        off = self.ElfHeader.e_shoff
        for sh in self.shdr_l:
            self.write(off, sh)
            off += off + sizeof(sh) 

    """ Parse Section header """
    def __setShdr(self):
        shdr_num = self.ElfHeader.e_shnum
        base = self.binary[self.ElfHeader.e_shoff:]
        shdr_l = []

        e_ident = self.binary[:15]
        ei_data = unpack("<B", e_ident[ELFFlags.EI_DATA:ELFFlags.EI_DATA+1])[0]

        for i in range(shdr_num):
            if self.getArchMode() == 32:
                if   ei_data == ELFFlags.ELFDATA2LSB: shdr = Elf32_Shdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf32_Shdr_MSB.from_buffer_copy(base)
            elif self.getArchMode() == 64:
                if   ei_data == ELFFlags.ELFDATA2LSB: shdr = Elf64_Shdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf64_Shdr_MSB.from_buffer_copy(base)

            self.shdr_l.append(shdr)
            base = base[self.ElfHeader.e_shentsize:]

        string_table = self.binary[(self.shdr_l[self.ElfHeader.e_shstrndx].sh_offset):]
        for i in range(shdr_num):
            self.shdr_l[i].str_name = string_table[self.shdr_l[i].sh_name:].split(b'\0')[0]

    """ Parse Program header """
    def __setPhdr(self):
        pdhr_num = self.ElfHeader.e_phnum
        base = self.binary[self.ElfHeader.e_phoff:]
        phdr_l = []

        e_ident = self.binary[:15]
        ei_data = unpack("<B", e_ident[ELFFlags.EI_DATA:ELFFlags.EI_DATA+1])[0]

        for i in range(pdhr_num):
            if self.getArchMode() == 32:
                if   ei_data == ELFFlags.ELFDATA2LSB: phdr = Elf32_Phdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: phdr = Elf32_Phdr_MSB.from_buffer_copy(base)
            elif self.getArchMode() == 64:
                if   ei_data == ELFFlags.ELFDATA2LSB: phdr = Elf64_Phdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: phdr = Elf64_Phdr_MSB.from_buffer_copy(base)

            self.phdr_l.append(phdr)
            base = base[self.ElfHeader.e_phentsize:]

    def get_section_id(self, sh_name):
        for idx, sh in enumerate(self.shdr_l):
            if sh.str_name == sh_name.encode('ascii'):
                return idx
        return None

    def get_shstrtab_data(self):
        sh = self.shdr_l[self.ElfHeader.e_shstrndx]
        if sh.sh_type == SHTypes.SHT_STRTAB:
            return self.binary[sh.sh_offset:sh.sh_offset+sh.sh_size]
        return None

    def get_sym_at_offset(self, off):
        if self.getArchMode() == 32:
            if   ei_data == ELFFlags.ELFDATA2LSB: sym = Elf32_Sym_LSB.from_buffer_copy(self.binary[off:])
            elif ei_data == ELFFlags.ELFDATA2MSB: sym = Elf32_Sym_MSB.from_buffer_copy(self.binary[off:])
        elif self.getArchMode() == 64:
            if   ei_data == ELFFlags.ELFDATA2LSB: sym = Elf64_Sym_LSB.from_buffer_copy(self.binary[off:])
            elif ei_data == ELFFlags.ELFDATA2MSB: sym = Elf64_Sym_MSB.from_buffer_copy(self.binary[off:])
        return sym

    def get_entrypoint(self):
        return self.e_entry

    def sizeof_sh(self):
        size = None
        if self.getArchMode() == 32:
            size = sizeof(Elf32_Shdr_LSB())
        elif self.getArchMode() == 64:
            size = sizeof(Elf64_Shdr_LSB())
        return size

    def sizeof_sym(self):
        size = None
        if self.getArchMode() == 32:
            size = sizeof(Elf32_Sym_LSB)
        elif self.getArchMode() == 64:
            size = sizeof(Elf64_Sym_LSB)
        return size

    def append_section_header(self, section):
        sh = None

        if self.getArchMode() == 32:
            if   self.ei_data == ELFFlags.ELFDATA2LSB: sh = Elf32_Shdr_LSB()
            elif self.ei_data == ELFFlags.ELFDATA2MSB: sh = Elf32_Shdr_MSB()
        elif self.getArchMode() == 64:
            if   self.ei_data == ELFFlags.ELFDATA2LSB: sh = Elf64_Shdr_LSB()
            elif self.ei_data == ELFFlags.ELFDATA2MSB: sh = Elf64_Shdr_MSB()

        sh.sh_name      = section["name"]
        sh.sh_type      = section["type"]
        sh.sh_flags     = section["flags"]
        sh.sh_addr      = section["addr"]
        sh.sh_offset    = section["offset"]
        sh.sh_size      = section["size"]
        sh.sh_link      = section["link"]
        sh.sh_info      = section["info"]
        sh.sh_addralign = section["addralign"]
        sh.sh_entsize   = section["entsize"]

        self.binary.extend(sh)

    def append_symbol(self, symbol):
        if self.getArchMode() == 32:
            if   self.ei_data == ELFFlags.ELFDATA2LSB: sym = Elf32_Sym_LSB()
            elif self.ei_data == ELFFlags.ELFDATA2MSB: sym = Elf32_Sym_MSB()
        elif self.getArchMode() == 64:
            if   self.ei_data == ELFFlags.ELFDATA2LSB: sym = Elf64_Sym_LSB()
            elif self.ei_data == ELFFlags.ELFDATA2MSB: sym = Elf64_Sym_MSB()

        sym.st_name   = symbol["name"]
        sym.st_value  = symbol["value"]
        sym.st_size   = symbol["size"]
        sym.st_info   = symbol["info"]
        sym.st_other  = symbol["other"]
        sym.st_shndx  = symbol["shndx"]

        self.binary.extend(sym)

    def get_binary(self):
        return self.binary

    def write(self, offset, data):
        self.binary[offset:offset+sizeof(data)] = data

    def expand_at_offset(self, offset, data):
        self.binary = self.binary[:offset] + data + self.binary[offset:]

    def cut_at_offset(self, offset, size):
        self.binary = self.binary[:offset] + self.binary[offset+size:]

    def save(self, output):
        with open(output, 'wb') as f:
            f.write(self.binary)


###################################################################################################
def write_symbols(input_file, output_file, symbols):
    try:        
        with open(input_file, 'rb') as f:
            bin = ELF(f.read())

        if len(symbols) < 1:
            log("No symbols to export")
            return

        log("Exporting symbols to ELF...")
        bin.strip_symbols()

        # raw strtab
        strtab_raw = b"\x00" + b"\x00".join([sym_name.encode('ascii') for sym_name in symbols.keys()]) + b"\x00"

        symtab = {
            "name"      : SHN_UNDEF,
            "type"      : SHTypes.SHT_SYMTAB,
            "flags"     : 0,
            "addr"      : 0,
            "offset"    : len(bin.binary) + (bin.sizeof_sh() * (bin.ElfHeader.e_shnum + 2)),
            "size"      : (len(symbols) + 1) * bin.sizeof_sym(),
            "link"      : bin.ElfHeader.e_shnum + 1, # index of SHT_STRTAB
            "info"      : 1,
            "addralign" : 4,
            "entsize"   : bin.sizeof_sym()
        }

        off_strtab = (len(bin.binary) + (bin.sizeof_sh() * (bin.ElfHeader.e_shnum + 2)) + (bin.sizeof_sym() * (len(symbols) + 1)))

        strtab = {
            "name"      : SHN_UNDEF,
            "type"      : SHTypes.SHT_STRTAB,
            "flags"     : 0,
            "addr"      : 0,
            "offset"    : off_strtab,
            "size"      : len(strtab_raw),
            "link"      : 0,
            "info"      : 0,
            "addralign" : 1,
            "entsize"   : 0
        }

        shdrs = bin.binary[bin.ElfHeader.e_shoff:bin.ElfHeader.e_shoff + (bin.sizeof_sh() * bin.ElfHeader.e_shnum)]
        bin.ElfHeader.e_shnum += 2
        bin.ElfHeader.e_shoff = len(bin.binary)
        bin.write(0, bin.ElfHeader)
        bin.binary.extend(shdrs)

        base = bin.binary[bin.ElfHeader.e_shoff:]
        _off = bin.ElfHeader.e_shoff
        for i in range(bin.ElfHeader.e_shnum - 2):
            if bin.getArchMode() == 32:
                if   bin.ei_data == ELFFlags.ELFDATA2LSB: shdr = Elf32_Shdr_LSB.from_buffer_copy(base)
                elif bin.ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf32_Shdr_MSB.from_buffer_copy(base)
            elif bin.getArchMode() == 64:
                if   bin.ei_data == ELFFlags.ELFDATA2LSB: shdr = Elf64_Shdr_LSB.from_buffer_copy(base)
                elif bin.ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf64_Shdr_MSB.from_buffer_copy(base)
            base = base[bin.ElfHeader.e_shentsize:]
            bin.write(_off, shdr)
            _off += bin.sizeof_sh()
        bin.append_section_header(symtab)
        bin.append_section_header(strtab)

        # Local symbol - separator
        sym = {
            "name"  : 0,
            "value" : 0,
            "size"  : 0,
            "info"  : SymFlags.STB_LOCAL,
            "other" : 0,
            "shndx" : 0 
        }
        bin.append_symbol(sym)

        # add symbols  
        BREAK()
        for st_name, (st_type, st_ea, st_size, st_seg) in symbols.items():
            
            st_info = SymFlags.STB_GLOBAL << 4
            if st_type=="FUNC":
                st_info|=SymFlags.STT_FUNC
            elif st_type=="OBJECT":
                st_info|=SymFlags.STT_OBJECT
            else:
                st_info|=SymFlags.STT_NOTYPE
    

            sh_idx = bin.get_section_id(st_seg)
            if not sh_idx:
                log("ERROR: Section ID for '%s' not found" % st_seg)
                continue

            sym = {
                "name"  : strtab_raw.index(st_name.encode('ascii')),
                "value" : st_ea,
                "size"  : st_size,
                "info"  : st_info,
                "other" : 0,
                "shndx" : sh_idx
            }

            #log("0x%08x - 0x%08x - %s - %d/%d - %d" % (s.value, s.size, s.name, strtab_raw.index(s.name), len(strtab_raw), s.info))
            bin.append_symbol(sym)

        # add symbol strings
        bin.binary.extend(strtab_raw)

        log("ELF saved to: %s" % output_file)
        bin.save(output_file)

    except:
        log(traceback.format_exc())


def export2elf(filename, symbols):
    show_proc_info()
    input_file_name = idc.GetInputFile()
    input_file_type = idaapi.get_file_type_name(input_file_name)
    print("Input file type: {}".format(input_file_type))
    if  "ELF" not in input_file_type:
        msg("Only ELF input file supported!")
        return 

    write_symbols(input_file_name, filename, symbols)
    









###################################################################################################


IDAVIEW_FUNCTIONS = 1
IDAVIEW_NAMES     = 2
IDAVIEW_EXPORTS   = 3

OPTIONS_EXCLUDE_PRE_SUB = 1
OPTIONS_EXCLUDE_PRE_UNKNOWN = 2
OPTIONS_EXCLUDE_FUNCTIONS = 3
OPTIONS_EXCLUDE_DATA = 4

class Ui_ExportSymbols_Dialog(object):
    parent = None
    data_segments = None
    data_views = None
    data_options = None

    def setupUi(self, Dialog):
        self.parent=Dialog
        Dialog.setObjectName("Dialog")
        Dialog.resize(600, 400)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(Dialog.sizePolicy().hasHeightForWidth())
        Dialog.setSizePolicy(sizePolicy)
        Dialog.setMinimumSize(QtCore.QSize(600, 400))
        Dialog.setMaximumSize(QtCore.QSize(600, 400))
        Dialog.setModal(True)
        self.buttonBox = QtWidgets.QDialogButtonBox(Dialog)
        self.buttonBox.setGeometry(QtCore.QRect(420, 360, 161, 32))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.labelSegments = QtWidgets.QLabel(Dialog)
        self.labelSegments.setGeometry(QtCore.QRect(30, 10, 231, 16))
        self.labelSegments.setObjectName("labelSegments")
        self.groupViews2Export = QtWidgets.QGroupBox(Dialog)
        self.groupViews2Export.setGeometry(QtCore.QRect(380, 30, 201, 131))
        self.groupViews2Export.setObjectName("groupViews2Export")
        self.checkFunctions = QtWidgets.QCheckBox(self.groupViews2Export)
        self.checkFunctions.setGeometry(QtCore.QRect(20, 20, 70, 17))
        self.checkFunctions.setChecked(True)
        self.checkFunctions.setObjectName("checkFunctions")
        self.checkNames = QtWidgets.QCheckBox(self.groupViews2Export)
        self.checkNames.setGeometry(QtCore.QRect(20, 40, 70, 17))
        self.checkNames.setObjectName("checkNames")
        self.checkExports = QtWidgets.QCheckBox(self.groupViews2Export)
        self.checkExports.setGeometry(QtCore.QRect(20, 60, 70, 17))
        self.checkExports.setObjectName("checkExports")
        self.segmentsWidget = QtWidgets.QTableWidget(Dialog)
        self.segmentsWidget.setGeometry(QtCore.QRect(20, 31, 351, 281))
        self.segmentsWidget.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.segmentsWidget.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.segmentsWidget.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        #self.segmentsWidget.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.segmentsWidget.setGridStyle(QtCore.Qt.DashLine)
        self.segmentsWidget.setWordWrap(False)
        self.segmentsWidget.setRowCount(0)
        self.segmentsWidget.setColumnCount(3)
        self.segmentsWidget.setObjectName("segmentsWidget")
        self.segmentsWidget.horizontalHeader().setVisible(True)
        self.segmentsWidget.horizontalHeader().setCascadingSectionResizes(True)
        self.segmentsWidget.horizontalHeader().setSortIndicatorShown(False)
        self.segmentsWidget.horizontalHeader().setStretchLastSection(False)
        self.segmentsWidget.verticalHeader().setVisible(False)
        self.segmentsWidget.verticalHeader().setMinimumSectionSize(15)
        self.segmentsWidget.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

        self.groupOptions = QtWidgets.QGroupBox(Dialog)
        self.groupOptions.setGeometry(QtCore.QRect(380, 160, 201, 151))
        self.groupOptions.setObjectName("groupOptions")
        self.checkExcludeSub = QtWidgets.QCheckBox(self.groupOptions)
        self.checkExcludeSub.setGeometry(QtCore.QRect(10, 20, 171, 17))
        self.checkExcludeSub.setChecked(True)
        self.checkExcludeSub.setObjectName("checkExcludeSub")
        self.checkExcludeUnknown = QtWidgets.QCheckBox(self.groupOptions)
        self.checkExcludeUnknown.setGeometry(QtCore.QRect(10, 40, 181, 17))
        self.checkExcludeUnknown.setChecked(True)
        self.checkExcludeUnknown.setObjectName("checkExcludeUnknown")
        self.checkExcludeFuncs = QtWidgets.QCheckBox(self.groupOptions)
        self.checkExcludeFuncs.setGeometry(QtCore.QRect(10, 60, 181, 17))
        self.checkExcludeFuncs.setObjectName("checkExcludeFuncs")
        self.checkExcludeData = QtWidgets.QCheckBox(self.groupOptions)
        self.checkExcludeData.setGeometry(QtCore.QRect(10, 80, 181, 17))
        self.checkExcludeData.setObjectName("checkExcludeData")

        self.retranslateUi(Dialog)
        #self.buttonBox.accepted.connect(Dialog.accept)
        self.buttonBox.accepted.connect(self.accept_and_save_data)
        self.buttonBox.rejected.connect(Dialog.reject)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Export symbols"))
        self.labelSegments.setText(_translate("Dialog", "Segments to export"))
        self.groupViews2Export.setTitle(_translate("Dialog", "Symbols types to export"))
        self.checkFunctions.setToolTip(_translate("Dialog", "<html><head/><body><p>Export symbols from Functions IDA view</p></body></html>"))
        self.checkFunctions.setText(_translate("Dialog", "Functions"))
        self.checkNames.setToolTip(_translate("Dialog", "<html><head/><body><p>Export symbols from Names IDA view</p></body></html>"))
        self.checkNames.setText(_translate("Dialog", "Names"))
        self.checkExports.setToolTip(_translate("Dialog", "<html><head/><body><p>Export symbols from Exports IDA view</p></body></html>"))
        self.checkExports.setText(_translate("Dialog", "Exports"))
        self.segmentsWidget.setSortingEnabled(False)
        self.segmentsWidget.setHorizontalHeaderLabels( ["Name","Start","End"])
        self.segmentsWidget.setColumnWidth(0, self.segmentsWidget.width() / 2  )
        self.segmentsWidget.setColumnWidth(1, self.segmentsWidget.width() / 4  )
        self.segmentsWidget.setColumnWidth(2, self.segmentsWidget.width() / 4  )
        # palette = self.segmentsWidget.horizontalHeader().palette()
        # palette.setColor( QtGui.QPalette.Normal, QtGui.QPalette.Window, Qt.red )
        # self.segmentsWidget.horizontalHeader().setPalette( palette )
        self.groupOptions.setTitle(_translate("Dialog", "Options"))
        self.checkExcludeSub.setText(_translate("Dialog", "Exclude \"sub_*\""))
        self.checkExcludeUnknown.setText(_translate("Dialog", "Exclude \"unknown_*\""))
        self.checkExcludeFuncs.setText(_translate("Dialog", "Exclude functions"))
        self.checkExcludeData.setText(_translate("Dialog", "Exclude data"))

    def accept_and_save_data(self):
        logger("Saving data from dialog...")

        #print( self.segmentsWidget.item(0, 0).text() )
        self.data_segments = []
        #ptvsd.break_into_debugger()        
        for idx in range( self.segmentsWidget.rowCount() ):
            if self.segmentsWidget.item(idx, 0).checkState()!=QtCore.Qt.Checked:
                continue
            sname = self.segmentsWidget.item(idx, 0).text()
            saddr = self.segmentsWidget.item(idx, 1).text()
            send  = self.segmentsWidget.item(idx, 2).text()
            self.data_segments.append( (sname, saddr, send) )

        self.data_views = dict()
        self.data_views[IDAVIEW_FUNCTIONS] = self.checkFunctions.checkState() == QtCore.Qt.Checked
        self.data_views[IDAVIEW_NAMES] = self.checkNames.checkState() == QtCore.Qt.Checked
        self.data_views[IDAVIEW_EXPORTS] = self.checkExports.checkState() == QtCore.Qt.Checked


        self.data_options = dict()
        self.data_options[OPTIONS_EXCLUDE_DATA] = self.checkExcludeData.checkState() == QtCore.Qt.Checked
        self.data_options[OPTIONS_EXCLUDE_FUNCTIONS] = self.checkExcludeFuncs.checkState() == QtCore.Qt.Checked
        self.data_options[OPTIONS_EXCLUDE_PRE_SUB] = self.checkExcludeSub.checkState() == QtCore.Qt.Checked
        self.data_options[OPTIONS_EXCLUDE_PRE_UNKNOWN] = self.checkExcludeUnknown.checkState() == QtCore.Qt.Checked

        self.parent.accept()

class ExportSymbolsWidget(QtWidgets.QDialog):
    UNKNOWN_TYPE    = 0
    USER_TYPE       = 1
    STANDARD_TYPE   = 2
    LOCAL_TYPE      = 3

    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent)
        try:
            self.tinfo = None
            self.inputType = self.USER_TYPE
            logger('ExportSymbolsWidget starting up')
            self.ui = Ui_ExportSymbols_Dialog()
            self.ui.setupUi(self)
        except Exception as err:
            logger('Error during init: %s' % str(err))

    def LoadData(self):
        cnt = ida_segment.get_segm_qty()
        self.ui.segmentsWidget.setRowCount(cnt)
        for idx, s_ea in enumerate(idautils.Segments()):
            seg_name =idc.get_segm_name(s_ea)
            seg_start=idc.get_segm_start(s_ea)
            seg_end  =idc.get_segm_end(s_ea)-1
             
            item0 = QtWidgets.QTableWidgetItem()
            item0.setText(seg_name)
            item0.setFlags(QtCore.Qt.ItemIsUserCheckable | QtCore.Qt.ItemIsEnabled)
            item0.setCheckState(QtCore.Qt.Checked)
            self.ui.segmentsWidget.setItem(idx, 0, item0)

            item1 = QtWidgets.QTableWidgetItem()
            item1.setText( "0x{:04x}".format(seg_start))
            self.ui.segmentsWidget.setItem(idx, 1, item1)

            item2 = QtWidgets.QTableWidgetItem()
            item2.setText( "0x{:04x}".format(seg_end))
            self.ui.segmentsWidget.setItem(idx, 2, item2)

        self.ui.segmentsWidget.resizeRowsToContents()
        

    def get_segments(self):
        return self.ui.data_segments

    def get_views(self):
        return self.ui.data_views

    def get_options(self):
        return self.ui.data_options



class ExportSymsPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL #unload after each run, for debug. After - FIX
    comment = ""
    help = ""
    wanted_name = PLUG_NAME
    wanted_hotkey = "Ctrl+`"

    ida_segments = None
    ida_views = None
    ida_options = dict()
    
    exported_symbols = None

    def init(self):
        return idaapi.PLUGIN_OK #Plugin agrees to work with the current database but will be loaded only when it is about to be invoked.

    def run(self, arg=0):
        logger('Starting up')

        show_proc_info()

        try:
            dlg = ExportSymbolsWidget()
            dlg.LoadData()
            oldTo = idaapi.set_script_timeout(0)
            res = dlg.exec_()
            idaapi.set_script_timeout(oldTo)

            if res != QtWidgets.QDialog.Accepted:
                #logger('Dialog rejected')
                return
            #logger('Dialog accepted. Input type: %d' % dlg.inputType)

            fileName, fileExt = QtWidgets.QFileDialog.getSaveFileName(caption="Save file", filter = "Text file (*.txt);;ELF file (*.elf)")
            logger(fileName)
            if "ELF" in fileName:
                print("Output to ELF not yet supported")
                return

            #ptvsd.break_into_debugger()
            self.ida_segments = dlg.get_segments()
            self.ida_views    = dlg.get_views()
            self.ida_options  = dlg.get_options()
            
            self.exported_symbols = self.get_symbols_from_ida()

            #ptvsd.break_into_debugger()

            if ".txt" in fileExt:
                with open(fileName,"wt") as ft:
                    idx = 0
                    exclude_pre_sub = self.ida_options[OPTIONS_EXCLUDE_PRE_SUB]
                    exclude_pre_unknown = self.ida_options[OPTIONS_EXCLUDE_PRE_UNKNOWN]
                    exclude_functions = self.ida_options[OPTIONS_EXCLUDE_FUNCTIONS]
                    exclude_data = self.ida_options[OPTIONS_EXCLUDE_DATA]
                    for s_name, sdata in sorted(self.exported_symbols.items(), key=lambda a: a[1][1]):
                        if exclude_pre_sub and s_name.startswith("sub_"):
                            continue
                        if exclude_pre_unknown and s_name.startswith("unknown_"):
                            continue
                        s_type, s_start, s_size, s_seg = sdata[0], sdata[1], sdata[2], sdata[3]
                        if exclude_functions and s_type=="FUNC":
                            continue
                        if exclude_data and s_type=="OBJECT":
                            continue
                        ft.write("{:4} 0x{:04x} {:4} {:6} {:7} {:7} {:10} {}\n".format(idx, s_start, s_size, s_type, "GLOBAL", "DEFAULT", s_seg, s_name))
                        idx+=1
                    print("Finally wrote {} symbols. Some symbols could be skipped due to set options".format(idx))
            elif ".elf" in fileExt:
                export2elf(fileName, self.exported_symbols)

        except Exception as err:
            logger("Exception caught: %s" % str(err))

    def term(self):
        pass


    def get_symbols_from_ida(self):
        symbols = dict()
        segs = [ s[0] for s in self.ida_segments]

        if self.ida_views[IDAVIEW_FUNCTIONS] and not self.ida_options.get(OPTIONS_EXCLUDE_FUNCTIONS,False):
            for f in idautils.Functions():
                fn_seg = idc.SegName(f)
                if fn_seg not in segs:
                    continue
                func     = idaapi.get_func(f)
                fn_name  = idc.GetFunctionName(f)
                fn_start = int(func.startEA)
                fn_size  = int(func.size())
                symbols[fn_name] = ("FUNC", fn_start, fn_size, fn_seg) 
            print("Found {} functions names from Functions IDA view".format(len(symbols)))

        #ptvsd.break_into_debugger()
        if self.ida_views[IDAVIEW_NAMES]:
            cnt_unk = 0
            cnt_data = 0
            cnt_code = 0
            for n_ea, n_name in idautils.Names():
                n_seg = idc.get_segm_name(n_ea)
                if n_seg not in segs:
                    continue
                n_flags = idc.GetFlags(n_ea)
                is_data = idc.is_data(n_flags)
                is_code = idc.is_code(n_flags)
                is_unknown = idc.is_unknown(n_flags) #not explored
                is_head = idc.is_head(n_flags)

                n_size = idc.get_item_size(n_ea)
                if symbols.get(n_name, False):
                    #print("Found duplicate {}, skip".format(n_name))
                    continue

                if is_unknown: #write as NOTYPE
                    symbols[n_name] = ("NOTYPE", n_ea, n_size, n_seg) 
                    cnt_unk+=1

                if is_data: #write as OBJECT
                    symbols[n_name] = ("OBJECT", n_ea, n_size, n_seg) 
                    cnt_data+=1

                if is_code: #write as FUNC, but they couldbe inside func
                    if is_head: #function name, some of them not listed in Functions View
                        symbols[n_name] = ("FUNC", n_ea, n_size, n_seg) 
                    else:
                        #ptvsd.break_into_debugger()
                        symbols[n_name] = ("FUNC", n_ea, n_size, n_seg) 
                    cnt_code+=1

            print("Found new {} unexplored data names from Names IDA view".format(cnt_unk))
            print("Found new {} data names from Names IDA view".format(cnt_data))
            print("Found new {} code names from Names IDA view".format(cnt_code))

        #ptvsd.break_into_debugger()
        if self.ida_views[IDAVIEW_EXPORTS]:
            cnt_unk = 0
            cnt_data = 0
            cnt_code = 0
            for exp_i, exp_ord, exp_ea, exp_name in idautils.Entries():
                #print("idx=%s ordinal=[#%d] name=[0x%08x]" % (exp_name, exp_ord, exp_ea))
                exp_seg = idc.get_segm_name(exp_ea)
                if exp_seg not in segs:
                    continue
                exp_flags = idc.GetFlags(exp_ea)
                is_data = idc.is_data(exp_flags)
                is_code = idc.is_code(exp_flags)
                is_unknown = idc.is_unknown(exp_flags) #not explored
                is_head = idc.is_head(exp_flags)

                exp_size = idc.get_item_size(exp_ea)
                if symbols.get(exp_name, False):
                    #print("Found duplicate {}, skip".format(exp_name))
                    continue

                if is_unknown: #write as NOTYPE
                    symbols[exp_name] = ("NOTYPE", exp_ea, exp_size, exp_seg) 
                    cnt_unk+=1

                if is_data: #write as OBJECT
                    symbols[exp_name] = ("OBJECT", exp_ea, exp_size, exp_seg) 
                    cnt_data+=1

                if is_code: #write as FUNC, but they couldbe inside func
                    func     = idaapi.get_func(exp_ea)
                    symbols[exp_name] = ("FUNC", exp_ea, 0, exp_seg) #set zero size due to exp_size = operator size
                    cnt_code+=1

            print("Found new {} unexplored data names from Exports IDA view".format(cnt_unk))
            print("Found new {} data names from Exports IDA view".format(cnt_data))
            print("Found new {} code names from Exports IDA view".format(cnt_code))

        #ptvsd.break_into_debugger()
        return symbols

def PLUGIN_ENTRY():
    return ExportSymsPlugin()

