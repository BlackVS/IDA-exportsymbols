#!/usr/bin/env python
from elf_exceptions import *
from elf_structs import *
from collections import defaultdict
import inspect
import os, os.path
import copy
import struct

ELF_FNAME_STRUCTURE = "elf_structure.txt"
ELF_FNAME_HEADER = "elf_header"

def tobytearray(data):
    if isinstance(data, str):
        res=bytearray(data)
    return res

def get_cstring(buffer,offset):
    res=""
    pos=offset
    while pos<len(buffer) and buffer[pos]!=0:
        res+=chr(buffer[pos])
        pos+=1
    return res

def hex_or_none(v):
    return (hex(v),"-")[v==0]

def log(msg,o):
    #frame = inspect.currentframe()
    #args, _, _, values = inspect.getargvalues(frame)
    #print( "%s:%s" % (args[0], values[args[0]]) )
    print(">=======================")
    print("{} :".format(msg))
    print(o)
    print("<=======================\n")


class ELFParser(object):
    """description of class"""
    def __init__(self, stream, dest_dir=None, store_in_structure = False ):
        self.header = None
        self.program_headers = []
        self.sections = []
        self.structure = []

        self.stream = stream
        self.dest_dir = dest_dir
        self._identify_file()
        if self.elfclass != 32:
            raise ELFError('Only 32bit supported for now! ELF_CLASS %s' % repr(self.elfclass))
        self.dump_header(store_in_structure)

    @staticmethod
    def get_elf_version(stream):
        pos = stream.tell()
        try:
            stream.seek(0)
            magic = stream.read(4)
            if magic != b'\x7fELF':
                raise ELFError('Invalid magic, not ELF : %s' % repr(magic))

            ei_class = stream.read(1)
            if ei_class == b'\x01':
                elfclass = 32
            elif ei_class == b'\x02':
                elfclass = 64
            else:
                raise ELFError('Invalid EI_CLASS %s' % repr(ei_class))

            ei_data = stream.read(1)
            if ei_data == b'\x01':
                is_little_endian = True
            elif ei_data == b'\x02':
                is_little_endian = False
            else:
                raise ELFError('Invalid EI_DATA %s' % repr(ei_data))
        finally:
            stream.seek(pos)
        return (elfclass, is_little_endian)

    def _identify_file(self):
        self.elfclass, self.is_little_endian = ELFParser.get_elf_version(self.stream)

    def dump_header(self, store_in_structure=False):
        self.header = ELF32_Ehdr(self.is_little_endian, self.stream);
        if self.dest_dir!=None:
            res=self.header.dump(ELF_FNAME_HEADER, self.dest_dir)
            if store_in_structure:
                self.structure.append( res ) #hedaer starts from 0
        #log("ELF Header",self.header)

    def dump_program_headers(self, store_in_structure=False):
        if self.header==None or self.stream == None:
            raise ELFError("{}: No header or input stream!".format(__name__) )

        f=None
        try:
            self.stream.seek( self.header.e_phoff )
            fn_pheaders=os.path.join( self.dest_dir, "elf_segments_info.txt")
            f=open(fn_pheaders, "wt+")

            f.write("{:8}{:12}{:12}{:12}{:12}{:12}{:12}{:12}{:12}{:12}\n".format("idx", "p_type", "p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz", "p_flags", "p_align", "payload" ))
            for i in range( self.header.e_phnum ):
                phdr=ELF32_ProgramHeader(self.is_little_endian)
                phdr.payload=0
                if len(phdr)!=self.header.e_phentsize:
                    raise ELFError("{}: Failed to parse programs headers!".format(__name__) )
                phdr.read_and_parse(self.stream)
                phdr_res=phdr.dump("segment_{:02}.hdr".format(i), self.dest_dir)
                if phdr.p_offset == 0: #special case - segment contains all headers. Due to segments usually are not overlap - try strip
                    # calc prefix paylod
                    phdr.payload = self.header.e_phoff + self.header.e_phnum*self.header.e_phentsize
                f.write("{:4}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}\n".format(
                         i, phdr.p_type, phdr.p_offset, phdr.p_vaddr, phdr.p_paddr, phdr.p_filesz, phdr.p_memsz, phdr.p_flags, phdr.p_align, phdr.payload 
                         )
                        )
                self.program_headers.append( phdr )
                if store_in_structure:
                    self.structure.append( phdr_res )
            
            for i,phdr in enumerate(self.program_headers):
                fname=os.path.join( self.dest_dir, "segment_{:02}.bin".format(i))
                with open(fname,"wb+") as fb:
                    self.stream.seek(phdr.p_offset)
                    data=self.stream.read(phdr.p_filesz)
                    fb.write(data)
                if phdr.payload!=0:
                    fname=os.path.join( self.dest_dir, "segment_{:02}.stripped.bin".format(i))
                    with open(fname,"wb+") as fb:
                        self.stream.seek(phdr.p_offset+phdr.payload)
                        data=self.stream.read(phdr.p_filesz-phdr.payload)
                        fb.write(data)
                
                if store_in_structure:
                    self.structure.append( (phdr.p_offset, phdr.p_filesz, "raw", "segment_{:02}".format(i)) )

        except Exception as e:
            raise e
        finally:
            if f:
                f.close()

    def dump_section_headers(self, store_in_structure=False):
        if self.header==None or self.stream == None:
            raise ELFError("{}: No header or input stream!".format(__name__) )

        #try:
        self.stream.seek( self.header.e_shoff )
        with open(os.path.join( self.dest_dir, "elf_sections_info.txt"), "wt+") as f:
            f.write( "{:8}{:12}{:12}{:12}{:12}{:12}{:12}{:12}{:12}{:14}{:14}\n".format("idx", "sh_name", "sh_type", "sh_flags", "sh_addr", "sh_offset", "sh_size", "sh_link", "sh_info", "sh_addralign", "sh_entsize" ))
            for i in range( self.header.e_shnum ):
                shdr=ELF32_SectionHeader(self.is_little_endian)
                if len(shdr)!=self.header.e_shentsize:
                    raise ELFError("{}: Failed to parse sections headers!".format(__name__) )
                shdr.read_and_parse(self.stream)
                shdr_res=shdr.dump("section_{:02}.hdr".format(i), self.dest_dir)
                f.write("{:4}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}    {:08x}      {:08x}      {:08x}\n".format(
                            i, shdr.sh_name, shdr.sh_type, shdr.sh_flags, shdr.sh_addr, shdr.sh_offset, shdr.sh_size, shdr.sh_link, shdr.sh_info, shdr.sh_addralign, shdr.sh_entsize 
                            )
                        )
                self.sections.append( shdr )
                if store_in_structure:
                    self.structure.append( shdr_res )
            
        #get sections names first
        raw_names=None
        if self.header.e_shstrndx!=0: #section with sections names is present
            shdr=self.sections[self.header.e_shstrndx]
            self.stream.seek(shdr.sh_offset)
            raw_names=tobytearray(self.stream.read(shdr.sh_size))

        ##
        with open(os.path.join( self.dest_dir, "elf_sections_info2.txt"), "wt+") as f2:
            f2_fmt_title = "{:4} {:8}  {:8}   {:10}   {:12}\n\n"
            f2_fmt       = "{:4} {:08x}   {:10}   {:10}   {:12}\n"
            f2.write(f2_fmt_title.format("#", "sh_offset", "sh_size", "v_addr", "name"))
            for i,shdr in enumerate(self.sections):
                section_name=shdr.sh_name
                if shdr.sh_name!=0:
                    section_name=get_cstring(raw_names, shdr.sh_name)
                f2.write(f2_fmt.format(i, shdr.sh_offset, hex_or_none(shdr.sh_size), hex_or_none(shdr.sh_addr), section_name))
                #####
                sz=shdr.sh_size
                if store_in_structure:
                    self.structure.append( (shdr.sh_offset,sz, "raw", "section_{:02}".format(i)) )
                if sz>0:
                    fname_short="section_{:02}.bin".format(i)
                    fname=os.path.join( self.dest_dir, fname_short)
                    with open(fname,"wb+") as fb:
                        self.stream.seek(shdr.sh_offset)
                        data=self.stream.read(sz)
                        fb.write(data)
        ## sorted
        with open(os.path.join( self.dest_dir, "elf_sections_info2_sorted.txt"), "wt+") as f2:
            f2_fmt_title = "{:4} {:8}  {:8}   {:10}   {:12}\n\n"
            f2_fmt       = "{:4} {:08x}   {:10}   {:10}   {:12}\n"
            f2.write(f2_fmt_title.format("#", "sh_offset", "sh_size", "v_addr", "name"))
            for i in sorted(range(len(self.sections)), key=lambda iv: self.sections[iv].sh_offset):
                shdr=self.sections[i]
                section_name=shdr.sh_name
                if shdr.sh_name!=0:
                    section_name=get_cstring(raw_names, shdr.sh_name)
                f2.write(f2_fmt.format(i, shdr.sh_offset, hex_or_none(shdr.sh_size), hex_or_none(shdr.sh_addr), section_name))

        # except Exception as e:
        #     raise e
        # finally:
        #     pass

    def write_structure(self):
        #self.structure.sort()
        res=defaultdict(list)
        for s in self.structure:
            res[(s[0],s[1],s[2])].append( s[3] )
        with open(os.path.join( self.dest_dir, ELF_FNAME_STRUCTURE), "wt+") as f:
            for (r0,r1,r2),r3 in sorted(res.items()):
                f.write("{:08x} {:08x} {:25} {}\n".format(r0,r1,r2," ".join(r3)))



class ELFAssembler(object):
    def __init__(self, src_dir):
        self.header = None
        self.program_headers = []
        self.section_headers = []
        self.src_dir = src_dir
        self.init_header()
        self.is_little_endian = None

    def init_header(self):
        self.header=ELF32_Ehdr()
        self.header['EI_MAG'] = [ 0x7f, 0x45, 0x4c, 0x46 ]
        self.header['EI_CLASS'] = 0x1 # 1=32 bit 2=64 bit
        self.header['EI_DATA']  = 0x1 # 1 LE , 2 BE
        self.header['EI_VERSION'] = 0x1
        self.header['e_type'] = 0x2 # exec
        self.header['e_version'] = 1
        try:
            with open(os.path.join( self.src_dir, ELF_FNAME_HEADER+".ini"),"rt") as f:
                for t in f:
                    a,b=t.split(":")
                    a=a.strip()
                    b=b.strip()
                    self.header[a]=b
        except:
            pass
        self.is_little_endian = self.header['EI_CLASS']==1
        self.header.setByteOrder(self.is_little_endian)

    def read_header(self):
        fheader=os.path.join( self.src_dir, ELF_FNAME_HEADER+".bin")
        with open(fheader, "rb") as f:
            self.elfclass, self.is_little_endian = ELFParser.get_elf_version(f)
            if self.elfclass!=32:
                raise ELFError('Only 32bit supported for now! ELF_CLASS %s' % repr(self.elfclass))
            self.header=ELF32_Ehdr(self.is_little_endian, f)

    #walk through program headers in structer, load from raw and update loaded program headers/table
    def read_segments_info(self):
        ##load map file
        with open(os.path.join( self.src_dir, "elf_segments.map"), "rt") as fmap:
            titles = fmap.readline().split()
            #print(titles)

            for t in fmap:
                t.strip()
                if not t: continue

                values=t.split()
                if not values: continue

                phdr=ELF32_ProgramHeader(self.is_little_endian)
                phdr['p_type']  = 1
                phdr['p_align'] = 1
                phdr.filename = None

                idx=int(values[0])

                for i in range(1,len(values)):
                    n,v= titles[i], values[i]
                    if n=='filename':
                        phdr.filename = v
                    elif n=='offset':
                        phdr.offset = int(v, 16)
                    else:
                        phdr[ n ] = v
                if phdr.filename:
                    sz=os.path.getsize( os.path.join( self.src_dir, phdr.filename ) ) - phdr.offset
                    if phdr['p_filesz']==0:
                        phdr['p_filesz']=sz
                    assert(phdr['p_filesz']==sz)
                    if phdr['p_memsz']==0:
                        phdr['p_memsz']=phdr['p_filesz']
                    assert(phdr['p_memsz']>=phdr['p_filesz'])

                self.program_headers.append(phdr)

    def read_sections_info(self):
        fsecmap=os.path.join( self.src_dir, "elf_sections_info.txt" )
        if not os.path.isfile(fsecmap):
            return #no sections defined`

        ##load map file
        with open(fsecmap) as fmap:
            titles = fmap.readline().split()
            #print(titles)

            for t in fmap:
                t.strip()
                if not t: continue

                values=t.split()
                if not values: continue

                shdr=ELF32_SectionHeader(self.is_little_endian)
                shdr.filename = None
                
                idx=int(values[0])
                fname_short="section_{:02}.bin".format(idx)
                fname=os.path.join( self.src_dir, fname_short)
                if os.path.isfile(fname):
                    shdr.filename=fname_short

                for i in range(1,len(values)):
                    n,v= titles[i], values[i]
                    shdr[ n ] = v

                if shdr.filename:
                    sz=os.path.getsize( os.path.join( self.src_dir, shdr.filename ) )
                    if shdr['sh_size']==0:
                        shdr['sh_size']=sz
                    assert(shdr['sh_size']==sz)

                self.section_headers.append(shdr)

    def update_data(self):
        #update header
        self.header['e_ehsize']=len(self.header) #header size
        self.header['e_phoff' ]=len(self.header) #pos of program table - just after header
        self.header['e_phentsize']=len(ELF32_ProgramHeader)
        self.header['e_phnum']=len(self.program_headers)
        
        #update program table
        poff=self.header['e_phoff' ]+self.header['e_phnum']*self.header['e_phentsize']
        for phdr in self.program_headers:
            phdr['p_offset']=poff
            poff+=phdr['p_filesz']

        #sectio ns
        if not self.section_headers:
            return #no sec tions defined
        self.header['e_shoff' ]   =poff #pos of sections table - just after segments
        self.header['e_shentsize']=len(ELF32_SectionHeader)
        self.header['e_shnum']    =len(self.section_headers)

        poff+=len(ELF32_SectionHeader)*len(self.section_headers)
        for shdr in self.section_headers:
            if shdr['sh_size']:
                shdr['sh_offset']=poff
                poff+=shdr['sh_size']

    def write(self, output_file):
        with open(output_file,"wb+") as stream:
            #write header
            self.header.pack()
            stream.write(self.header.raw_data)
            #write program table
            for phdr in self.program_headers:
                phdr.pack()
                stream.write(phdr.raw_data)
            #write segments
            for phdr in self.program_headers:
                with open(os.path.join( self.src_dir, phdr.filename ),"rb") as f:
                    f.seek( phdr.offset )
                    data=f.read( phdr.p_filesz )
                    stream.write(data)
            #write sections headers
            if not self.section_headers:
                return
            pos=stream.tell()
            assert(self.header['e_shoff']==pos)
            for shdr in self.section_headers:
                shdr.pack()
                stream.write(shdr.raw_data)
            #write sections itself
            for shdr in self.section_headers:
                if shdr.filename:
                    pos=stream.tell()
                    assert(pos==shdr.sh_offset)
                    with open(os.path.join( self.src_dir, shdr.filename ),"rb") as f:
                        data=f.read( shdr.sh_size )
                        stream.write(data)
