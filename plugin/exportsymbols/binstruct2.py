#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import struct
import sys
import os, os.path

__all__ = ['BinStruct',
          ]

# type: fmt
BIN_TYPE_IDX_FMT   = 0
BIN_TYPE_IDX_PYTHON_TYPE = 1
BIN_TYPES = {
    # "alias" : ( pack flag, python type, size )
    'pad'   : ('x', int),
    'bool'  : ('?', bool),
    'char'  : ('b', str ),
    'byte'  : ('B', int ),
    'int8'  : ('b', int ),
    'uint8' : ('B', int ),
    'int16' : ('h', int ),
    'uint16': ('H', int ),
    'int32' : ('i', int ),
    'uint32': ('I', int ),
    'int64' : ('q', int ),
    'uint64': ('Q', int ),
}


class BinStructMeta(type):
    def __new__(cls, name, bases, dct):
        __DEFINE_STRUCT__ = dct.get("__DEFINE_STRUCT__", None)
        __fmt__        = ""
        __datastruct__ = list()
        __datastructdict__ = dict()
        if __DEFINE_STRUCT__ is not None: #BinStructMeta and BinStruct has not __struct__ at init time
            #parse
            reConsoleParser = re.compile(r"([\w.]+)\s*([\w.]+)\s*(?:\[(\d+)\])?;")

            try:
                parsed = reConsoleParser.findall(__DEFINE_STRUCT__)
            except Exception as inst:
                raise Exception("Error parsing: " + __DEFINE_STRUCT__)
            pos=0
            for (vtype, vname, varrsize) in parsed:
                if varrsize==None or varrsize=='':
                    varrsize=1
                # if known ordinary type
                t=BIN_TYPES.get(vtype,None)
                varrsize=max(1, int(varrsize))
                if t!=None:
                    fmt = t[BIN_TYPE_IDX_FMT]
                    sz = struct.calcsize(fmt)
                    if varrsize>1: #arrays
                        if len(fmt)==1: #arrays of ordinal type
                            fmt=str(varrsize)+fmt
                        else: #arrays of complex type
                            fmt=fmt*varrsize
                        sz*=varrsize
                    __datastruct__.append( (vname, vtype, varrsize, fmt, pos, sz) )
                    __datastructdict__[vname]=(vtype, varrsize, fmt, pos, sz)
                    __fmt__  += fmt
                    pos += sz
                    continue
            dct['__packedsize__'] = struct.calcsize(__fmt__)
            dct['__fmt__']        = __fmt__
            #dct['__data__']       = __data__
            dct['__datastruct__'] = __datastruct__
            dct['__datastructdict__'] = __datastructdict__
        #new_cls = super().__new__(cls, name, bases, dct)
        new_cls = super(BinStructMeta, cls).__new__(cls, name, bases, dct)
        if __fmt__:
            BIN_TYPES[name]=(__fmt__,new_cls)
        return new_cls

    def __len__(cls):
        """ Structure size (in bytes) """
        return cls.__packedsize__

    @property
    def size(cls):
        """ Structure size (in bytes) """
        return cls.__packedsize__

#class BinStruct(object):
#    __metaclass__ = BinStructMeta
_BinStructParent = BinStructMeta('_BinStructParent', (object, ), {})
class BinStruct(_BinStructParent):
    def __init__(self, isLE=None, stream=None):
        self.raw_is_dirty=True
        self.raw_data = None
        self.raw_pos  = None;
        self.parsed_data=dict()

        self.setByteOrder(isLE)
        self.clear()
        #if buffer!=None:
        #    self.unpack(buffer)
        if stream!=None:
            self.read_and_parse(stream)

    def __len__(self):
        """ Structure size (in bytes) """
        return self.__packedsize__

    def setByteOrder(self, isLE):
        if isLE == None:
            self.struct_byteorder_format=''
        else:
            self.struct_byteorder_format=('>','<')[isLE]

    def clear(self):
        for (vname, vtype, varrsize, fmt, pos, sz) in self.__datastruct__:
            t=BIN_TYPES.get(vtype,None)
            if t!=None:
                if varrsize==1:
                    self.parsed_data[vname]=t[BIN_TYPE_IDX_PYTHON_TYPE]()
                else:
                    self.parsed_data[vname]= [t[BIN_TYPE_IDX_PYTHON_TYPE]()]*varrsize

    def format_as_str(self, shift=0):
        prefix=""
        if shift:
            prefix=" "*shift
        result = prefix + "<{}> :\n".format(type(self).__name__)
        for (vname, vtype, varrsize, fmt, fpos, vsize) in self.__datastruct__:
            value = self.parsed_data[vname]
            if isinstance(value,BinStruct):
                result += prefix + "{} = ".format(vname)
                result += prefix + value.format_as_str(shift+4)
            else:
                if isinstance(value, int):
                    value=hex(value)
                if isinstance(value, list) or isinstance(value, tuple):
                    result += prefix + vname + " = [ " + ", ".join(map(lambda v: hex(v) if isinstance(v,int) else str(v), value)) + " ]\n"
                else:
                    result += prefix + "{} = {}\n".format(vname, value)
        return result 

    def format_as_dump(self):
        result=""
        ###
        result += ":> {}\n".format(type(self).__name__)
        for (vname, vtype, varrsize, fmt, fpos, vsize) in self.__datastruct__:
            vpos = fpos
            value = self.parsed_data[vname]
            if isinstance(value,BinStruct):
                result += value.format_as_dump()
            else:
                if isinstance(value, int):
                    value=hex(value)
                if isinstance(value, list) or isinstance(value, tuple):
                    result += "{:08x} {:02x} {:16} : [ {} ]\n".format(vpos, vsize, vname, ", ".join(map(lambda v: hex(v) if isinstance(v,int) else str(v), value)))
                else:
                    result += "{:08x} {:02x} {:16} : {}\n".format(vpos, vsize, vname, value)
        result += ":< {}\n".format(type(self).__name__)
        return result 

    def __str__(self, shift=0):
        return  self.format_as_str()

    def __repr__(self):
        return self.__str__()

    def get_value(self, name):
        if name in self.parsed_data:
            return self.parsed_data[name]
        raise ELFError("get_value: no key {}".format(name))

    def set_value(self, name, value):
        if not (name in self.parsed_data):
            raise ELFError("set_value: no key {}".format(name))

        vtype, varrsize, fmt, fpos, vsize = self.__datastructdict__[name]
        if not isinstance(value, type(self.parsed_data[name])):
            # try to convert first
            if isinstance(value, str):
                if isinstance(self.parsed_data[name],int):
                    value=int(value,16) #only hex!!!
        if not isinstance(value, type(self.parsed_data[name])):
            raise ValueError
        if self.parsed_data[name]!=value:
            self.parsed_data[name]=value
            self.raw_is_dirty=True

    #def __setattr__(self, name, value):
    #    self._set_value(name, value)

    def __getattr__(self, name):
        return self.get_value(name)

    def __setitem__(self, name, value):
        self.set_value(name, value)

    def __getitem__(self, name):
        return self.get_value(name)

    def unpack(self, buffer):
        if len(buffer)<self.__packedsize__:
            raise Exception("Error parsing: " + __DEFINE_STRUCT__)
        for (vname, vtype, varrsize, fmt, pos, sz) in self.__datastruct__:
            if isinstance(self.parsed_data[vname],BinStruct):
                #recursive unpack
                self.parsed_data[vname].unpack(buffer[pos:])
            else:
                data = struct.unpack_from(self.struct_byteorder_format+fmt, buffer, pos)
                if len(data)==1:
                    self.parsed_data[vname]=type(self.parsed_data[vname])(data[0])
                else:
                    self.parsed_data[vname]=type(self.parsed_data[vname])(data)
        self.raw_is_dirty=False

    def pack(self, buffer=None):
        if not self.raw_is_dirty:
            return 
        if buffer==None:
            buffer=self.raw_data=bytearray(self.__packedsize__)
        if len(buffer)<self.__packedsize__:
            raise Exception("Error packing, buffer too small: " + __DEFINE_STRUCT__)

        for (vname, vtype, varrsize, fmt, pos, sz) in self.__datastruct__:
            if isinstance(self.parsed_data[vname], BinStruct):
                #recursive unpack
                self.parsed_data[vname].pack(buffer[pos:])
            else:
                if varrsize==1:
                    struct.pack_into(self.struct_byteorder_format+fmt, buffer, pos, self.parsed_data[vname])
                else:
                    struct.pack_into(self.struct_byteorder_format+fmt, buffer, pos, *self.parsed_data[vname])


    def read_and_parse(self, stream):
        self.raw_pos  = stream.tell()
        self.raw_data = stream.read( self.__packedsize__ )
        self.unpack(self.raw_data)

    def dump(self, element_name, destdir, save_bin=True, save_parsed=True):
        if destdir==None:
            return
        if not os.path.exists(destdir):
            os.makedirs(destdir)
        fname_bin_short=""
        if save_bin:
            fname_bin_short = "{}.bin".format(element_name)
            fname_bin    = os.path.join( destdir, fname_bin_short)
            with open(fname_bin, "wb+") as f:
                f.write(self.raw_data)
        fname_parsed_short=""
        if save_parsed:
            fname_parsed_short = "{}.parsed".format(element_name)
            fname_parsed = os.path.join( destdir, fname_parsed_short)
            with open(fname_parsed,"wt+") as f:
                f.write(self.format_as_dump())

        #( offest in file, fname_bin, fname_parsed)
        return ( self.raw_pos, len(self.raw_data), type(self).__name__, fname_bin_short ) 