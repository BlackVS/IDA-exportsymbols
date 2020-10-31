#!/usr/bin/env python


#-------------------------------------------------------------------------------
# elftools: common/exceptions.py
#
# Exception classes for elftools
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
class ELFError(Exception): 
    pass

class ELFRelocationError(ELFError):
    pass
        
class ELFParseError(ELFError):
    pass

class ELFCompressionError(ELFError):
    pass

class DWARFError(Exception):
    pass



def _assert_with_exception(cond, msg, exception_type):
    if not cond:
        raise exception_type(msg)

def elf_assert(cond, msg=''):
    """ Assert that cond is True, otherwise raise ELFError(msg)
    """
    _assert_with_exception(cond, msg, ELFError)
