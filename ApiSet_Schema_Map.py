'''
ApiSet Schema Map
=================

This tool creates a mapping from the "Virtual DLLs" to the "Implementation DLLs",
based on the ApiSet Schema mechanism introduced in Windows 7 (also available in
Windows Vista Platform Update).

For more info about the ApiSet Schema, refer to this article by Sebastien Renaud:
https://blog.quarkslab.com/runtime-dll-name-resolution-apisetschema-part-i.html

This tool was originally written in 2012 by Sebastien Renaud for the APiSet Schema v2.
It was updated by Vladimir Kamenar to support newer ApiSet Schema versions up to v6.

(c) Copyright Quarkslab : www.quarkslab.com
Author: S.R
'''
import os, sys, ctypes

class IMAGE_SECTION_HEADER(ctypes.LittleEndianStructure):
   _fields_ = [('Name',             ctypes.c_uint8 * 8),
               ('Misc',             ctypes.c_uint32),
               ('VirtualAddress',   ctypes.c_uint32),
               ('SizeOfRawData',    ctypes.c_uint32),
               ('PointerToRawData', ctypes.c_uint32)]

STRINGDESCRIPTOR_FIELDS = [

   # V1
   [('OffsetDllString', ctypes.c_int32),
    ('StringLength',    ctypes.c_int32),
    ('OffsetDllRedir',  ctypes.c_int32)],

   # V2
   [('OffsetDllString', ctypes.c_int32),
    ('StringLength',    ctypes.c_int32),
    ('OffsetDllRedir',  ctypes.c_int32)],

   # V3
   None,

   # V4
   [('Flags',            ctypes.c_int32),
    ('OffsetDllString',  ctypes.c_int32),
    ('StringLength',     ctypes.c_int32),
    ('AliasOffset',      ctypes.c_int32),
    ('AliasLength',      ctypes.c_int32),
    ('OffsetDllRedir',   ctypes.c_int32)],

   # V5
   None,

   # V6
   [('Flags',            ctypes.c_int32),
    ('OffsetDllString',  ctypes.c_int32),
    ('StringLength',     ctypes.c_int32),
    ('HashedLength',     ctypes.c_int32),
    ('OffsetDllRedir',   ctypes.c_int32),
    ('ValueCount',       ctypes.c_int32)]
]

APISETMAP_FIELDS = [

   # V1
   [('NumStructs',       ctypes.c_int32)],

   # V2
   [('NumStructs',       ctypes.c_int32)],

   # V3
   None,

   # V4
   [('Size',             ctypes.c_int32),
    ('Flags',            ctypes.c_int32),
    ('NumStructs',       ctypes.c_int32)],

   # V5
   None,

   # V6
   [('Size',             ctypes.c_int32),
    ('Flags',            ctypes.c_int32),
    ('NumStructs',       ctypes.c_int32),
    ('EntryOffset',      ctypes.c_int32),
    ('HashOffset',       ctypes.c_int32),
    ('HashFactor',       ctypes.c_int32)]
]

REDIRECTION_FIELDS = [

   # V1
   [('OffsetRedir1',     ctypes.c_uint32),
    ('RedirLen1',        ctypes.c_uint32),
    ('OffsetRedir2',     ctypes.c_uint32),
    ('RedirLen2',        ctypes.c_uint32)],

   # V2
   [('OffsetRedir1',     ctypes.c_uint32),
    ('RedirLen1',        ctypes.c_uint32),
    ('OffsetRedir2',     ctypes.c_uint32),
    ('RedirLen2',        ctypes.c_uint32)],

   # V3
   None,

   # V4
   [('Flags',            ctypes.c_uint32),
    ('OffsetRedir1',     ctypes.c_uint32),
    ('RedirLen1',        ctypes.c_uint32),
    ('OffsetRedir2',     ctypes.c_uint32),
    ('RedirLen2',        ctypes.c_uint32)],

   # V5
   None,

   # V6
   [('Flags',            ctypes.c_uint32),
    ('OffsetRedir1',     ctypes.c_uint32),
    ('RedirLen1',        ctypes.c_uint32),
    ('OffsetRedir2',     ctypes.c_uint32),
    ('RedirLen2',        ctypes.c_uint32)]
]

DLLREDIRECTOR_FIELDS = [

   # V1
   [('ValueCount',       ctypes.c_uint32)],

   # V2
   [('ValueCount',       ctypes.c_uint32)],

   # V3
   None,

   # V4
   [('Flags',            ctypes.c_uint32),
    ('ValueCount',       ctypes.c_uint32)],

   # V5
   None,

   # V6
   []
]

class FileReader:
   def __init__(self, filepath):
      self.file = open(filepath, "rb")

   def __del__(self):
      if not self.file.closed:
         self.file.close()

   def read_chunk(self, start, length):
      self.file.seek(start)
      data = self.file.read(length)
      return data
      
   def readinto(self, file_index, struct):
      self.file.seek(file_index)
      sz = ctypes.sizeof(struct)
      data = self.file.read(sz)
      ctypes.memmove(ctypes.addressof(struct), data, min(len(data), sz))

class Descriptor:
   def __init__(self, buf, index):
      _s = STRINGDESCRIPTOR.from_buffer_copy(buf, 4 + ctypes.sizeof(APISETMAP) + (index * ctypes.sizeof(STRINGDESCRIPTOR)))
      self.string = buf[_s.OffsetDllString : _s.OffsetDllString + _s.StringLength].decode("utf_16_le", errors='replace')
      if hasattr(_s, 'ValueCount'):
         redirs = _s.ValueCount
      else:
         _r = DLLREDIRECTOR.from_buffer_copy(buf, _s.OffsetDllRedir)
         redirs = _r.ValueCount
      self.redirections = list()
      for i in range(redirs):
         redir = Redirection(buf, _s.OffsetDllRedir + ctypes.sizeof(DLLREDIRECTOR), i)
         self.redirections.append(redir)  

class Redirection:
   def __init__(self, buf, offset, index):
      _r = REDIRECTION.from_buffer_copy(buf, offset + (index * ctypes.sizeof(REDIRECTION)))
      self.RedirName = buf[_r.OffsetRedir2 : _r.OffsetRedir2 + _r.RedirLen2].decode("utf_16_le", errors='replace')

def main(dllpath):
   fr = FileReader(dllpath)
   head = fr.read_chunk(0, 0x400) # Read the first 0x400 bytes of the PE file
   section_index = head.index(b".apiset") # Check if ".apiset" can be found
   if section_index <= 0:
      print("Error: Couldn't find the \".apiset\" section")
      return
   print("Found \".apiset\" section header at {:#x}".format(section_index))

   # Read the IMAGE_SECTION_HEADER of .apiset section
   ish = IMAGE_SECTION_HEADER()
   fr.readinto(section_index, ish)
   print("SizeOfRawData: {:#x}, PointerToRawData: {:#x}".format(ish.SizeOfRawData, ish.PointerToRawData))

   # Read the section contents
   buf = fr.read_chunk(ish.PointerToRawData, ish.SizeOfRawData)
   Ver = (buf[0] & 0xFF) | ((buf[1] & 0xFF) << 8) | ((buf[2] & 0xFF) << 16) | ((buf[3] & 0xFF) << 24)
   if Ver < 1 or Ver > 6 or Ver == 3 or Ver == 5:
      print("Error: version {} not supported".format(Ver))
      return

   global STRINGDESCRIPTOR, DLLREDIRECTOR, REDIRECTION, APISETMAP
   STRINGDESCRIPTOR = type('STRINGDESCRIPTOR', (ctypes.LittleEndianStructure,), { '_fields_': STRINGDESCRIPTOR_FIELDS[Ver - 1] })
   DLLREDIRECTOR    = type('DLLREDIRECTOR',    (ctypes.LittleEndianStructure,), { '_fields_': DLLREDIRECTOR_FIELDS[Ver - 1] })
   REDIRECTION      = type('REDIRECTION',      (ctypes.LittleEndianStructure,), { '_fields_': REDIRECTION_FIELDS[Ver - 1] })
   APISETMAP        = type('APISETMAP',        (ctypes.LittleEndianStructure,), { '_fields_': APISETMAP_FIELDS[Ver - 1] })

   _a = APISETMAP.from_buffer_copy(buf, 4)
   print("Version: {}\nNumber of Structures: {}\n".format(Ver, _a.NumStructs))
   Descriptors = list()
   for i in range(_a.NumStructs):
      Descriptors.append(Descriptor(buf, i))

   for descriptor in Descriptors:
      print("Virtual DLL " + descriptor.string, end="")
      for redir in descriptor.redirections:
         print(" -> " + redir.RedirName, end="")
      print()

if __name__ == '__main__':
   if len(sys.argv) <= 2:
      main(os.path.join(os.getenv("windir"), "system32", "apisetschema.dll") if len(sys.argv) == 1 else sys.argv[1])
   else:
      print("Usage: {} <apisetschema.dll>".format(sys.argv[0]))
