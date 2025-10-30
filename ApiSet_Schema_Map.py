'''
ApiSet Schema Map
=================

This tool creates a mapping from the "Virtual DLLs" to the "Implementation DLLs",
based on the ApiSet Schema mechanism introduced in Windows 7 (also available in
Windows Vista Platform Update).

For more info about the ApiSet Schema, refer to this article by Sebastien Renaud:
https://blog.quarkslab.com/runtime-dll-name-resolution-apisetschema-part-i.html

This tool was originally written in 2012 by Sebastien Renaud for the APiSet Schema v2.
In 2025 it was updated by Vladimir Kamenar to support newer ApiSet Schema versions,
up to v6.

(c) Copyright Quarkslab : www.quarkslab.com
Author: S.R
'''
import os, sys, ctypes

STRDESCRIPTOR_FIELDS = [

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

class Descriptor:
  def __init__(self, buf, index):
    _s = STRDESCRIPTOR.from_buffer_copy(buf, 4 + ctypes.sizeof(APISETMAP) + (index * ctypes.sizeof(STRDESCRIPTOR)))
    _r = _s.OffsetDllRedir
    self.string = buf[_s.OffsetDllString : _s.OffsetDllString + _s.StringLength].decode('utf_16_le', errors='replace')
    if not hasattr(_s, 'ValueCount'):
      _s = DLLREDIRECTOR.from_buffer_copy(buf, _r)
    self.redirections = list()
    for i in range(_s.ValueCount):
      self.redirections.append(Redirection(buf, _r + ctypes.sizeof(DLLREDIRECTOR), i))  

class Redirection:
  def __init__(self, buf, offset, index):
    _r = REDIRECTION.from_buffer_copy(buf, offset + (index * ctypes.sizeof(REDIRECTION)))
    self.RedirName = buf[_r.OffsetRedir2 : _r.OffsetRedir2 + _r.RedirLen2].decode('utf_16_le', errors='replace')

def bin2dw(buf):
  _b0, _b1, _b2, _b3 = buf[0], buf[1], buf[2], buf[3]
  if isinstance(_b0, int):
    return _b0 & 0xFF | (_b1 & 0xFF) << 8 | (_b2 & 0xFF) << 16 | (_b3 & 0xFF) << 24
  return ord(_b0) & 0xFF | (ord(_b1) & 0xFF) << 8 | (ord(_b2) & 0xFF) << 16 | (ord(_b3) & 0xFF) << 24

def main(dllpath):

  with open(dllpath, 'rb') as f:
    secIdx = f.read(0x400).index(b'.apiset') # Look for ".apiset" within the first 0x400 bytes of the PE
    if secIdx <= 0:
      sys.stdout.write('Error: ".apiset" section not found\n')
      return

    # Read the IMAGE_SECTION_HEADER of .apiset section
    f.seek(secIdx + 16)
    SizeOfData = bin2dw(f.read(4))

    # Read the section contents
    f.seek(bin2dw(f.read(4)))
    buf = f.read(SizeOfData)
    Ver = bin2dw(buf)
    if Ver < 1 or Ver > 6 or Ver == 3 or Ver == 5:
      sys.stderr.write('Error: version {} not supported\n'.format(Ver))
      return

    global STRDESCRIPTOR, DLLREDIRECTOR, REDIRECTION, APISETMAP
    STRDESCRIPTOR = type('STRDESCRIPTOR', (ctypes.LittleEndianStructure,), { '_fields_': STRDESCRIPTOR_FIELDS[Ver - 1] })
    DLLREDIRECTOR = type('DLLREDIRECTOR', (ctypes.LittleEndianStructure,), { '_fields_': DLLREDIRECTOR_FIELDS[Ver - 1] })
    REDIRECTION   = type('REDIRECTION',   (ctypes.LittleEndianStructure,), { '_fields_': REDIRECTION_FIELDS[Ver - 1] })
    APISETMAP     = type('APISETMAP',     (ctypes.LittleEndianStructure,), { '_fields_': APISETMAP_FIELDS[Ver - 1] })

    _a = APISETMAP.from_buffer_copy(buf, 4)
    sys.stdout.write('Version: {}\nNumber of Structures: {}\n\n'.format(Ver, _a.NumStructs))
    Descriptors = list()
    for i in range(_a.NumStructs):
       Descriptors.append(Descriptor(buf, i))

    for descriptor in Descriptors:
      sys.stdout.write('Virtual DLL ' + descriptor.string)
      for redir in descriptor.redirections:
        sys.stdout.write(' -> ' + redir.RedirName)
      sys.stdout.write('\n')

if __name__ == '__main__':
  if len(sys.argv) == 2:
    main(sys.argv[1])
  elif len(sys.argv) == 1:
    apidll = os.path.join(os.getenv('windir'), 'system32', 'apisetschema.dll')
    if not os.path.isfile(apidll):
      apidll = os.path.join(os.getenv('windir'), 'sysnative', 'apisetschema.dll')
    main(apidll)
  else:
    sys.stdout.write('Usage: ' + sys.argv[0] + ' <apisetschema.dll>\n')
