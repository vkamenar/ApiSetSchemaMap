# ApiSet Schema Mapper

This tool was originally created by Sebastien Renaud for the APiSet Schema v2. It was updated by Vladimir Kameñar to support newer ApiSet Schema versions, up to v6.  

The [**ApiSet Schema**](https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) is a feature introduced in Windows 7.
It is also available in Windows Vista Platform Update. This feature allows importing symbols from specific implementation DLL (e.g., ```kernel32.dll```, ```advapi32.dll```)
through Virtual DLL names (e.g., ```api-ms-win-core-console-ansi-l2-1-0.dll```). The following articles explain the internal ApiSet Schema mechanism:  
* [Runtime DLL name resolution: ApiSetSchema - Part I](https://blog.quarkslab.com/runtime-dll-name-resolution-apisetschema-part-i.html)
* [Runtime DLL name resolution: ApiSetSchema - Part II](https://blog.quarkslab.com/runtime-dll-name-resolution-apisetschema-part-ii.html)

The ApiSet Schema Mapper is a Python script to view the corresponding implementation DLL for each Virtual DLL. The tool is compatible with x86, x64 and ARM64
DLL files. The minimum Python version to run this tool is 2.7.  
<br>

## The purpose of the ApiSet Schema Mapper

Let's suppose you are analyzing a PE32 binary in your favorite disassembler, like IDA Pro, and you see that it's calling a symbol from a Virtual DLL:

![IDA disassembly listing](https://github.com/user-attachments/assets/b4d15f45-da38-4284-9de9-d249a8f089ba)

This symbol *IsLibraryCreatedByPolicy* appears to be exported by the Virtual DLL ```api-ms-win-storage-exports-internal-l1-1-0.dll```. If you want to identify
the DLL where this symbol is really implemented, you can use the ApiSet Schema Mapper:  

```python ApiSet_Schema_Map.py```

The output will show you the redirection, for example:  

```Virtual DLL api-ms-win-storage-exports-internal-l1-1-0 -> windows.storage.dll```

```windows.storage.dll``` is the implementation DLL in this case.  
<br>

## Running the tool

The tool can receive a single command-line parameter. This parameter is the ApiSet Schema DLL. For example:  

```python ApiSet_Schema_Map.py C:\Windows\system32\apisetschema.dll```

**Note:** Be careful when specifying a DLL file in the Windows system directory. If your Windows is x64 and the Python interpreter is 32-bit,
the system may redirect ```System32``` to ```SysWOW64``` and the DLL might not be there. It is recommended to copy the DLL to a different location to
avoid this kind of issues.  

If you don't specify the command-line parameter, the tool will try to locate the ```apisetschema.dll``` automatically.  
<br>

## Sample output

[Sample output files](sample_output) are provided for multiple Windows versions. These files should not be used as a stable reference because
the exact mapping may depend on the SP level, among other variables.  
