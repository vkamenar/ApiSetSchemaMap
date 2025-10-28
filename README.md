# ApiSet Schema Mapper

This tool was originally created by Sebastien Renaud for the APiSet Schema v2. It was updated by Vladimir Kameñar to support newer ApiSet Schema versions, up to v6.  

The [**ApiSet Schema**](https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets) is a feature introduced in Windows 7.
It is also available in Windows Vista Platform Update. This feature allows importing symbols from specific implementation DLL (i.e. *kernel32.dll*, *advapi32.dll*)
through Virtual DLL names (i.e. *api-ms-win-core-console-ansi-l2-1-0.dll*). The following articles explain the ApiSet Schema mechanism:  
* [Runtime DLL name resolution: ApiSetSchema - Part I](https://blog.quarkslab.com/runtime-dll-name-resolution-apisetschema-part-i.html)
* [Runtime DLL name resolution: ApiSetSchema - Part II](https://blog.quarkslab.com/runtime-dll-name-resolution-apisetschema-part-ii.html)

The ApiSet Schema Mapper is a simple Python script to view the corresponding implementation DLL for each Virtual DLL. The tool is compatible with x86, x64 and ARM64
DLL files. The minimum Python version to run this tool is 2.7.
