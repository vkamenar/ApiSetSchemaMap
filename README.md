# ApiSet Schema Mapper

This tool was originally created by Sebastien Renaud for the APiSet Schema v2. It was updated by Vladimir Kameñar to support newer ApiSet Schema versions, up to v6.  

The **ApiSet Schema** is an undocumented feature introduced in Windows 7. It is also available in Windows Vista Platform Update. This feature allows importing symbols
from specific implementation DLL (i.e. *kernel32.dll*, *advapi32.dll*) through Virtual DLL names (i.e. *api-ms-win-core-console-ansi-l2-1-0.dll*).  

The ApiSet Schema Mapper is a simple Python script to view the corresponding implementation DLL for each Virtual DLL.
