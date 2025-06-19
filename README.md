## PrivUp

A Windows priv esc finder

### How you should use this tool in a OSCP setting
1) Check for quick wins (check whoami /all, C:\ dir and user dir) - if no priv...
2) Run ".\PrivUp.ps1" - if no priv...
3) Run winPeas

### What does it check?
1) Checks if you can write to directories in path (for DLL hijacking)
2) Check if you can write to services and resart them
3) Enumerates installed software, checks if you can write
4) Checks for unqouted service paths
5) Checks if you can write to any running processes
6) Checks for passwords in default locations (does not search filesystem)
7) Checks if you can write to services and checks for unquooted services
8) Checks startup apps 