# SMB Parse v1.0
**About**

- Simple Ruby parser for Nmap's 'smb-enum-shares' NSE script.
- Compatible with .nmap files or copy-pasted 'smb-enum-shares' output.

**Installation**

- Clone the repository or download the raw file to your system.
- Make the file executable with `chmod +x smb_parse.rb`
- Copy or move the file to your path, eg `cp smb_parse.rb /usr/local/bin`
- Run SMB Parse: `smb_parse.rb [your arguments]`

Alternatively, you can run it immediately after downloading by invoking Ruby:
- `ruby smb_parse.rb [your arguments]`
 
**How to use**

`smb_parse.rb [file1] [file2] [file3] ... [filex]`


Options:
    -h, --help                       Display this menu and exit
    -d, --dir     OUTPUT_DIRECTORY   Directory to store results. If it doesn't exist, SMB Parse creates it.
    -s, --scheme  NAMING_SCHEME      Naming scheme for the output file(s).Default: 'smbparsed_[inputfile].' For multiple input files, the name of each file is appended to the scheme.


Example usage:
- `smb_parse.rb nmap_results1.txt nmap_results2.txt`
  - The parsed results will be written to 'smbparsed_nmap_results1.txt' and 'smbparsed_nmap_results2.txt'
- `smb_parse.rb scan.txt -s results -d /tmp`
  - The parsed results will be written to '/tmp/results'
- `smb_parse.rb -s results smb1.nmap smb2.nmap -d /tmp`
  - The parsed results will be written to '/tmp/results_smb1.nmap' and '/tmp/results_smb2.nmap'

**Example output**
```
smb_parse.rb -s results scan1.nmap scan2.nmap -d /tmp
[+] scan1.nmap: 4 shares accross 2 hosts allow null session authentication.
[*] Writing results to '/tmp/results_scan1.nmap'.
Affected hosts:
192.168.1.16   192.168.1.17
--------------------------------------------------------------
|IP: 192.168.1.16
|-Share: 192.168.1.16\IPC$      - Anonymous access: READ/WRITE
|-Share: 192.168.1.16\tmp       - Anonymous access: READ/WRITE
--------------------------------------------------------------
|IP: 192.168.1.17
|-Share: 192.168.1.17\IPC$      - Anonymous access: READ/WRITE
|-Share: 192.168.1.17\test      - Anonymous access: READ/WRITE
--------------------------------------------------------------
[+] scan2.nmap: 17 shares accross 6 hosts allow null session authentication.
[*] Writing results to '/tmp/results_scan2.nmap'.
Affected hosts:
192.168.1.22   192.168.1.27   192.168.1.23   192.168.1.24   192.168.1.25
192.168.1.26
--------------------------------------------------------------
|IP: 192.168.1.22
|-Share: 192.168.1.22\dev       - Anonymous access: READ/WRITE
|-Share: 192.168.1.22\IPC$      - Anonymous access: READ/WRITE
|-Share: 192.168.1.22\tmp       - Anonymous access: READ/WRITE
--------------------------------------------------------------
|IP: 192.168.1.27
|-Share: 192.168.1.27\IPC$      - Anonymous access: READ/WRITE
|-Share: 192.168.1.27\web       - Anonymous access: READ/WRITE
--------------------------------------------------------------
|IP: 192.168.1.23
|-Share: 192.168.1.23\ADMIN$    - Anonymous access: READ/WRITE
|-Share: 192.168.1.23\C$        - Anonymous access: READ/WRITE
|-Share: 192.168.1.23\IPC$      - Anonymous access: READ/WRITE
|-Share: 192.168.1.23\temp      - Anonymous access: READ/WRITE
|-Share: 192.168.1.23\test      - Anonymous access: READ/WRITE
--------------------------------------------------------------
|IP: 192.168.1.24
|-Share: 192.168.1.24\dev       - Anonymous access: READ/WRITE
|-Share: 192.168.1.24\IPC$      - Anonymous access: READ/WRITE
|-Share: 192.168.1.24\print$    - Anonymous access: READ/WRITE
--------------------------------------------------------------
|IP: 192.168.1.25
|-Share: 192.168.1.25\IPC$      - Anonymous access: READ/WRITE
|-Share: 192.168.1.25\temp      - Anonymous access: READ/WRITE
--------------------------------------------------------------
|IP: 192.168.1.26
|-Share: 192.168.1.26\dev       - Anonymous access: READ/WRITE
|-Share: 192.168.1.26\IPC$      - Anonymous access: READ/WRITE
--------------------------------------------------------------
```
**Note:** The output files will only contain the blocks starting and ending with a row of dashes. For example:
```
cat results_scan1.nmap
--------------------------------------------------------------
|IP: 192.168.1.16
|-Share: 192.168.1.16\IPC$      - Anonymous access: READ/WRITE
|-Share: 192.168.1.16\tmp       - Anonymous access: READ/WRITE
--------------------------------------------------------------
|IP: 192.168.1.17
|-Share: 192.168.1.17\IPC$      - Anonymous access: READ/WRITE
|-Share: 192.168.1.17\test      - Anonymous access: READ/WRITE
--------------------------------------------------------------
```
**Dependencies**

- 'optparse' (installed by default)
