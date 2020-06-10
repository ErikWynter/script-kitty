# Anon FTParse v1.0
**About**

- Simple Ruby parser for Nmap's 'ftp-anon' NSE script.
- Compatible with .nmap files or copy-pasted 'ftp-anon' output.

**Installation**

- Clone the repository or download the raw file to your system.
- Make the file executable with `chmod +x anon_ftparse.rb`
- Copy or move the file to your path, eg `cp anon_ftparse.rb /usr/local/bin`
- Run Anon FTParse: `anon_ftparse.rb [your arguments]`

Alternatively, you can run it immediately after downloading by invoking Ruby:
- `ruby anon_ftparse.rb [your arguments]`
 
**How to use**

`anon_ftparse.rb [file1] [file2] [file3] ... [filex]`


Options:
-    -h, --help                       Display this menu and exit
-    -d, --dir     OUTPUT_DIRECTORY   Directory to store results. If it doesn't exist, Anon FTParse creates it.
-    -s, --scheme  NAMING_SCHEME      Naming scheme for the output file(s). Default: 'ftparsed_[inputfile].' For multiple input files, the name of each file is appended to the scheme.


Example usage:
- `anon_ftparse.rb nmap_ftp_results1.txt nmap_ftp_results2.txt`
  - The parsed results will be written to 'ftparsed_nmap_ftp_results1.txt' and 'ftparsed_nmap_ftp_results2.txt'
- `anon_ftparse.rb scan.txt -s results -d /tmp`
  - The parsed results will be written to '/tmp/results'
- `anon_ftparse.rb -s results ftp1.nmap ftp2.nmap -d /tmp`
  - The parsed results will be written to '/tmp/results_ftp1.nmap' and '/tmp/results_ftp2.nmap'

**Example output**
```
anon_ftparse.rb results.nmap results2.nmap -d /tmp
[+] results.nmap: 2 FTP servers allow anonymous login.
[*] Writing results to '/tmp/ftparsed_results.nmap'.
Affected hosts:
192.168.1.1   192.168.1.2
--------------------------------------------------------------
IP: 192.168.1.1
Accessible resources:
| drwxr-xr-x   2 root     root         4096 Apr 02 10:22 Desktop
| drwxr-xr-x   2 root     root         4096 Apr 20 07:02 Documents
| drwxr-xr-x   2 root     root         4096 Apr 22 15:00 Downloads
| drwxr-xr-x   2 root     root         4096 Apr 02 10:22 Music
| drwxr-xr-x   2 root     root         4096 Apr 02 10:22 Pictures
| drwxr-xr-x   2 root     root         4096 Apr 02 10:22 Public
|_drwxr-xr-x   2 root     root         4096 Apr 02 10:22 Templates
--------------------------------------------------------------
IP: 192.168.1.2
Accessible resources:
| -rw-r--r--   1 root     root         3466 Apr 02 11:30 .bashrc
|_drwxr-xr-x   2 root     root         4096 Apr 30 12:38 Temp
--------------------------------------------------------------
[+] results2.nmap: 2 FTP servers allow anonymous login.
[*] Writing results to '/tmp/ftparsed_results2.nmap'.
Affected hosts:
192.168.1.5   192.168.1.6
--------------------------------------------------------------
IP: 192.168.1.5
Accessible resources:
| -rw-r--r--   1 root     root        26532 May 13 13:24 .bash_history
| -rw-r--r--   1 root     root         3466 Apr 02 11:30 .bashrc
| drwx------   2 root     root         4096 May 12 14:24 .ssh
| drwxr-xr-x   2 root     root         4096 Apr 02 10:22 Desktop
| drwxr-xr-x   2 root     root         4096 Apr 20 07:02 Documents
| drwxr-xr-x   2 root     root         4096 Apr 22 15:00 Downloads
| drwxr-xr-x   2 root     root         4096 Apr 02 10:22 Music
| drwxr-xr-x   2 root     root         4096 Apr 02 10:22 Pictures
|_drwxr-xr-x   2 root     root         4096 Apr 02 10:22 Public
--------------------------------------------------------------
IP: 192.168.1.6
Accessible resources:
| drwxr-xr-x  35 root     root         4096 Apr 27 07:48 .config
| drwxr-xr-x   5 root     root         4096 Jul 17  2019 backups
| drwxr-xr-x   2 root     root         4096 Jul 17  2019 credentials
|_drwxr-xr-x   4 root     root         4096 Feb 06 13:25 pci_data
--------------------------------------------------------------

```
**Note:** The output files will only contain the blocks starting and ending with a row of dashes. For example:
```
cat results.nmap
--------------------------------------------------------------
IP: 192.168.1.1
Accessible resources:
| drwxr-xr-x   2 root     root         4096 Apr 02 10:22 Desktop
| drwxr-xr-x   2 root     root         4096 Apr 20 07:02 Documents
| drwxr-xr-x   2 root     root         4096 Apr 22 15:00 Downloads
| drwxr-xr-x   2 root     root         4096 Apr 02 10:22 Music
| drwxr-xr-x   2 root     root         4096 Apr 02 10:22 Pictures
| drwxr-xr-x   2 root     root         4096 Apr 02 10:22 Public
|_drwxr-xr-x   2 root     root         4096 Apr 02 10:22 Templates
--------------------------------------------------------------
IP: 192.168.1.2
Accessible resources:
| -rw-r--r--   1 root     root         3466 Apr 02 11:30 .bashrc
|_drwxr-xr-x   2 root     root         4096 Apr 30 12:38 Temp
--------------------------------------------------------------
```
**Dependencies**

- 'optparse' (installed by default)
