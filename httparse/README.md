# HTTParse v1.0
**About**

- Simple Ruby parser for Nmap's 'http-methods' NSE script 
- If 'http-methods' was run together with 'http-title', any HTTP titles found will be added to the results for ports supporting risky HTTP methods.
- Compatible with .nmap files or copy-pasted 'http-methods' output.

**Installation**

- Clone the repository or download the raw file to your system.
- Make the file executable with `chmod +x httparse.rb`
- Copy or move the file to your path, eg `cp httparse.rb /usr/local/bin`
- Run HTTParse: `httparse.rb [your arguments]`

Alternatively, you can run it immediately after downloading by invoking Ruby:
- `ruby httparse.rb [your arguments]`
 
**How to use**

`httparse.rb [file1] [file2] [file3] ... [filex]`


Options:
-    -h, --help                       Display this menu and exit
-    -d, --dir     OUTPUT_DIRECTORY   Directory to store results. If it doesn't exist, HTTParse creates it.
-    -s, --scheme  NAMING_SCHEME      Naming scheme for the output file(s). Default: 'httparsed_[inputfile].' For multiple input files, the name of each file is appended to the scheme.


Example usage:
- `httparse.rb nmap_http_results1.txt nmap_http_results2.txt`
  - The parsed results will be written to 'httparsed_nmap_http_results1.txt' and 'httparsed_nmap_http_results3.txt'
- `httparse.rb scan.txt -s results -d /tmp`
  - The parsed results will be written to '/tmp/results'
- `httparse.rb -s results http1.nmap http2.nmap -d /tmp`
  - The parsed results will be written to '/tmp/results_http1.nmap' and '/tmp/results_http2.nmap'

**Example output**
```
httparse.rb results.nmap results2.nmap -d /tmp 
[*]Created output directory '/tmp'
[+] results.nmap: Found risky HTTP methods for 5 hosts.
[*] Writing results to '/tmp/httparsed_results.nmap'.
Affected hosts:
10.103.12.20   10.103.12.19   10.103.92.61   10.35.161.138   10.134.17.65
--------------------------------------------------------------
IP: 10.103.12.20
|Port: 80
|-Risky HTTP methods: TRACE
|-Website title: IIS Windows Server
|Port: 443
|-Risky HTTP methods: PUT
|Port: 8080
|-Risky HTTP methods: PUT DELETE
|-Website title: Welcome
--------------------------------------------------------------
IP: 10.103.12.19
|Port: 80
|-Risky HTTP methods: TRACE
|Port: 8443
|-Risky HTTP methods: PUT DELETE
|-Website title: Hack Me Please!
--------------------------------------------------------------
IP: 10.103.92.61
|Port: 80
|-Risky HTTP methods: TRACE
--------------------------------------------------------------
IP: 10.35.161.138
|Port: 80
|-Risky HTTP methods: PUT DELETE
|-Website title: Authentication Required
|Port: 443
|-Risky HTTP methods: PUT DELETE
|-Website title: Authentication Required
--------------------------------------------------------------
IP: 10.134.17.65
|Port: 80
|-Risky HTTP methods: PUT DELETE
|-Website title: Configuration Settings
--------------------------------------------------------------
[+] results2.nmap: Found risky HTTP methods for 3 hosts.
[*] Writing results to '/tmp/httparsed_results2.nmap'.
Affected hosts:
192.103.54.20   192.103.54.19   192.103.92.61
--------------------------------------------------------------
IP: 192.103.54.20
|Port: 80
|-Risky HTTP methods: DELETE
|-Website title: Cloud Manager 3.2
|Port: 443
|-Risky HTTP methods: DELETE
|-Website title: Cloud Manager 3.2
--------------------------------------------------------------
IP: 192.103.54.19
|Port: 80
|-Risky HTTP methods: TRACE
|Port: 8443
|-Risky HTTP methods: PUT DELETE
|-Website title: Admin Dashboard
--------------------------------------------------------------
IP: 192.103.92.61
|Port: 80
|-Risky HTTP methods: TRACE
--------------------------------------------------------------
```
**Note:** The output files will only contain the blocks starting and ending with a row of dashes. For example:
```
cat /tmp/httparsed_results2.nmap
--------------------------------------------------------------
IP: 192.103.54.20
|Port: 80
|-Risky HTTP methods: DELETE
|-Website title: Cloud Manager 3.2
|Port: 443
|-Risky HTTP methods: DELETE
|-Website title: Cloud Manager 3.2
--------------------------------------------------------------
IP: 192.103.54.19
|Port: 80
|-Risky HTTP methods: TRACE
|Port: 8443
|-Risky HTTP methods: PUT DELETE
|-Website title: Admin Dashboard
--------------------------------------------------------------
IP: 192.103.92.61
|Port: 80
|-Risky HTTP methods: TRACE
--------------------------------------------------------------
```
**Dependencies**

- 'optparse' (installed by default)
