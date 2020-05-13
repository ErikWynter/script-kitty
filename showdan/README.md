# ShoWdan v1.0
**About**

- ShoWdan is a simple web scraper that uses the Shodan.io web interface to find information about Internet-facing ports and potential CVEs for specific IPs.
- Creates a file containing a list of open ports and, if listed by Shodan.io, potential CVEs with their description. Users can also obtain a file containing detailed port information (eg HTTP headers, SSL certificates, encryption algorithms).
- Creates files for open ports (eg '80.txt', '443.txt') containing a list of all IPs with that port exposed. These files can be used to run additional tests, such as Nmap script scans or Metasploit modules.
- ShoWdan makes it easy for penetration testers / red teamers to obtain basic Shodan.io information about client systems during an external assessment, and may also be useful for sysadmins, blue teamers, and anyone else interested in monitoring their organization's Internet exposure.

**Installation**

- Clone the repository or download the raw file to your system.
- Make the file executable with `chmod +x showdan.rb`
- Copy or move the file to your path, eg `cp showdan.rb /usr/local/bin`
- Run ShoWdan: `showdan.rb [your arguments]`

Alternatively, you can run it immediately after downloading by invoking Ruby:
- `ruby showdan.rb [your arguments]`
 
**How to use**

`showdan.rb -f [path/to/targets.file] &&/|| -t [targets]`

Options:
- -h, --help                       Display the help menu and exit.
- -f, --file    TARGETS_FILE       File containing target IP addresses
- -t, --targets TARGETS            Comma-separated list of target IP addresses

OPTIONAL:
- -d, --dir     OUTPUT_DIRECTORY   Directory to store results. If it doesn't exit, Showdan will create it.
- -s, --scheme  NAMING_SCHEME      Naming scheme for the output file(s). Default: '[IP]_showdan.txt'
- -p, --p_info                     Write detailed port info listed by Shodan.io (eg HTTP headers) to a file.

Example usage:
- `showdan.rb -f target_ips.txt -d /tmp -p`
  - ShoWdan will perform Shodan.io lookups for all IPs in 'target_ips.txt'. The  output files, including one with detailed port information, will be written to '/tmp'.
- `showdan.rb -t 192.168.1.1,192.168.1.2 -f ips.txt -s shodan.results`
  - ShoWdan will perform Shodan.io lookups for 192.168.1.1, 192.168.1.2 and all IPs in 'ips.txt'. The output files will be named according to the scheme '[IP]_shodan.results'

**Example output**
```
showdan.rb -t 192.168.1.5 -d /tmp/showdan

 ######################################################################
                    _          __    __    _             
                ___| |__   ___/ / /\ \ \__| | __ _ _ __                                                           
               / __| '_ \ / _ \ \/  \/ / _` |/ _` | '_ \                                                          
               \__ \ | | | (_) \  /\  / (_| | (_| | | | |                                                         
               |___/_| |_|\___/ \/  \/ \__,_|\__,_|_| |_|                                                         
                                                                                                                  
                version 1.0 - Erik Wynter (@WynterErik)                                                           

 ######################################################################

[*] Loading targets...
[*] Performing Shodan.io lookup for 192.168.1.5...
----------------------------------------------------------------------
|IP: 192.168.1.5
|
|-Open ports (6):
|--22/tcp - ssh
|--25/tcp - smtp
|--80/tcp - http
|--110/tcp - pop3
|--143/tcp - imap
|--443/tcp - https
|
|-Potential CVE(s) (27):
|--CVE-2014-0117
|--CVE-2017-15906
|--CVE-2014-0118
|--CVE-2016-0736
|--CVE-2015-3185
|--CVE-2015-3184
|--CVE-2018-1312
|--CVE-2016-4975
|--CVE-2016-8612
|--CVE-2014-0226
|--CVE-2014-3523
|--CVE-2017-15710
|--CVE-2017-15715
|--CVE-2013-6438
|--CVE-2017-7679
|--CVE-2018-17199
|--CVE-2017-9788
|--CVE-2014-8109
|--CVE-2017-9798
|--CVE-2016-2161
|--CVE-2018-15919
|--CVE-2014-0231
|--CVE-2013-4352
|--CVE-2019-0220
|--CVE-2014-0098
|--CVE-2018-1283
|--CVE-2016-8743
----------------------------------------------------------------------
```
**Note:** The output files will be formatted as such:
```
cat /tmp/showdan/192.168.1.5_showdan.txt 
Open ports (6):
22/tcp - ssh
25/tcp - smtp
80/tcp - http
110/tcp - pop3
143/tcp - imap
443/tcp - https

Potential CVE(s) (27):
CVE-2014-0117
The mod_proxy module in the Apache HTTP Server 2.4.x before 2.4.10, when a reverse proxy is enabled, allows remote attackers to cause a denial of service (child-process crash) via a crafted HTTP Connection header.

CVE-2017-15906
The process_open function in sftp-server.c in OpenSSH before 7.6 does not properly prevent write operations in readonly mode, which allows attackers to create zero-length files.

CVE-2014-0118
The deflate_in_filter function in mod_deflate.c in the mod_deflate module in the Apache HTTP Server before 2.4.10, when request body decompression is enabled, allows remote attackers to cause a denial of service (resource consumption) via crafted request data that decompresses to a much larger size.
<SNIPPED>
```
**Dependencies**

- 'optparse' (installed by default)
- 'httparty' (gem install 'httparty')
- 'nokogiri' (gem install 'nokogiri')
