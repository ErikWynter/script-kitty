# ShoWdan v1.0
**About**

- ShoWdan is a simple web scraper that uses the Shodan.io web interface to find information about Internet-facing ports and potential CVEs for specific IPs. It will also obtain the CVSS score for each CVE by querying cvedetails.com.
- Creates a file containing a list of open ports and, if listed by Shodan.io, potential CVEs with their CVSS score and description. Users can also obtain a file containing detailed port information (eg HTTP headers, SSL certificates, encryption algorithms).
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
|-Potential CVE(s) (2):
|--CVE-2019-13917       CVSS: 10.0
|--CVE-2019-10149       CVSS: 7.5
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

Potential CVE(s) (2):
CVE-2019-13917 - CVSS: 10.0
Exim 4.85 through 4.92 (fixed in 4.92.1) allows remote code execution as root in some unusual configurations that use the ${sort } expansion for items that can be controlled by an attacker (e.g., $local_part or $domain).

CVE-2019-10149 - CVSS: 7.5
A flaw was found in Exim versions 4.87 to 4.91 (inclusive). Improper validation of recipient address in deliver_message() function in /src/deliver.c may lead to remote command execution.
```
**Dependencies**

- 'optparse' (installed by default)
- 'httparty' (gem install 'httparty')
- 'nokogiri' (gem install 'nokogiri')
