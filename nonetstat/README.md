# nonetstat
nonetstat.sh is a bash script that can obtain netstat-like info from /proc/net/tcp and /proc/net/udp in a restricted Linux environment where the netstat command is not enabled.

## How to use ##
Just clone or download the repository/script file to your system. Then navigate to the directory from the command line and run the script according to one of the following ways.
1. Run the script with no arguments: ```bash nonetstat.sh```. In this case, nonetstat will simply read the /proc/net/tcp and /proc/net/udp files on the local system and use them to output a list of tcp and udp connections.
2. Feed one or more files into the script: ```bash nonetstat.sh file1 file2 file3 file4 filex```. This option is convenient if running the script directly on the target system is not possible. Instead, you can simply grab the /proc/net/tcp and/or /proc/net/udp files from the system(s) you are probing and save them to your local box. Then you can call netstat.sh with the saved /proc/net/tcp and/or /proc/net/udp files as arguments. It doesn't matter how many files you provide or how you name them, as long as they are direct copies of /proc/net/tcp and/or /proc/net/udp files.

## Example scenarios ##
1. Running nonetstat without arguments
```
$ bash no_teststat.sh
Showing results for local host with eth0 IP 192.168.1.2.
TCP connections:
0.0.0.0:111 0.0.0.0:0
192.168.1.2:48266 123.125.78.90:443
192.168.1.2:46088 192.168.1.4:443
192.168.1.2:32944 121.154.87.9:443

UDP connections:
192.168.1.2:68 192.168.1.1:67
0.0.0.0:111 0.0.0.0:0
```

2. Feeding files into nonetstat
```
bash no_teststat.sh tcp_file1 udp_file1 udp_file2 tcp_file2 
tcp_file1 connections:
0.0.0.0:222 0.0.0.0:0
192.168.1.3:48794 123.156.78.90:443
192.168.1.3:12644 192.168.1.4:443
192.168.1.3:25468 121.54.87.9:443

udp_file1 connections:
192.168.1.3:78 192.168.1.1:90
0.0.0.0:222 0.0.0.0:0

udp_file2 connections:
192.168.1.5:87 192.168.1.1:85
192.168.1.5:89 123.156.78.90:56
0.0.0.0:333 0.0.0.0:0

tcp_file2 connections:
0.0.0.0:555 0.0.0.0:0
192.168.1.6:46648 123.56.78.90:443
192.168.1.6:35467 192.168.1.4:443
```

