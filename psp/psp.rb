#!/usr/bin/env ruby

require 'optparse'

def help(logo,help=false)
  options = {'directory' => './', 'scripts' => 'true', 'enum_dir' => './enum' }
  parser = OptionParser.new do |opts|
    opts.banner = "Usage: #{$0} [file1] [file2] [file3] ... [filex]"
    opts.on("-h", "--help", "Display this menu and exit") do
      pr.print_help = true
    end
    opts.on("-d", "--dir      OUTPUT DIRECTORY", "Directory to store results. If it\n\t\t\t\t     doesn't exist, PSP creates it.") do |directory|
      options['directory'] = directory;
    end
    opts.on("-s", "--scripts  RUN SCRIPT SCANS", "Perform Nmap script scans against\n\t\t\t\t     discovered ports (default).\n\t\t\t\t     Disable with value `false`.") do |scripts|
      options['scripts'] = scripts;
    end
    opts.on("-e", "--enum_dir ENUM DIRECTORY", "Directory to store the result of\n\t\t\t\t     enumeration via Nmap script scans.\n\t\t\t\t     Default: `./enum`.") do |enum_dir|
      options['enum_dir'] = enum_dir;
    end
  end
  parser.parse!

  if help == true
    logo.each { |i| puts i }
    puts parser
    puts "\n  Example: #{$0} scan.nmap ports.gnmap"
    puts "  Example: #{$0} portscan.nmap -d /tmp/port_files"
    puts "  Example: #{$0} portscan.nmap -s false"
    exit
  end
  options
end

class Color_print
  #enable colored printing
  def initialize
    @red = "\033[01;31m"
    @green = "\033[01;32m"
    @yellow = "\033[01;33m"
    @blue = "\033[01;34m"
    @white = "\033[00m"
  end

  def print_info(text)
    txt_info = @white + "[" + @blue + "*" + @white + "]"
    puts "#{txt_info} #{text}"
  end

  def print_good(text)
    txt_info = @white + "[" + @green + "+" + @white + "]"
    puts "#{txt_info} #{text}"
  end
  
  def print_warning(text)
    txt_info = @white + "[" + @yellow + "!" + @white + "]"
    puts "#{txt_info} #{text}"
  end

  def print_failure(text)
    txt_info = @white + "[" + @red + "-" + @white + "]"
    puts "#{txt_info} #{text}"
  end
end

class Parser
  def initialize(file,contents,directory)
    @file = file
    @contents = contents
    @directory = directory
    @pr = Color_print.new()
  end

  def nmap
    @pr.print_info("Treating `#{@file}` as a .nmap file.")
    hosts_info = @contents.split("report for ") #split file contents into chunkcs for each host
    hosts_info.shift #remove nmap initiation info
    ct = 0
    port_hash = {}
    ip_arr = []
    hosts_info.each do |data|  
      lines = data.split("\n")
      ip = lines[0]
      ip_arr.append(ip)
      lines.shift
      lines.each do |l|
        if l.include?("open") && !l.include?("filtered")
          port = l.split("/")[0]
          ct += 1
          if port_hash.include?(port)
            port_hash[port].append(ip)
          else
            port_hash[port] = [ip]
          end
        end
      end
    end
    if ct > 0 && ct % 100000 == 0
        @pr.print_info("Read #{ct} lines so far...")
      end
    ip_arr = ip_arr.uniq
    if port_hash.length > 0
      return ip_arr, port_hash
    else
      return [ip_arr]
    end
  end

  def gnmap
    @pr.print_info("Treating `#{@file}` as a .gnmap file.")
    hosts_info = @contents.split("Host: ") #split file contents into chunkcs for each host
    hosts_info.shift #remove gnmap initiation info
    ct = 0
    port_hash = {}
    ip_arr = []
    hosts_info.each do |data|
      if data.include?("Up")
        ip = data.split(" ")[0]
      elsif data.include?("open")
        ip = data.split(" ")[0]
        port_info = data.split("Ports: ")[1].split(" ")
        port_info.each do |p|
          if p.include?("open") && !p.include?("filtered")
            port = p.split("/")[0]
            ct += 1
            if port_hash.include?(port)
              port_hash[port].append(ip)
            else
              port_hash[port] = [ip]
            end
          end
        end
      end
      if ip
        ip_arr.append(ip)
      end
      if ct > 0 && ct % 100000 == 0
        @pr.print_info("Read #{ct} lines so far...")
      end
    end
    ip_arr = ip_arr.uniq
    if port_hash.length > 0
      return ip_arr, port_hash
    else
      return [ip_arr]
    end
  end

  def write_files(results,directory)
    ip_arr = results[0]
    port_hash = results[1]
    file_base = @file.sub(/\.[^.]+\z/, '')
    file_base = file_base.split("/")
    file_base = file_base[file_base.length-1]
    
    if port_hash
      @pr.print_good("Creating text file(s) with live hosts for the #{port_hash.length} open port(s) found.")
      port_hash.each do |port,ips|
        port_file = "#{directory}#{port}.txt"
        File.open(port_file, "w") {
          |f| ips.each do |ip|
            f.write("#{ip}\n")
          end
        }
      end
    end

    ip_file = "#{directory}#{file_base}.ips"
    @pr.print_good("Writing all #{ip_arr.length} IPs in `#{@file}` to `#{ip_file}`.")
    File.open(ip_file, "w") {
      |h| ip_arr.each do |ip|
        h.write("#{ip}\n")  
      end
    }
  end
end

class Script_scans
  def initialize(parse_results,directory,enum_dir)
    @pr = Color_print.new()
    @directory = directory
    @enum_dir = enum_dir
    @port_hash = parse_results[1]
    @script_hash = {
      '21' => ['FTP', 'ftp-anon'],
      '25' => ['SMTP', 'smtp-open-relay'],
      '445' => ['SMB', 'smb-security-mode,smb-enum-domains,smb-enum-shares,smb-system-info,smb-os-discovery,smb-vuln-cve-2017-7494'],
      '111' => ['NFS', 'nfs-ls,nfs-showmount,nfs-statfs'],
      '161' => ['SNMP', 'snmp-processes'],
      '389' => ['LDAP', 'ldap-rootdse'],
      '1433' => ['MSSQL', 'ms-sql-empty-password,ms-sql-info,ms-sql-ntlm-info'],
      '3306' => ['MYSQL', 'mysql-empty-password,mysql-info'],
      '1521' => ['ORACLE_TNS', 'oracle-tns-version'],
      '80' => ['HTTP', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title'],
      '81' => ['HTTP(S)', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title,ssl-cert'],
      '8000' => ['HTTP(S)', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title,ssl-cert'],
      '8001' => ['HTTP(S)', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title,ssl-cert'],
      '8002' => ['HTTP(S)', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title,ssl-cert'],
      '8080' => ['HTTP(S)', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title,ssl-cert'],
      '8081' => ['HTTP(S)', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title,ssl-cert'],
      '8082' => ['HTTP(S)', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title,ssl-cert'],
      '8083' => ['HTTP(S)', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title,ssl-cert'],
      '8084' => ['HTTP(S)', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title,ssl-cert'],
      '8085' => ['HTTP(S)', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title,ssl-cert'],
      '8086' => ['HTTP(S)', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title,ssl-cert'],
      '8087' => ['HTTP(S)', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title,ssl-cert'],
      '8088' => ['HTTP(S)', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title,ssl-cert'],
      '8089' => ['HTTP(S)', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title,ssl-cert'],
      '8090' => ['HTTP(S)', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title,ssl-cert'],
      '9090' => ['HTTP(S)', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title,ssl-cert'],
      '8181' => ['HTTP(S)', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title,ssl-cert'],
      '2301' => ['HTTP', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title'],
      '443' => ['HTTPS', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title,ssl-cert'],
      '8443' => ['HTTPS', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title,ssl-cert'],
      '2443' => ['HTTPS', 'http-headers,http-put,http-methods,http-robots.txt,http-shellshock,http-title,ssl-cert']
    }
  end

  def run_scripts
    @http_ports = []
    @port_hash.each do |port,ip_list|
      if @script_hash.include?(port)
        protocol = @script_hash[port][0]
        scripts = @script_hash[port][1]
        if scripts.split(",").length > 1
          if protocol.include?("HTTP")
            @script_out_file = "#{protocol.split('(S)')[0]}-#{port}-scripts"
          else
            @script_out_file = "#{protocol.downcase}-scripts"
          end
        else
          @script_out_file = scripts
        end
        @pr.print_info("Launching Nmap scripts for #{protocol}...")
        `nmap --disable-arp-ping -Pn -n -vv -p #{port} --script #{scripts} -oA #{@enum_dir}#{@script_out_file} -iL #{@directory}#{port}.txt`
      end
    end
   end  

  def create_enum_dir
    system("[ -d #{@enum_dir} ]") 
    unless $?.exitstatus == 0
      system("mkdir #{@enum_dir}")
      unless $?.exitstatus == 0
        @pr.print_failure("Failed to create #{@enum_dir} to store the script scan results.")
        @pr.print_warning("Quitting!")
        exit
      end
      @pr.print_info("Created directory '#{@enum_dir}' to store the script scan results")
    end
  end
end

if $0 == __FILE__
  warning = "[" + "\033[01;33m" + "!" + "\033[00m" + "]"
  info = "[" + "\033[01;34m" + "*" + "\033[00m" + "]"
  success = "[" + "\033[01;32m" + "+" + "\033[00m" + "]"
  failure = "[" + "\033[01;31m" + "-" + "\033[00m" + "]"

  banner = "*" * 70 + "\n\t\033[01;32mPSP : PortScan Parser v1.0\033[00m - \033[01;34mErik Wynter (@wyntererik)\033[00m\n" + "*" * 70
  descr1 = "\nTurn portscan results into text files grouping IPs by port."
  descr2 = "Compatible with .nmap and .gnmap files."
  logo = [banner,descr1,descr2] 

  pr = Color_print.new()

  if ARGV.length == 0
    pr.print_warning("Please provide at least one file to parse.")
    pr.print_info("Loading help menu:")
    help(logo,true)
  end

  options = help(logo) 
  
  directory = options['directory']
  system("[ -d #{directory} ]") 
  unless $?.exitstatus == 0
    system("mkdir #{directory}")
    unless $?.exitstatus == 0
      pr.print_failure("Failed to create #{directory} to store the results.")
      pr.print_warning("Quitting!")
      exit
    end
    pr.print_info("Created output directory '#{directory}'")
  end
  directory << "/" if directory[-1] != "/"

  scripts = options['scripts']
  enum_dir = options['enum_dir']
  enum_dir << "/" if enum_dir[-1] != "/"

  pr.print_info("Getting ready...")
  file = ARGV[0]
  unless File.file?(file)
    pr.print_failure("Can't parse `#{file}` because it does not exist. Please check for typos.")
    pr.print_warning("Quitting!")
    exit
  end

  begin
    contents = File.open(file).read
    parse = Parser.new(file,contents,directory)
    if contents.include?("report for")
      results = parse.nmap
    elsif contents.include?("Host:")
      results = parse.gnmap
    else
      pr.print_failure("Can't parse `#{file}` because it is not a compatible filetype. Please provide a .nmap or .gnmap file.")
      pr.print_warning("Quitting!")
      exit
    end
    unless results.length == 2
      pr.print_failure("#{file} does not contain any hosts with open ports.")
    end
    parse.write_files(results,directory)
  rescue
    pr.print_failure("The following error occurred while trying to parse `#{file}`.")
    pr.print_warning("Please provide only .nmap and .gnmap files.\n\n")
    raise
  end

  begin
    if scripts == 'true' && results.length > 0
      script = Script_scans.new(results, directory, enum_dir)
      script.create_enum_dir
      script.run_scripts
    end
  rescue
    pr.print_failure("The following error occurred while trying to run Nmap script scans.")
    raise
  end
    
  pr.print_info("No tasks left. Time for a well-deserved nap.")
end
