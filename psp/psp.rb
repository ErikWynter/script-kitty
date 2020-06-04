#!/usr/bin/env ruby

require 'optparse'

def help(logo,help=false)
  options = {'directory' => './'}
  parser = OptionParser.new do |opts|
    opts.banner = "Usage: #{$0} [file1] [file2] [file3] ... [filex]"
    opts.on("-h", "--help", "Display this menu and exit") do
      pr.print_help = true
    end
    opts.on("-d", "--dir     OUTPUT_DIRECTORY", "Directory to store results.\n\t\t\t\t     If it doesn't exist, PSP creates it.") do |directory|
      options['directory'] = directory;
    end
  end
  parser.parse!

  if help == true
    logo.each { |i| puts i }
    puts parser
    puts "\n  Example: #{$0} scan.nmap ports.gnmap"
    puts "  Example: #{$0} portscan.nmap -d /tmp/port_files"
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
    
    port_hash = {}
    ip_hash = {}
    ip_arr = []
    hosts_info.each do |data|  
      lines = data.split("\n")
      ip = lines[0]
      ip_arr.append(ip)
      lines.shift
      lines.each do |l|
        if l.include?("open") && !l.include?("filtered")
          port = l.split("/")[0]
          if port_hash.include?(port)
            port_hash[port].append(ip)
          else
            port_hash[port] = [ip]
          end
          if ip_hash.include?(ip)
            ip_hash[ip].append(port)
          else
            ip_hash[ip] = [port]
          end
        end
      end
    end
    if port_hash.length > 0
      return ip_arr, port_hash, ip_hash
    else
      return [ip_arr]
    end
  end

  def gnmap
    @pr.print_info("Treating `#{@file}` as a .gnmap file.")
    hosts_info = @contents.split("Host: ") #split file contents into chunkcs for each host
    hosts_info.shift #remove gnmap initiation info
    
    port_hash = {}
    ip_hash = {}
    ip_arr = []
    hosts_info.each do |data|
      ip = data.split(" ")[0]
      unless ip_arr.include?(ip)
        ip_arr.append(ip)
      end
      if data.include?("open")
        port_info = data.split("Ports: ")[1].split(" ")
        port_info.each do |p|
          if p.include?("open") && !p.include?("filtered")
            port = p.split("/")[0]
            if port_hash.include?(port)
              port_hash[port].append(ip)
            else
              port_hash[port] = [ip]
            end
            if ip_hash.include?(ip)
              ip_hash[ip].append(port)
            else
              ip_hash[ip] = [port]
            end
          end
        end
      end
    end
    if port_hash.length > 0
      return ip_arr, port_hash, ip_hash
    else
      return [ip_arr]
    end
  end

  def write_files(results)
    ip_arr = results[0]
    port_hash = results[1]
    ip_hash = results[2]
    file_base = @file.sub(/\.[^.]+\z/, '')
    
    if port_hash
      @pr.print_good("Creating text file(s) with live hosts for the #{port_hash.length} open port(s) found.")
      port_hash.each do |port,ips|
        port_file = "#{port}.txt"
        File.open(port_file, "w") {
          |f| ips.each do |ip|
            f.write("#{ip}\n")
          end
        }
      end
  
      ip_port_file = "#{file_base}.ports"
      @pr.print_good("Writing #{ip_hash.length} IPs and their respective open ports to `#{ip_port_file}`.")
      File.open(ip_port_file, "w") {
        |g| ip_hash.each do |ip,ports|
          g.write("#{ip} - #{ports.join(" ")}\n")  
        end
      }
    end

    ip_file = "#{file_base}.ips"
    @pr.print_good("Writing all #{ip_arr.length} IPs in `#{@file}` to `#{ip_file}`.")
    File.open(ip_file, "w") {
      |h| ip_arr.each do |ip|
        h.write("#{ip}\n")  
      end
    }
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

  if ARGV.length() == 0
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
  directory += "/" if directory[-1] != "/"

  pr.print_info("Getting ready to parse some files...")
  ARGV.each do |file| 
    unless File.file?(file)
      pr.print_warning("Skipping `#{file}` because it does not exist. Please check for typos.")
      next
    end

    begin
      contents = File.open(file).read
      parse = Parser.new(file,contents,directory)
      if contents.include?("report for")
        results = parse.nmap
      elsif contents.include?("Host:")
        results = parse.gnmap
      else
        pr.print_warning("Skipping `#{file}` because it is not a compatible filetype. Please provide .nmap and .gnmap files only.")
        next
      end
      unless results.length == 3
        pr.print_failure("#{file} does not contain any hosts with open ports.")
      end
      parse.write_files(results)
    rescue
      raise #TODO: remove after testing
      pr.print_failure("An error occurred while trying to parse `#{file}`. Skipping...")
      pr.print_warning("Please provide only .nmap and .gnmap files.\n\n")
      next
    end
  end
  pr.print_info("No tasks left. Time for a well-deserved nap.")
end
