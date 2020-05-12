#!/usr/bin/env ruby

BEGIN { $VERBOSE = nil } #to ignore HTTParty deprecation warning about response.nil which is caused by Nokogiri
##Warning[:deprecated] = false doesn't work with all ruby versions
#if defined?(Warning) && Warning.respond_to?(:[]=)
  #Warning[:deprecated] = false
#end

['getopt/std','httparty','nokogiri'].each(&method(:require))
def help(logo)
  logo.each { |item| puts item }
  puts "\n  Usage: #{$0} -f /path/to/ips_and_domains.txt"
  puts "\n  -f\tFile containing IP addresses and/or domain names"
  puts "  -t\tComma-separated list of IP addresses and/or domain names"
  puts "  -o\tExisting directory to store the results. If not specified, the\n\tresults will be stored in the present working directory."
  puts "\n  Example: #{$0} -f my_ips_and_domains.txt -o /tmp"
  puts "  Example: #{$0} -f ips_and_domains.txt -t 192.168.1.1,my.example.site"
  puts "\n"
  exit
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

  def print_error(text)
    txt_info = @white + "[" + @red + "-" + @white + "]"
    puts "#{txt_info} #{text}"
  end
end

class Showdan
  def initialize(targets,out_file)
    @out_file = out_file
    @pr = Color_print.new()
    
    if targets[0].nil?
      @targets = []
    else
      @targets = File.open(targets[0]).read.split("\n")
    end
    unless targets[1].nil?
      @targets += targets[1].split(",")
    end
  end

  def parse_targets
    @pr.print_info("Loading targets...")
    ips = []
    domains = []
    @targets.each do |item|
      begin
        ips += IPAddr.new(item).to_range.to_a
      rescue IPAddr::InvalidAddressError
        #first strip a bunch of stuff if present
        #domain = ActionView::Base.full_sanitizer.sanitize(line).split[-1]
        #domain.gsub! "http://", ""
        #domain.gsub! "https://", ""
        #domain.gsub! "www.", ""
        #domain.gsub! "/", ""
        #@company_domain = domain
        
        #the below regex will filter out most illegal domain names
        #it should exclude domains starting or ending with '-' but that doesn' t work so the two extra statements cover this
        #source: https://stackoverflow.com/questions/10306690/what-is-a-regular-expression-which-will-match-a-valid-domain-name-without-a-subd
        begin
          if item.match(/^(((?!-))(xn--|_{1,1})?[a-z0-9-]{0,61}[a-z0-9]{1,1}\.)*(xn--)?([a-z0-9][a-z0-9\-]{0,60}|[a-z0-9-]{1,30}\.[a-z]{2,})$/) and item[0] != '-' and item.split(".")[-2][-1] != '-'
            domains.append(item)
            next
          end
        rescue
        end
        #print this if an item did not match the above regex or threw an error
        @pr.print_error("Skipping #{item} because it is not a valid IP address or domain.")
      end  
    end
    return ips,domains
  end

  def lookup(domains)
    return
  end

  def shodan_check(ip, ports_hash)
    out_file = @out_file + ip.to_s + "_showdan.txt"
    port_info_file = @out_file + ip.to_s + "_port_info" + "_showdan.txt"

    url = "https://shodan.io/host/"+ip.to_s
    response = HTTParty.get(url)
    if response.body.nil? || response.body.empty?
      return
    end
    doc = Nokogiri::HTML(response)

    ports_info_hash = {}
    ports_info = doc.css("li.service.service-long")
    ports_info.each do |port|
      no = port.css("div.port").text
      prot = port.css("div.protocol").text
      service = port.css("div.state").text
      info = port.css("div.service-main").text.strip()
      ports_info_hash[no] = [prot,service,info]
      if not ports_hash.keys.include? no
        ports_hash[no] = [ip]
      else
        ports_hash[no].append(ip)
      end
    end

    File.open(out_file, "w") {
      |f| puts "-" *70 + "\n|IP: #{ip}\n|"
      f.write("Open ports (#{ports_info_hash.length}):\n")
      puts "|-Open ports (#{ports_info_hash.length}):"
      # it should only write the port_info file if requested by the user
      File.open(port_info_file, "w") {
        |g| ports_info_hash.each do |port,info|
          f.write("#{port}/#{info[0]} - #{info[1]}\n")
          g.write("-" *70 + "\n#{port}/#{info[0]} - #{info[1]}\n")
          g.write("#{info[2]}\n\n")
          puts "|--#{port}/#{info[0]} - #{info[1]}"
        end
        g.write("-" *70 + "\n")
      }
      puts "|"
      #create file for each port with IP?

      vuln_hash = {}
      if doc.css("i.fa.fa-exclamation-triangle").empty?
        puts "|-No potential CVE(s) listed."
      else
        f.write("\n")
        doc.css('tr').each do |node|
          if node.search('th').text.include? 'CVE'
            cve = node.search('th').text
            descr = node.search('td').text
            vuln_hash[cve] = descr
          end
        end
        f.write("Potential CVE(s) (#{vuln_hash.length}):\n")
        puts ("|-Potential CVE(s) (#{vuln_hash.length}):")
        vuln_hash.each do |key,value|
          f.write("#{key}\n")
          f.write("#{value}\n")
          puts "|--#{key}"
        end
      end
    }
    ports_hash
  end
end


if $0 == __FILE__
  line = "\n " + "#" * 70
  title = """     \e[1;32m               _          \e[1;31m__    __    \e[1;32m_             
                ___| |__   ___\e[1;31m/ / /\\ \\ \\\e[1;32m__| | __ _ _ __  
               / __| '_ \\ / _ \e[1;31m\\ \\/  \\/ /\e[1;32m _` |/ _` | '_ \\ 
               \\__ \\ | | | (_) \e[1;31m\\  /\\  /\e[1;32m (_| | (_| | | | |
               |___/_| |_|\\___/ \e[1;31m\\/  \\/\e[1;32m \\__,_|\\__,_|_| |_|   

                \e[1;34mversion 0.1 - \e[1;33mErik Wynter \e[1;34m(@WynterErik)\e[00m"""
  logo = [line,title,line]

  if ARGV.length == 0
    help(logo)
  end
  pr = Color_print.new()

  opt = Getopt::Std.getopts("f:t:o:")
  unless opt['f'] or opt['t']
    pr.print_warning("Please specify target IPs and/or domains to check using the -f and/or -t switches. Quitting!") 
    exit
  end

  targets = []

  #Add -f to targets if provided and file exists
  if opt.include? 'f'
    unless File.exists? opt['f']
      pr.print_warning("The file provided with -f does not exist. Please select a valid file. Quitting!")
      exit
    end
  else
    opt['f'] = nil
  end

  #Add -t to targets if provided
  unless opt.include? 't'
    opt['t'] = nil 
  end

  targets.append(opt['f'],opt['t'])

  #set output directory to pwd if -o is not provided, and always append '/' unless the user has already done this
  opt['o'] = "." if opt['o'].nil?
  opt['o'] += "/" if opt['o'][-1] != "/"

  #print logo and start
  logo.each { |item| puts item }
  puts
  sho = Showdan.new(targets, opt['o'])
  targets = sho.parse_targets
  ips = targets[0]
  domains = targets[1]
  
  unless domains.length == 0
    sho.lookup(domains)
  end

  ports_hash = {} #hash to map ports with all IPs that have that port open, used to create files later
  ips.each do |ip|
    pr.print_info("Performing Shodan.io lookup for #{ip}...")
    ports_hash = sho.shodan_check(ip,ports_hash)
    puts "-" * 70
  end

  ports_hash.each do |port,ip_list|
    File.open("#{opt['o']}#{port}.txt", "w") {
      |f| f.puts(ip_list)
    }
  end

  #TODO: change version number in logo
  #TODO: check if -o directory exists, otherwise create it
  #TODO: strip domain names off a bunch of stuff if present
  #TODO: add DNS lookups for domains
  #TODO: replace getopt with option parser and deal with warning issue
  #https://ruby-doc.org/stdlib-2.7.0/libdoc/optparse/rdoc/OptionParser.html
end