#!/usr/bin/env ruby

BEGIN { $VERBOSE = nil } #to ignore HTTParty deprecation warning about response.nil which is caused by Nokogiri
##Warning[:deprecated] = false doesn't work with all ruby versions
#if defined?(Warning) && Warning.respond_to?(:[]=)
#  Warning[:deprecated] = false
#end

['optparse','httparty','nokogiri'].each(&method(:require))

def help(logo,print_help=false)
  options = {'scheme' => 'showdan.txt', 'p_info' => nil}
  parser = OptionParser.new do |opts|
    opts.banner = "Usage: #{$0} -f [path/to/targets.file] &&/|| -t [targets]"
    opts.on("-h", "--help", "Display this menu and exit") do
      print_help = true
    end
    opts.on("-f", "--file    TARGETS_FILE", "File containing target IP addresses") do |file|
      options['file'] = file;
    end
    opts.on("-t", "--targets TARGETS", "Comma-separated list of target IP addresses\n\n    OPTIONAL:") do |targets|
      options['targets'] = targets;
    end
    opts.on("-d", "--dir     OUTPUT_DIRECTORY", "Directory to store results. If it doesn't exit, shoWdan will create it.") do |directory|
      options['directory'] = directory;
    end
    opts.on("-s", "--scheme  NAMING_SCHEME", "Naming scheme for the output file(s). Default: '[IP]_showdan.txt'") do |scheme|
      options['scheme'] = scheme;
    end
    opts.on("-p", "--p_info", "Write detailed port info listed by Shodan.io (eg HTTP headers) to a file.") do |p_info|
      options['p_info'] = p_info;
    end
  end
  parser.parse!

  if print_help == true
    logo.each { |item| puts item }
    puts parser
    puts "\n    Example: #{$0} -f my_target_ips.txt -d /tmp -p"
    puts "    Example: #{$0} -t 192.168.1.1,192.168.1.2 -f ips.txt -s shodan.results\n\n"
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

  def cve_details(cve)
    url = "https://www.cvedetails.com/cve/" + cve
    response = HTTParty.get(url)
    if response.body.nil? || response.body.empty?
      return
    end
    doc = Nokogiri::HTML(response)
    cvss = doc.at('div.cvssbox').text
  end


  def shodan_check(ip, ports_hash,p_info,scheme,cve_hash)
    out_file = @out_file + ip.to_s + "_" + scheme
    port_info_file = @out_file + ip.to_s + "_port_info_" + scheme

    url = "https://shodan.io/host/"+ip.to_s
    response = HTTParty.get(url)
    if response.body.nil? || response.body.empty?
      @pr.print_error("IP: #{ip} - Shodan did not return a response.")
      return [ports_hash, cve_hash]
    end
    doc = Nokogiri::HTML(response)

    ports_info_hash = {}
    ports_info = doc.css("li.service.service-long")

    unless ports_info && ports_info.length() > 0
      @pr.print_error("IP: #{ip} - No open ports found.")
      return [ports_hash, cve_hash]
    end

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
      if p_info == true
        File.open(port_info_file, "w") {
          |g| ports_info_hash.each do |port,info|
            f.write("#{port}/#{info[0]} - #{info[1]}\n")
            g.write("-" *70 + "\n#{port}/#{info[0]} - #{info[1]}\n")
            g.write("#{info[2]}\n\n")
            puts "|--#{port}/#{info[0]} - #{info[1]}"  
          end
          g.write("-" *70 + "\n")
        }
      else
        ports_info_hash.each do |port,info|
          f.write("#{port}/#{info[0]} - #{info[1]}\n")
          puts "|--#{port}/#{info[0]} - #{info[1]}"  
        end
      end
      puts "|"

      vuln_hash = {}
      if doc.css("i.fa.fa-exclamation-triangle").empty?
        puts "|-No potential CVE(s) listed."
      else
        f.write("\n")
        doc.css('tr').each do |node|
          if node.search('th').text.include? 'CVE'
            cve = node.search('th').text
            cvss = cve_details(cve)
            if cvss.to_s.strip().empty?
              cvss = "N/A"
            end
            cve_hash[cve] ? nil : cve_hash[cve] = cvss #map cve with cvss if it's not already in cve_hash
            descr = node.search('td').text
            vuln_hash[cve] = [cvss, descr]
          end
        end
        f.write("Potential CVE(s) (#{vuln_hash.length}):\n")
        puts ("|-Potential CVE(s) (#{vuln_hash.length}):")
        vuln_hash.each do |key,value|
          f.write("#{key} - CVSS: #{value[0]}\n")
          f.write("#{value[1]}\n")
          puts "|--#{key}\tCVSS: #{value[0]}"
        end
      end
    }
    [ports_hash, cve_hash]
  end
end

if $0 == __FILE__
  pr = Color_print.new()
  line = "\n " + "#" * 70
  title = """     \e[1;32m               _          \e[1;31m__    __    \e[1;32m_             
                ___| |__   ___\e[1;31m/ / /\\ \\ \\\e[1;32m__| | __ _ _ __  
               / __| '_ \\ / _ \e[1;31m\\ \\/  \\/ /\e[1;32m _` |/ _` | '_ \\ 
               \\__ \\ | | | (_) \e[1;31m\\  /\\  /\e[1;32m (_| | (_| | | | |
               |___/_| |_|\\___/ \e[1;31m\\/  \\/\e[1;32m \\__,_|\\__,_|_| |_|   

                \e[1;34mversion 1.0 - \e[1;33mErik Wynter \e[1;34m(@WynterErik)\e[00m"""
  logo = [line,title,line,"\n"]
  options = help(logo)

  unless options['file'] or options['targets']
    pr.print_warning("Please provide at least one target IP or file using the -t or -f switch, respectively.")
    pr.print_info("Loading help menu:")
    help(logo,true)
  end

  targets = []

  #Add -f to targets if provided and file exists
  if options['file']
    unless File.exists? options['file']
      pr.print_warning("The file provided with -f does not exist. Please select a valid file. Quitting!")
      exit
    end
  end

  ['file','targets'].each { |i| i ? targets.append(options[i]) : targets.append(nil) }

  #print logo
  logo.each { |item| puts item }

  #if -d is provided, check if directory already exists, otherwise create it
  if options['directory']
    directory = options['directory']
    system("[ -d #{directory} ]") 
    unless $?.exitstatus == 0
      system("mkdir #{directory}")
      unless $?.exitstatus == 0
        pr.print_error("Failed to create #{directory} to store the results.")
        pr.print_warning("Quitting!")
        exit
      end
      pr.print_info("Created output directory '#{directory}'")
    end
  else
    directory = "."
  end
  directory += "/" if directory[-1] != "/"

  #load targets
  sho = Showdan.new(targets, directory)
  targets = sho.parse_targets
  ips = targets[0]
  domains = targets[1]
  
  unless domains.length == 0
    sho.lookup(domains)
  end

  #start performing shodan lookups
  ports_hash = {} #hash to map ports with all IPs that have that port open, used to create files later
  cve_hash = {} #hash to map cves to cvss scores, used to prevent unnecessary lookups on cvedetails.com for duplicate cves accross IPs
  ips.each do |ip|
    pr.print_info("Performing Shodan.io lookup for #{ip}...")
    results = sho.shodan_check(ip,ports_hash,options['p_info'],options['scheme'],cve_hash)
    ports_hash = results[0]
    cve_hash = results[1]
    puts "-" * 70
  end

  #write port files containing IPs
  ports_hash.each do |port,ip_list|
    File.open("#{directory}#{port}.txt", "w") {
      |f| f.puts(ip_list)
    }
  end

  #TODO: add DNS lookups for domains
  #TODO: strip domain names off a bunch of stuff if present
  #TODO: deal with warning issue (see top)
  #https://ruby-doc.org/stdlib-2.7.0/libdoc/optparse/rdoc/OptionParser.html
end
