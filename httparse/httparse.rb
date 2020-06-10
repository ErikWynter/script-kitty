#!/usr/bin/env ruby

require 'optparse'

def help(logo,print_help=false)
  options = {'scheme' => 'httparsed'}
  parser = OptionParser.new do |opts|
    opts.banner = "Usage: #{$0} [file1] [file2] [file3] ... [filex]"
    opts.on("-h", "--help", "Display this menu and exit") do
      print_help = true
    end
    opts.on("-d", "--dir     OUTPUT_DIRECTORY", "Directory to store results.\n\t\t\t\t     If it doesn't exist, Showdan creates it.") do |directory|
      options['directory'] = directory;
    end
    opts.on("-s", "--scheme  NAMING_SCHEME", "Naming scheme for the output file(s).\n\t\t\t\t     Default: 'ftparsed_[inputfile].'\n\t\t\t\t     For multiple input files, the name of\n\t\t\t\t     each file is appended to the scheme.") do |scheme|
      options['scheme'] = scheme;
    end
  end
  parser.parse!

  if print_help == true
    logo.each { |i| puts i }
    puts parser
    puts "\n  Example: #{$0} nmap_ftp_results1.txt nmap_ftp_results2.txt"
    puts "  Example: #{$0} scan1.txt -o results"
    exit
  end
  options
end

def add_results(results,ip,port,risky_methods,title)
  if results.include? ip
    results[ip].append([port,risky_methods,title])
  else
    results[ip] = [[port,risky_methods,title]]
  end
  results
end

if $0 == __FILE__
  warning = "[" + "\033[01;33m" + "!" + "\033[00m" + "]"
  info = "[" + "\033[01;34m" + "*" + "\033[00m" + "]"
  success = "[" + "\033[01;32m" + "+" + "\033[00m" + "]"
  failure = "[" + "\033[01;31m" + "-" + "\033[00m" + "]"

  banner = "*" * 70 + "\n\t\t\033[01;32mHTTP Parse v1.0\033[00m - \033[01;34mErik Wynter (@wyntererik)\033[00m\n" + "*" * 70
  descr1 = "\nEasily parse the results of Nmap's 'http-title' and 'http-methods' NSE scripts."
  descr2 = "Compatible with .nmap files or copy-pasted 'http-title' and 'http-methods' output."
  logo = [banner,descr1,descr2] 

  if ARGV.length() == 0
    puts "#{warning} Please provide at least one file to parse."
    puts "#{info} Loading help menu:"
    help(logo,true)
  end

  options = help(logo) 
  scheme = options['scheme']

  if options['directory']
      directory = options['directory']
      system("[ -d #{directory} ]") 
      unless $?.exitstatus == 0
        system("mkdir #{directory}")
        unless $?.exitstatus == 0
          puts("#{failure} Failed to create #{directory} to store the results.")
          puts("#{warning} Quitting!")
          exit
        end
        puts("#{info}Created output directory '#{directory}'")
      end
    else
      directory = "."
    end
    directory += "/" if directory[-1] != "/"

  ARGV.each do |file| 
    results = {}
    begin
      hosts_info = File.open(file).read.split("report for ") #split file contents into chunkcs for each host
      hosts_info.shift #remove nmap initiation info
      unless hosts_info.to_s.include?("http-methods") || hosts_info.to_s.include?("http-title")
        puts "#{failure} #{file}: The file does not contain any HTTP title or methods information."
        next
      end
      hosts_info.each do |data|
        risky_methods = []
        title = nil
        port = nil
        ct = 0
        if data.include?("http-methods") || data.include?("http-title")
          lines = data.split("\n")
          ip = lines[0].strip
          lines.each do |line|
            if line.include?("/tcp") && line.include?("open")
              if ct > 0
                results = add_results(results,ip,port,risky_methods,title)
                risky_methods = []
                title = nil
                ct = 0
              end
              port = line.split("/tcp")[0]
            elsif line.include? "risky methods:"
              risky_methods = line.split("methods: ")[1]
            end
            if port && risky_methods.length > 0
              ct += 1
              if ct == 2
                if line.include? "http-title"
                  unless line.include?("Site doesn't have a title") || line.include?("Did not follow redirect")
                    title = line.split("title: ")[1]
                  end
                end
              elsif ct == 3
                results = add_results(results,ip,port,risky_methods,title)
              end
            end
          end
        end
      end
    rescue
      raise #TODO REMOVE AFTER TESTING
      puts "#{failure} Unable to parse '#{file}'."
      puts "#{warning} Please provide only .nmap files or files containing copy-pasted Nmap output.\n\n"
      next
    end
    puts "#{success} #{file}: Found HTTP titles and/or risky methods for #{results.length()} hosts."
    if ARGV.length() == 1
      if scheme == "httparsed"
        scheme += ".txt"
      end
      out_file = directory + scheme
    else
      if file.include? "/"
        f_scheme = file.split("/")
        f_scheme = f_scheme[f_scheme.length() -1]
      end
      scheme = scheme.delete_suffix('_') #remove prevent getting "_" twice in a row at the end of scheme
      out_file = directory + scheme + "_" + f_scheme
    end
    puts "#{info} Writing results to '#{out_file}'.\n"
    puts "Affected hosts:"
    hosts = results.keys
    hosts = hosts.each_slice(5).to_a
    hosts.each { |ip| puts ip.join("   ")}
    File.open(out_file, "w") {
      |f| results.each do |ip,results_arr|
        puts "-" * 62 + "\nIP: #{ip}\n"
        f.write("-" * 62 + "\nIP: #{ip}\n")
        results_arr.each do |r|
          port = r[0]
          risky_methods = r[1]
          title = r[2]
          puts "|Port: #{port}"
          f.write("|Port: #{port}\n")
          puts "|-Risky HTTP methods: #{risky_methods}"
          f.write("|-Risky HTTP methods: #{risky_methods}\n")
          if title
            puts "|-Website title: #{title}"
            f.write("|-Website title: #{title}\n")
          end
        end
      end
      puts "-" * 62
      f.write("-" * 62 + "\n")
    }
  end
end