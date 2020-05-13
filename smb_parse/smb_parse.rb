#!/usr/bin/env ruby
def help()
  puts "*" * 70 + "\n\t\t\033[01;32mSMB Parse v1.0\033[00m - \033[01;34mErik Wynter (@wyntererik)\033[00m"
  puts "*" * 70
  puts "\nEasily parse the results of Nmap's 'smb-enum-shares' NSE script."
  puts "Compatible with .nmap files or copy-pasted 'smb-enum-shares' output."
  puts "\nUsage: #{$0} [file1] [file2] [file3] ... [filex]"
  puts "  -h\t\tDisplay this menu and exit."
  puts "  -o [scheme]\tNaming scheme for the output file(s). For multiple\n\t\tinput files, the name of each input file is appended\n\t\tto the scheme for the respective outpute file.\n\t\tDefault scheme: 'parsed_[inputfile]'"
  puts "\n  Example: #{$0} nmap_smb_results1.txt nmap_smb_results2.txt"
  puts "  Example: #{$0} scan1.txt -o results"
  exit
end

warning = "[" + "\033[01;33m" + "!" + "\033[00m" + "]"
info = "[" + "\033[01;34m" + "*" + "\033[00m" + "]"
success = "[" + "\033[01;32m" + "+" + "\033[00m" + "]"
error = "[" + "\033[01;31m" + "-" + "\033[00m" + "]"

if ARGV.length() == 0
  puts "#{warning} Please provide at least one file to parse."
  puts "#{info} Loading help menu:"
  help()
end

if ARGV.include? '-h'
  if ARGV.length > 1
    puts "#{warning} Cannot combine '-h' with other arguments. Quitting!"
    exit
  else
    help()
  end
elsif ARGV.include? '-o'
  o_index = ARGV.find_index('-o')
  out_scheme = ARGV[o_index + 1]
  if out_scheme.to_s.strip.empty?
    puts "#{warning} Option '-o' needs to be followed by a non-empty string. Quitting!"
    exit
  end
  args = ARGV[0...o_index] + ARGV[o_index+2...ARGV.length] #take all arguments except for -o and the argument following it
else
  args = ARGV
end

args.each do |file| 
  begin
    results = {}
    null_session_ct = 0
    hosts_info = File.open(file).read.split("report for ")
    hosts_info.shift
    hosts_info.each do |data|
      if data.include? "Anonymous access: READ"
        ip = data.split("\n")[0]
        results[ip] = []
        shares = data.split("\\\\")
        shares.shift
        shares.each do |s|
          lines = s.split("\n")
          share = lines[0].strip().gsub(":","")
          lines.each do |l|
            if l.include? 'Anonymous access: R'
              anon_access = l.split(": ")[1]
              unless l.split(": ")[1] == nil
                results[ip].append([share,anon_access])
                null_session_ct += 1
              end
            end
          end
        end
      end
    end
    if results.length() == 0
      failure = "[" + "\033[01;31m" + "-" + "\033[00m" + "]"
      puts "#{failure} #{file}: Did not find shares allowing null session authentication."
    else
      if file.include? "/"
        file = file.split("/")
        file = file[file.length() -1]
      end
      if out_scheme
        if args.length() > 1
          out_file = out_scheme + "_" + file
        else
          out_file = out_scheme
        end
      else
        out_file = "parsed_" + file
      end
      puts "#{success} #{file}: #{null_session_ct} shares accross #{results.length()} hosts allow null session authentication."
      puts "#{info} Writing results to '#{out_file}'.\n"
      puts "Affected hosts:"
      hosts = results.keys
      hosts = hosts.each_slice(5).to_a
      hosts.each { |ip| puts ip.join("   ")}
      File.open(out_file, "w") {
        |f| results.each do |ip|
          puts "-" *62 + "\n|IP: #{ip[0]}"
          f.write("-" *62 + "\n|IP: #{ip[0]}\n")
          ip[1].each {
            |i| puts "|-Share: #{i[0]}\t- Anonymous access: #{i[1]}"
            f.write("|-Share: #{i[0]}\t- Anonymous access: #{i[1]}\n")
          }
          end
          puts "-" *62
          f.write("-" *62 + "\n")
      }
    end
  rescue
    puts "#{error} Unable to parse '#{file}'."
    puts "#{warning} Please provide only .nmap files or files containing copy-pasted Nmap output.\n\n"
    next
  end
end