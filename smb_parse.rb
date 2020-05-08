#!/usr/bin/env ruby

if ARGV.length() == 0
  warning = "[" + "\033[01;33m" + "!" + "\033[00m" + "]"
  puts "#{warning} Please provide a file to parse. Quitting!"
  exit
end
ARGV.each do |file| 
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
    success = "[" + "\033[01;32m" + "+" + "\033[00m" + "]"
    puts "#{success} #{file}: #{null_session_ct} shares accross #{results.length()} hosts allow null session authentication."
    puts "Affected hosts:"
    hosts = results.keys
    hosts = hosts.each_slice(5).to_a
    hosts.each { |ip| puts ip.join("   ")}
    results.each do |ip|
      puts "-" *62 + "\n|IP: #{ip[0]}"
      ip[1].each {|info| puts "|-Share: #{info[0]}\t- Anonymous access: #{info[1]}"  }
    end
    puts "-" *62 + "\n\n"
    #{results.length()} #{ct}"
  end
end