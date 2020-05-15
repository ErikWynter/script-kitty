#!/usr/bin/env bash

main () {
        ct=0    #this variable is used for parsing purposes later
        file=( "$@" )   #ensures that the $tcp and $udp arguments passed to the script are treated as arrays
        for i in ${file[@]}
        do
                ip_hex=$(echo ${i} |  cut -d ":" -f 1)  #get IP number in hexadecimal format
                port_hex=$(echo ${i} | cut -d ":" -f 2) #get port number in hexademical format
                port=$((16#$port_hex))  #convert hexadecimal port number to decimal
                ip=""
                for j in $(seq 0 3)     #for all 4 hexadecimal numbers in the hexadecimal IP notation, do:
                do
                        tmp=$((j*=2))   #used to calculate the offset for each hexadecimal number
                        slice_hex=${ip_hex:${tmp}:2}    #obtains a single hexadecimal number
                        slice=$((16#$slice_hex))        #converts the hexadecimal number to decimal
                        ip+=$slice"."   #create an IP-like string of the decimal numbers, seperated by dots
                done

                #reverse the order of the dot-delimited IP elements (since the hex IP is in the reverse order)
                ip=$(echo $ip | ( while read -d . f;do g="$f${g+.}$g" ;done;echo "$g" ))

                #add local and remote addresses together and print them
                rem=$(( $ct % 2 ))
                if [[ rem -eq 0 ]]; then
                        con=$ip":"$port
                else
                        con+=" "$ip":"$port
                        echo $con
                fi
                ((ct++))
        done
}
#check if a file has passed to the script
if [[ $# -eq 0 ]]; then

        #get local and remote IP:port connections in hexadecimal format from /proc/net/tcp and /proc/net/udp files
        tcp=($(grep ":" /proc/net/tcp | sed 's/^ *//g' | cut -d " " -f 2,3))
        udp=($(grep ":" /proc/net/udp | sed 's/^ *//g' | cut -d " " -f 2,3))

        #print local IP
        local_ip=$(ifconfig eth0 | grep "inet " | sed 's/^ *//g' | cut -d " " -f 2)
        echo "Showing results for local host with eth0 IP ${local_ip}."
        echo "TCP connections:"
        main ${tcp[@]}
        echo
        echo "UDP connections:"
        main ${udp[@]}

elif [[ $# -eq 1 ]]; then
        con_file=($(grep ":" $1 | sed 's/^ *//g' | cut -d " " -f 2,3))
        echo "$1 connections:"
        main ${con_file[@]}

else
        f_ct=$(( $# -1 ))
        for f in $(seq 0 $f_ct)
        do
                f_arr=( "$@" )
                con_file=($(grep ":" ${f_arr[$f]} | sed 's/^ *//g' | cut -d " " -f 2,3))
                echo "${f_arr[$f]} connections:"
                main ${con_file[@]}
                if [[ $f -ne $f_ct ]]; then echo; fi    #don't print empty line after results for last file 
        done
fi
