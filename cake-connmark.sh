#!/bin/sh
# CAKE-ConnMark - Main
# Copyright (C) 2025 https://github.com/mvin321
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

#SCRIPT-ALIAS:CAKE-ConnMark

DIR_SCRIPTS="/jffs/scripts"
DIR_CONN="$DIR_SCRIPTS/cake-connmark"
DIR_CONN_CFG="$DIR_CONN/cfg"
DIR_CONN_TMP="$DIR_CONN/tmp"

printf "\n\n$logstart"

#Extract value from conntrack parameters (i.e get 50000 in dport=50000, etc)
extract_value () {
    xfield="$1"
    xvalue=$(echo "$xfield" | awk -F= '{print $2}')
    echo "$xvalue"
}

#escapes dotted string to be usable in regex. i.e 192\.168\.1\.1
esc_dot () {
    dottedstr="$1"
    echo "$1" | sed 's/\./\\./g'
}

clear_tmp_files () {
    > "$DIR_CONN_TMP/ipt.curr"
    > "$DIR_CONN_TMP/connt.tmp"
}

clear_rgx_files () {
    > "$DIR_CONN_TMP/srcip_in.rgx"
    > "$DIR_CONN_TMP/srcip_ex.rgx"
    > "$DIR_CONN_TMP/dstip_in.rgx"
    > "$DIR_CONN_TMP/dstip_ex.rgx"    
    > "$DIR_CONN_TMP/dport_in.rgx"
    > "$DIR_CONN_TMP/dport_ex.rgx"
}

#Converts CIDR to Regular Expression
#SAMPLE INPUT: 192.168.1.1/24 
#SAMPLE OUTPUT: (192)\.(168)\.(1)\.([0-9]|[2-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])
#If input is individual IPs (not annotated), escape the dots (i.e 192\.168\.1\.100).
ip_to_regex_range () {
    ip="$1"

    set -- $(echo "$ip" | awk -F/ '{print $0, $2}')
    c_ip="$1"
    cidr="$2"

    ipcalc="$DIR_CONN/ipcalc.sh"
    regx_ip_rng="$DIR_CONN/ip2regex.sh"

    #Check if notation exists, if so, convert to ip ranges and generate regex
    if [ ! -z "$cidr" ]; then
        ip_R=$(sh "$ipcalc" "$c_ip") #convert notation to IP ranges
        rgx_ip=$(sh "$regx_ip_rng" $ip_R) #convert IP range to regular expression
    else
        rgx_ip="$(esc_dot "$ip")"
    fi

    echo "$rgx_ip"
}

filter_port_range () {
    #Include or Exclude port ranges in conntrack list
    in_filter_method="$1" #I or E: Include or Exclude
    in_port_rngs="$2"
    in_connt="$3"
    out_connt=""
    
    > "$DIR_CONN/connt.tmp" #clear conntrack tmp file

    echo "$in_connt" | while read -r f_conn; do
        dest_port=$(echo "$f_conn" | awk '{print $4}' | awk -F= '{print $2}')
        port_match="0"
        for fport in $in_port_rngs; do
            #check for port ranges
            set -- $(echo "$fport" | awk -F: '{print $1, $2}')
            p1="$1"
            p2="$2"

            if [ ! -z "$p2" ]; then
                if [ "$dest_port" -ge "$p1" ] && [ "$dest_port" -le "$p2" ]; then
                    port_match="1"
                fi
            fi

            if [ "$port_match" -eq 1 ]; then
                break #exit loop if matched
            fi
        done
        
        case "${in_filter_method}${port_match}" in
            "I1"|"E0")
                echo "$f_conn" >> "$DIR_CONN/connt.tmp"
            ;;
        esac            
    done

    out_connt=$(cat "$DIR_CONN/connt.tmp")        

    echo "$out_connt"
}

#construct conntrack command
prioritize_conn () {
    cfg_F="$1"
    conn_include_sip=""
    conn_exclude_sip=""
    conn_include_dip=""
    conn_exclude_dip=""    
    conn_include_port=""
    conn_exclude_port=""
    conn_include_rport=""
    conn_exclude_rport=""    
    ipt_exclude_chain=""
    conn_pro=""
    cf_dscp=""
    connt_in_cmd=""
    connt_ex_cmd=""
    connt=""

    while read -r cfg || [ -n "$cfg" ]; do
        cfg_P=$(echo "$cfg" | awk '{print $1}')
        cfg_V=$(echo "$cfg" | awk '{$1=""; print $0}')

        for i in $cfg_V; do
            case "$cfg_P" in
                "DSCP")
                    #example for Voice Tin: 0x2e (EF) 0x28 (CS4)
                    cf_dscp="$i"
                    ;;
                "PROTOCOL")
                    if [ -z "$conn_pro" ]; then
                        conn_pro="${i}"
                    else
                        conn_pro="${conn_pro}|${i}"
                    fi     
                    ;;
                "SRCIP")
                    #Consolidate IPs in regex form, both single and CIDR are handled here
                    i_ip=$(ip_to_regex_range "$i")
                    echo "\\bsrc=(${i_ip})\\b" >> "$DIR_CONN_TMP/srcip_in.rgx"
                    ;;
                "!SRCIP")
                    #Consolidate IPs in regex form, both single and CIDR are handled here
                    x_ip=$(ip_to_regex_range "$i")
                    echo "\\bsrc=(${x_ip})\\b" >> "$DIR_CONN_TMP/srcip_ex.rgx"
                    ;; 
                "DSTIP")
                    #Consolidate IPs in regex form, both single and CIDR are handled here
                    i_ip=$(ip_to_regex_range "$i")

                    echo "\\bdst=(${i_ip})\\b" >> "$DIR_CONN_TMP/dstip_in.rgx"
                    ;;
                "!DSTIP")
                    #Consolidate IPs in regex form, both single and CIDR are handled here
                    x_ip=$(ip_to_regex_range "$i")

                    echo "\\bdst=(${x_ip})\\b" >> "$DIR_CONN_TMP/dstip_ex.rgx"
                    ;;                                       
                "PORT")
                    #Check for port range.
                    set -- $(echo "$i" | awk -F: '{print $1, $2}')
                    i_p1="$1"
                    i_p2="$2"

                    if [ ! -z "$i_p2" ]; then
                        #consolidate port ranges, this will be evaluated separately.
                        if [ -z "$conn_include_rport" ]; then
                            conn_include_rport="${i}"
                        else
                            conn_include_rport="${conn_include_rport} ${i}"
                        fi                        
                    else
                        #If not range, consolidate in regex form
                        echo "\\bdport=(${i_p1})\\b" >> "$DIR_CONN_TMP/dport_in.rgx"
                    fi
                    ;;
                "!PORT")
                    #Check for port range.
                    set -- $(echo "$i" | awk -F: '{print $1, $2}')
                    x_p1="$1"
                    x_p2="$2"

                    if [ ! -z "$x_p2" ]; then
                        #consolidate port ranges, this will be evaluated separately.
                        if [ -z "$conn_exclude_rport" ]; then
                            conn_exclude_rport="${i}"
                        else
                            conn_exclude_rport="${conn_exclude_rport} ${i}"
                        fi                        
                    else
                        #If not range, consolidate in regex form
                        echo "\\bdport=(${x_p1})\\b" >> "$DIR_CONN_TMP/dport_ex.rgx"
                    fi
                    ;;                    
                "!CHAIN")
                    #Re-assign whole value - Chain criteria will be evaluated separately
                    if [ -z "$ipt_exclude_chain" ]; then
                        ipt_exclude_chain="${cfg_V}"
                    fi                    
                    ;;
                *)
                ;;
            esac
        done
    done < "$cfg_F"

    connt_cmd="conntrack -L -u ASSURED 2>/dev/null | grep -vE \"src=127\.0\.0\.1\" | grep -E \"\\b($conn_pro)\\b\""

    for rgx in "$DIR_CONN_TMP"/*_ex.rgx; do
        echo "$rgx"
        if [ -s "$rgx" ]; then
            cat "$rgx"
            connt_cmd="$connt_cmd | grep -vE -f \"${rgx}\""
        fi
    done

    for rgx in "$DIR_CONN_TMP"/*_in.rgx; do
        echo "$rgx"    
        if [ -s "$rgx" ]; then
            cat "$rgx"        
            connt_cmd="$connt_cmd | grep -E -f \"${rgx}\""
        fi
    done

    connt_cmd="$connt_cmd | awk '/udp|icmp/ { print \$4, \$5, \$6, \$7, \$8, \$9, \$10, \$11, \$1 } /tcp/ { print \$5, \$6, \$7, \$8, \$9, \$10, \$11, \$12, \$1 }'"
    
    connt=$(sh -c "$connt_cmd")
    echo "$connt_cmd"
    echo "connt=$connt"
    
    #If port ranges are present in !PORT parameter, they will be filtered here.
    echo "conn_exclude_rport=$conn_exclude_rport"
    if [ ! -z "$conn_exclude_rport" ] && [ ! -z "$connt" ]; then
        connt=$(filter_port_range "E" "$conn_exclude_rport" "$connt")
        echo "filtered-exclude-connt=$connt"
    fi
    
    #If port ranges are present in PORT parameter, they will be filtered here.
    echo "conn_include_rport=$conn_include_rport"
    if [ ! -z "$conn_include_rport" ] && [ ! -z "$connt" ]; then
        connt=$(filter_port_range "I" "$conn_include_rport" "$connt")
        echo "filtered-include-connt=$connt"
    fi

    if [ ! -z "$connt" ]; then
        build_ipt "$connt" "$cf_dscp" "$ipt_exclude_chain"
    fi
}

find_insert_seq () {
    ins_chain="$1" #FORWARD or POSTROUTING
    ins_protocol="$2" #tcp, udp, icmp
    ins_dscp="$3" #in hex form
    
    #Get current iptable rules for the current chain including sequence number
    chain_rules=$(iptables-save -t mangle | grep DSCP | grep "${ins_chain}" | awk '{print NR, $0}')

    dscp_lvl="0"
    chck_lvl="0"
    seq="0"

    #Loop through all the supported dscp value from highest to lowest
    for hex in 0x2e 0x22 0x24 0x26 0x00 0x08; do
        
        dscp_lvl=$(( dscp_lvl + 1))

        if [ "$hex" = "$ins_dscp" ]; then
            chck_lvl="${dscp_lvl}"
        fi

        rule_fetch=$(echo "$chain_rules" | grep "${hex}")

        if [ ! -z "$rule_fetch" ]; then

            if [ "$chck_lvl" -eq 0 ]; then
                seq=$(echo "$rule_fetch" | awk 'END {print $1}') #insert at the bottom              
                seq=$(( seq + 1 ))
            elif [ "$chck_lvl" -ne 0 ] && [ "$chck_lvl" -le "$dscp_lvl" ]; then
                seq=$(echo "$rule_fetch" | awk 'NR == 1 {print $1}') #insert at the top
            fi
        
        fi

        if [ "$seq" -ne 0 ] && [ "$chck_lvl" -ne 0 ]; then
             break; #exit loop once sequence is found
        fi
    done

    if [ "$seq" -eq 0 ]; then
        seq="1" #Default to 1 if insert position can't be found
    fi
       
    echo "$seq"    
}

#Create iptables mangle rules - check TINS.txt for dscp value in hex, decimal and classes
build_ipt () {
    conns="$1"
    dscp="$2"
    exclude_chains="$3"

    chk_chain=$(echo "$exclude_chains" | grep -ioE "FORWARD")
    if [ ! -z "$chk_chain" ]; then
        include_forw="1"
    fi
    chk_chain=$(echo "$exclude_chains" | grep -ioE "POSTROUTING")
    if [ ! -z "$chk_chain" ]; then
        include_post="1"
    fi

    include_forw="${include_forw:-0}"
    include_post="${include_post:-0}"
   
    echo "$conns" | while read -r conn; do
        set -- $(echo "$conn" | awk '{print $1, $2, $3, $4, $5, $6, $7, $8, $9}')
        conn_protocol="$9"
        clientIP=$(extract_value "$1")
        remoteIP=$(extract_value "$2")
        clientPort=$(extract_value "$3")
        remotePort=$(extract_value "$4")
        in_remoteIP=$(extract_value "$5")
        in_clientIP=$(extract_value "$6")
        in_remotePort=$(extract_value "$7")
        in_clientPort=$(extract_value "$8")

        if [ "$include_post" -ne 1 ]; then
            ipt_seq1=$(find_insert_seq "POSTROUTING" "$conn_protocol" "$dscp")
            ipt_post="POSTROUTING ${ipt_seq1} -s ${clientIP}/32 -d ${remoteIP}/32 -p ${conn_protocol} -m ${conn_protocol} --sport ${clientPort} --dport ${remotePort} -j DSCP --set-dscp ${dscp}"
            ipt_post_strip_line=$(echo "$ipt_post" | grep -oE "\-s.*")
            ipt_post_strip_line="POSTROUTING $ipt_post_strip_line"
            echo "$ipt_post_strip_line" >> "$DIR_CONN_TMP/ipt.curr"
            chk_ipt_post=$(iptables-save -t mangle | grep -- "$ipt_post_strip_line")
            if [ -z "$chk_ipt_post" ]; then
                printf "\ncreating POSTROUTING rules..."
                iptables -t mangle -I ${ipt_post}
                printf "\nrule creatd --> $ipt_post"
            fi                
        fi

        if [ "$include_forw" -ne 1 ]; then
            ipt_seq2=$(find_insert_seq "FORWARD" "$conn_protocol" "$dscp")
            ipt_pre="FORWARD ${ipt_seq2} -s ${remoteIP}/32 -d ${clientIP}/32 -p ${conn_protocol} -m ${conn_protocol} --sport ${remotePort} --dport ${clientPort} -j DSCP --set-dscp ${dscp}"                 
            ipt_pre_strip_line=$(echo "$ipt_pre" | grep -oE "\-s.*")
            ipt_pre_strip_line="FORWARD $ipt_pre_strip_line"
            echo "$ipt_pre_strip_line" >> "$DIR_CONN_TMP/ipt.curr"
            chk_ipt_pre=$(iptables-save -t mangle | grep -- "$ipt_pre_strip_line")            
        
            if [ -z "$chk_ipt_pre" ]; then
                printf "\n\ncreating FORWARD rules..."
                iptables -t mangle -I ${ipt_pre}
                printf "\nrule creatd --> $ipt_pre"
            fi
        fi
    done 
}

##################
# MAIN
##################

#Only pass argument for testing as it will clear up all iptables and will only create rules for this particular config file
#This script is intended to be run without passing an argument to process all config files in /jffs/scripts/cake-connmark/cfg/*.cfg
cfg_files="$1" 

if [ -z "$cfg_files" ]; then
    cfg_files="$DIR_CONN_CFG/*.cfg"
fi

clear_tmp_files
#Read all config files
for file in $cfg_files; do
    echo "$file"
    clear_rgx_files
    prioritize_conn $file
done

iptrules=$(iptables-save -t mangle | grep DSCP)
currconns=$(cat "$DIR_CONN_TMP/ipt.curr")

echo "$iptrules" | while read -r rule; do
    strippedR=$(echo ${rule} | awk '{$1=""; sub(/^ /, ""); print}') #removed -A at the start of the string and remove space added by awk
    activerule=$(echo "$currconns" | grep -- "${strippedR}")

    if [[ -z "$activerule" && ! -z "$strippedR" ]]; then
        iptables -t mangle -D ${strippedR}
        printf "\nDELETED --> $strippedR"
    fi
done

#check if correct filter exists to ensure DSCP tagging for ifb4eth0 is retained
if  ! tc filter show dev eth0 | grep -q "protocol all pref 10 u32 chain 0"; then 
    printf "\n\nadding tc filter.."
    tc filter del dev eth0
    tc filter replace dev eth0 protocol all prio 10 u32 match u32 0 0 action mirred egress redirect dev ifb4eth0
    printf "\n\nDone.."
fi

connTO="90" #conntract UDP timeout settings - default is 30 sec

if [ "$(cat /proc/sys/net/netfilter/nf_conntrack_udp_timeout)" -lt "$connTO" ]; then 
    echo "$connTO" > /proc/sys/net/netfilter/nf_conntrack_udp_timeout
    printf "\n\nconntrack udp timeout updated to $connTO seconds"
fi

clear_tmp_files
clear_rgx_files