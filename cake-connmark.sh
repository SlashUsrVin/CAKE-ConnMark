#!/bin/sh
# CAKE-ConnMark: Marks packets with DSCP based on active conntrack connections
# Author: SlashUsrVin
#
# MIT License
# Copyright (c) 2025 SlashUsrVin
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# See the LICENSE file in the repository root for full text.

#SCRIPT-ALIAS:CAKE-ConnMark

DIR_SCRIPTS="/jffs/scripts"
DIR_CONN="$DIR_SCRIPTS/cake-connmark"
DIR_CONN_CFG="$DIR_CONN/cfg"
DIR_CONN_TMP="$DIR_CONN/tmp"

logparm="$1"
#######################################################################################
# Hides or shows logging
#######################################################################################
log () {
   #replace % with %% except if % is followed by s (%s) which is a string argument for printf
   msg=$(echo "$1" | sed -e 's/%s/__KEEP_THIS__/g' -e 's/%/%%/g' -e 's/__KEEP_THIS__/%s/g')
   if [ "$logparm" = "logging" ]; then
      shift    #Remove msg (=$1) as 1st argument since msg can also contain multiple arguments (%s). This will avoid the whole string (msg) to be assigned to itself.
      printf -- "$msg\n" "$@"
   fi
}

#######################################################################################
# Extract value from conntrack parameters (i.e get 50000 in dport=50000, etc)
#######################################################################################
extract_value () {
    xfield="$1"
    xvalue=$(echo "$xfield" | awk -F= '{print $2}')
    echo "$xvalue"
}

#######################################################################################
# Escapes "." from IP so it can be use in grep
#######################################################################################
esc_dot () {
    dottedstr="$1"
    echo "$1" | sed 's/\./\\./g'
}

#######################################################################################
# Clears temporary iptable files
#######################################################################################
clear_tmp_files () {
    > "$DIR_CONN_TMP/curr.ipt"
    > "$DIR_CONN_TMP/all.ipt"
    > "$DIR_CONN_TMP/del.ipt"
    > "$DIR_CONN_TMP/del_ipt.sh"
    > "$DIR_CONN_TMP/connt.tmp"
}

#######################################################################################
# Clears temporary generated regex files
#######################################################################################
clear_rgx_files () {
    > "$DIR_CONN_TMP/srcip_in.rgx"
    > "$DIR_CONN_TMP/srcip_ex.rgx"
    > "$DIR_CONN_TMP/dstip_in.rgx"
    > "$DIR_CONN_TMP/dstip_ex.rgx"    
    > "$DIR_CONN_TMP/dport_in.rgx"
    > "$DIR_CONN_TMP/dport_ex.rgx"
}

#######################################################################################
# Converts CIDR to Regular Expression
# SAMPLE INPUT: 192.168.1.1/24 
# SAMPLE OUTPUT: (192)\.(168)\.(1)\.([0-9]|[2-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])
# If input is individual IPs (not annotated), escape the dots (i.e 192\.168\.1\.100).
#######################################################################################
ip_to_regex_range () {
    ip="$1"

    set -- $(echo "$ip" | awk -F/ '{print $0, $2}')
    c_ip="$1"
    cidr="$2"

    ipcalc="$DIR_CONN/ipcalc.sh"
    regx_ip_rng="$DIR_CONN/ip2regex.sh"

    # Check if notation exists, if so, convert to ip ranges and generate regex
    if [ -n "$cidr" ]; then
        ip_R=$(sh "$ipcalc" "$c_ip") #convert notation to IP ranges
        rgx_ip=$(sh "$regx_ip_rng" $ip_R) #convert IP range to regular expression
    else
        rgx_ip="$(esc_dot "$ip")"
    fi

    echo "$rgx_ip"
}

#######################################################################################
# Enables the PORT parameter to contain ranges i.e 7000:8000
#######################################################################################
filter_port_range () {
    # Include or Exclude port ranges in conntrack list
    in_filter_method="$1" #I or E: Include or Exclude
    in_port_rngs="$2"
    in_connt="$3"
    out_connt=""
    
    > "$DIR_CONN/connt.tmp" #clear conntrack tmp file

    echo "$in_connt" | while read -r f_conn; do
        dest_port=$(echo "$f_conn" | awk '{print $4}' | awk -F= '{print $2}')
        port_match="0"
        for fport in $in_port_rngs; do
            # check for port ranges
            set -- $(echo "$fport" | awk -F: '{print $1, $2}')
            p1="$1"
            p2="$2"

            if [ -n "$p2" ]; then
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

#######################################################################################
# This is the main function. It evaluates active connections from conntrack 
# based on criteria defined in the configuration files, and applies the corresponding 
# DSCP markings.     
#######################################################################################
process_config () {
    cfg_F="$1"
    conn_include_sip=""
    conn_exclude_sip=""
    conn_include_dip=""
    conn_exclude_dip=""    
    conn_include_port=""
    conn_exclude_port=""
    conn_include_rport=""
    conn_exclude_rport=""    
    cf_in_chain=""
    cf_out_chain=""
    cf_cust_chain=""
    conn_pro=""
    cf_dscp=""
    connt_in_cmd=""
    connt_ex_cmd=""
    connt=""

    while read -r cfg || [ -n "$cfg" ]; do
        cfg_P=$(echo "$cfg" | awk '{print $1}')
        cfg_V=$(echo "$cfg" | cut -d' ' -f2-)

        for i in $cfg_V; do
            case "$cfg_P" in
                "DSCP")
                    # example for Voice Tin: 0x2e (EF) 0x28 (CS4)
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
                    # Consolidate IPs in regex form, both single and CIDR are handled here
                    i_ip=$(ip_to_regex_range "$i")
                    echo "\\bsrc=(${i_ip})\\b" >> "$DIR_CONN_TMP/srcip_in.rgx"
                    ;;
                "!SRCIP")
                    # Consolidate IPs in regex form, both single and CIDR are handled here
                    x_ip=$(ip_to_regex_range "$i")
                    echo "\\bsrc=(${x_ip})\\b" >> "$DIR_CONN_TMP/srcip_ex.rgx"
                    ;; 
                "DSTIP")
                    # Consolidate IPs in regex form, both single and CIDR are handled here
                    i_ip=$(ip_to_regex_range "$i")
                    echo "\\bdst=(${i_ip})\\b" >> "$DIR_CONN_TMP/dstip_in.rgx"
                    ;;
                "!DSTIP")
                    # Consolidate IPs in regex form, both single and CIDR are handled here
                    x_ip=$(ip_to_regex_range "$i")
                    echo "\\bdst=(${x_ip})\\b" >> "$DIR_CONN_TMP/dstip_ex.rgx"
                    ;;                                       
                "PORT")
                    # Check for port range.
                    set -- $(echo "$i" | awk -F: '{print $1, $2}')
                    i_p1="$1"
                    i_p2="$2"

                    if [ -n "$i_p2" ]; then
                        # consolidate port ranges, this will be evaluated separately.
                        if [ -z "$conn_include_rport" ]; then
                            conn_include_rport="${i}"
                        else
                            conn_include_rport="${conn_include_rport} ${i}"
                        fi                        
                    else
                        # If not range, consolidate in regex form
                        echo "\\bdport=(${i_p1})\\b" >> "$DIR_CONN_TMP/dport_in.rgx"
                    fi
                    ;;
                "!PORT")
                    # Check for port range.
                    set -- $(echo "$i" | awk -F: '{print $1, $2}')
                    x_p1="$1"
                    x_p2="$2"

                    if [ -n "$x_p2" ]; then
                        # consolidate port ranges, this will be evaluated separately.
                        if [ -z "$conn_exclude_rport" ]; then
                            conn_exclude_rport="${i}"
                        else
                            conn_exclude_rport="${conn_exclude_rport} ${i}"
                        fi                        
                    else
                        # If not range, consolidate in regex form
                        echo "\\bdport=(${x_p1})\\b" >> "$DIR_CONN_TMP/dport_ex.rgx"
                    fi
                    ;;                    
                "ICHAIN")
                    # Re-assign whole value - Chain criteria will be evaluated separately
                    if [ -z "$cf_in_chain" ]; then
                        cf_in_chain="${cfg_V}"
                    fi                    
                    ;;
                "OCHAIN")
                    # Re-assign whole value - Chain criteria will be evaluated separately
                    if [ -z "$cf_out_chain" ]; then
                        cf_out_chain="${cfg_V}"
                    fi                    
                    ;;   
                "NCHAIN")
                    # Re-assign whole value - Chain criteria will be evaluated separately
                    if [ -z "$cf_cust_chain" ]; then
                        cf_cust_chain="${cfg_V}"
                    fi                    
                    ;;                                        
                *)
                ;;
            esac
        done
    done < "$cfg_F"

    # Base conntrack command
    connt_cmd="conntrack -L -u ASSURED 2>/dev/null | grep -vE \"src=127\.0\.0\.1\""
    
    # Append protocol
    connt_cmd="$connt_cmd | grep -E \"\\\\b($conn_pro)\\\\b\""

    # Exclude inactive connections
    connt_cmd="$connt_cmd | grep -vE \"TIME_WAIT|CLOSE|CLOSE_WAIT|LAST_ACK|FIN_WAIT\""

    # Regex exclusion
    for rgx in "$DIR_CONN_TMP"/*_ex.rgx; do
        log "$rgx"
        if [ -s "$rgx" ]; then
            log "$(cat "$rgx")"
            connt_cmd="$connt_cmd | grep -vE -f \"${rgx}\""
        fi
    done

    # Regex inclusion
    for rgx in "$DIR_CONN_TMP"/*_in.rgx; do
        log "$rgx"    
        if [ -s "$rgx" ]; then
            log "$(cat "$rgx")"
            connt_cmd="$connt_cmd | grep -E -f \"${rgx}\""
        fi
    done

    # Output only parameters needed for creating iptables
    connt_cmd="$connt_cmd | awk '/udp|icmp/ { print \$4, \$5, \$6, \$7, \$8, \$9, \$10, \$11, \$1 } /tcp/ { print \$5, \$6, \$7, \$8, \$9, \$10, \$11, \$12, \$1 }'"
    
    connt=$(sh -c "$connt_cmd")
    log "$connt_cmd"
    log "connt=$connt"
    
    # If port ranges are present in !PORT parameter, they will be filtered here.
    log "conn_exclude_rport=$conn_exclude_rport"
    if [ -n "$conn_exclude_rport" ] && [ -n "$connt" ]; then
        connt=$(filter_port_range "E" "$conn_exclude_rport" "$connt")
        log "filtered-exclude-connt=$connt"
    fi
    
    # If port ranges are present in PORT parameter, they will be filtered here.
    log "conn_include_rport=$conn_include_rport"
    if [ -n "$conn_include_rport" ] && [ -n "$connt" ]; then
        connt=$(filter_port_range "I" "$conn_include_rport" "$connt")
        log "filtered-include-connt=$connt"
    fi

    if [ -n "$connt" ]; then
        process_conntrack "$connt" "$cf_dscp" "$cf_in_chain" "$cf_out_chain" "$cf_cust_chain"
    fi
}

#######################################################################################
# Ensures that rules are sorted by dscp value, from highest to lowest for each chain  
#######################################################################################
find_insert_seq () {
    ins_chain="$1" 
    ins_protocol="$2" #tcp, udp, icmp
    ins_dscp="$3" #in hex form
    
    # Get current iptable rules for the current chain including sequence number
    chain_rules=$(iptables-save -t mangle | grep "DSCP" | grep "${ins_chain}" | awk '{print NR, $0}')

    dscp_lvl="0"
    chck_lvl="0"
    seq="0"

    # Loop through all the supported dscp value from highest to lowest
    for hex in 0x2e 0x2c 0x28 0x22 0x24 0x26 0x20 0x00 0x08; do
        
        dscp_lvl=$(( dscp_lvl + 1))

        if [ "$hex" = "$ins_dscp" ]; then
            chck_lvl="${dscp_lvl}"
        fi

        rule_fetch=$(echo "$chain_rules" | grep "${hex}")

        if [ -n "$rule_fetch" ]; then

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

#######################################################################################
# Writes to the temp file curr.ipt. This ensures that only active       
# connections based from conntrack will have the iptable rules created                
# it is used to delete iptable rules that are already inactive
#######################################################################################
check_and_write_to_ipt () {
    rc_chk="$1"
    ipt_str="$2"

    ipt_file="$DIR_CONN_TMP/curr.ipt"
    
    if [ "$rc_chk" -le 1 ]; then
        if ! grep -Fxq -- "$ipt_str" "$ipt_file"; then
            echo "$ipt_str" >> "$ipt_file"
            log "\nipt written...\n"
        fi
    fi    
}

#######################################################################################
# Creates the iptables rules in the mangle table. It creates custom chain based from 
# the configuration files
#######################################################################################
create_mangle () {
    chains="$1" 
    custom_chain="$2"
    ipt_p="$3"
    ipt_s="$4"
    ipt_d="$5"
    ipt_sp="$6" 
    ipt_dp="$7"
    ipt_dscp="$8"
    direction="$9"

    ipt_cmd="" 
    ipt_cmd_strip_line=""
    write_ipt="0"
    last_rule_in_chain=""

    # Ensure only Client/Device IPs will be the basis for redirection (easier to look at when monitoring)
    case "$direction" in 
        INBOUND)
            main_chain_ip="-d ${ipt_d}/32"
            main_chain_port="--dport ${ipt_dp}"              
            cust_chain_ip="-s ${ipt_s}/32"
            cust_chain_port="--sport ${ipt_sp}"              
            ;;
        OUTBOUND)
            main_chain_ip="-s ${ipt_s}/32"                   
            main_chain_port="--sport ${ipt_sp}"               
            cust_chain_ip="-d ${ipt_d}/32"          
            cust_chain_port="--dport ${ipt_dp}"              
            ;;
            
    esac

    # Ensure custom chain is created and -j RETURN is always the last rule of the chain
    if [ -n "$custom_chain" ]; then
        if ! iptables-save -t mangle | grep -q "^:${custom_chain} " >/dev/null 2>&1; then
            iptables -t mangle -N ${custom_chain}
            iptables -t mangle -A ${custom_chain} -j RETURN
            log "Custom chain ${custom_chain} created"
        else
            last_rule_in_chain=$(iptables-save -t mangle | grep -E "^\-A ${custom_chain}" | tail -n 1)
            if [ "$last_rule_in_chain" != "-A ${custom_chain} -j RETURN" ];then
                iptables -t mangle -D ${custom_chain} -j RETURN 2>/dev/null
                iptables -t mangle -A ${custom_chain} -j RETURN
                log "RETURN step missing in ${custom_chain}. Rule re-added!"
            fi
        fi
    else
        log "MISSING NCHAIN PARAMETER! Check config files. Execution cancelled!"
        exit 1
    fi

    # Need to strickly follow the sequence of arguments for current clean-up logic to work
    # FORWARD -s 192.168.2.10/32 -j STREAMING
    ipt_r_spec1="${main_chain_ip} -j ${custom_chain}"
    
    # Need to strickly follow the sequence of arguments for current clean-up logic to work
    # STREAMING -d 8.8.8.8/32 -p tcp -m tcp --sport 5223 --dport 49978 -j DSCP --set-dscp 0x28    
    ipt_r_spec2="${cust_chain_ip} -p ${ipt_p} -m ${ipt_p} ${cust_chain_port} -j DSCP --set-dscp ${ipt_dscp}"
    
    for chain in $chains; do        
        ipt_main_chain="${chain}"
        
        ipt_main="$ipt_main_chain $ipt_r_spec1"
        log "ipt_main=$ipt_main"

        iptables-save -t mangle | grep -F "${ipt_main}" >/dev/null 2>&1
        rc="$?"
        case "$rc" in 
            0)
                log "\nThis redirection rule already exists.. ignoring to avoid duplication\n"
                ;;
            1)
                iptables -t mangle -A ${ipt_main}
                log "\nRedirection rule created (${chain}) --> $ipt_main"
                ;;
            *)
                log "\nError executing iptables-save -t mangle!\n"
                ;;
        esac

        check_and_write_to_ipt "$rc" "$ipt_main" 

        ipt_custom="$custom_chain $ipt_r_spec2"
        log "ipt_custom=$ipt_custom"

        iptables-save -t mangle | grep -F "${ipt_custom}" >/dev/null 2>&1
        rc="$?"
        case "$rc" in 
            0)
                log "\nThis handling rule already exists.. ignoring to avoid duplication\n"        
                ;;
            1)
                ipt_seq=$(find_insert_seq "$custom_chain" "$ipt_p" "$ipt_dscp")
                ipt_i_custom="$custom_chain $ipt_seq $ipt_r_spec2"

                iptables -t mangle -I ${ipt_i_custom}
                log "\nHandling rule created (${custom_chain}) --> $ipt_i_custom"
                ;;
            *)
                log "\nError executing iptables-save -t mangle!\n"
                ;;
        esac

        check_and_write_to_ipt "$rc" "$ipt_custom"         
    done 
}

#######################################################################################
# Extracts necessary parameters from the identified conntract connections and calls
# create_mangle function to the create the iptable rules
#######################################################################################
process_conntrack () {
    conns="$1"
    dscp="$2"   

    tgt_chain_in="$3"
    tgt_chain_out="$4"

    handling_chain="$5"
   
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

        if [ -n "$tgt_chain_out" ]; then
            create_mangle "$tgt_chain_out" "$handling_chain" "$conn_protocol" "$clientIP" "$remoteIP" "$clientPort" "$remotePort" "$dscp" "OUTBOUND"       
        fi

        if [ -n "$tgt_chain_in" ]; then
            create_mangle "$tgt_chain_in" "$handling_chain" "$conn_protocol" "$remoteIP" "$clientIP" "$remotePort" "$clientPort" "$dscp" "INBOUND"
        fi
    done 
}

# Clear temporary files
clear_tmp_files

# Process config files
for file in $DIR_CONN_CFG/*.cfg; do
    log "Processing $file"
    # Clear generated regex files every time a new cfg is being processed
    clear_rgx_files 
    # Ensure any newly uploaded config is in unix format
    dos2unix $file
    
    process_config $file
done

# Perform iptables clean-up
iptables-save -t mangle | grep -E "\-A [a-zA-Z]+" | sed 's/^-A //' | grep -v " -j RETURN$" > "$DIR_CONN_TMP/all.ipt"
grep -Fxvf "$DIR_CONN_TMP/curr.ipt" "$DIR_CONN_TMP/all.ipt" > "$DIR_CONN_TMP/del.ipt"
del_count=$(wc -l < "$DIR_CONN_TMP/del.ipt")

if [ "$del_count" -gt 0 ]; then
    sed 's/^/iptables -t mangle -D /' "$DIR_CONN_TMP/del.ipt" > "$DIR_CONN_TMP/del_ipt.sh"
    chmod +x "$DIR_CONN_TMP/del_ipt.sh"
    "$DIR_CONN_TMP/del_ipt.sh"

    log "RULES DELETED (clean-up):\n$(cat "$DIR_CONN_TMP/del.ipt")\n"
fi

# Apply tc filters to retain dscp for inbound traffic
if  ! tc filter show dev eth0 | grep -q "protocol ip pref 10 u32 chain 0"; then 
    tc filter del dev eth0
    tc filter add dev eth0 protocol ip pref 10 u32 match u32 0 0 action mirred egress redirect dev ifb4eth0
    log "TC FILTER ADDED:"
    log "$(tc filter show dev eth0)"
fi

# Make conntract keep entries longer
connTO="90" #default is 30
if [ "$(cat /proc/sys/net/netfilter/nf_conntrack_udp_timeout)" -lt "$connTO" ]; then 
    echo "$connTO" > /proc/sys/net/netfilter/nf_conntrack_udp_timeout
    log "\n\nCONNTRACK UDP TIMEOUT UPDATED TO $connTO SECONDS\n"
fi

# Clear temporary files
clear_tmp_files
clear_rgx_files