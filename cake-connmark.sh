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
# Convert mark ID to hex
#######################################################################################
dec_to_hex () {
    conv_dec="$1"
    printf "0x%x\n" "$conv_dec"
}

#######################################################################################
# Build priority mapping for the Supported DSCP values. 
# ORDER is IMPORTANT, value must be defined from lowest to highest priority. 
# i.e 0x28 - lowest in voice tin;  0x2e - highest in voice tine; 
#######################################################################################
build_dscp_priority_map () {    
    # Only need to udpate the 4 tin variables below when adding new dscp values
    # Voice Tin 
    tin4="0x28 0x2c 0x2e" # lowest --> highest
    # Video Tin (high)
    tin3="0x20 0x26 0x24 0x22" # lowest --> highest
    # BestEffort (default)
    tin2="0x00" 
    # Bulk (lowest)
    tin1="0x08" 

    # Define an ID so its easier to read conntrack
    # i.e mark=4000, mark=4001, mark=4002 are all marked for voice tin
    write_dscp_map "$tin4" "4000"
    write_dscp_map "$tin3" "3000"
    write_dscp_map "$tin2" "2000"
    write_dscp_map "$tin1" "1000"   
}

#######################################################################################
# Populate the DSCP mapping file
# Format: [connmark_id] [dscp_value_in_hex]
# i.e 4002 0x2e
#     4001 0x2c
#     4000 0x28
#     3002 0x22
# This means any traffic in conntrack marked with 4000+ range will fall in voice tin
#######################################################################################
write_dscp_map () {
    dscp_hex="$1"
    connmark_id="$2"
    
    supp_dscp=""

    for hex in $dscp_hex; do
        if [ -z "$supp_dscp" ]; then
            supp_dscp=$(printf "%s %s\n" "${connmark_id}" "${hex}" )
        else
            supp_dscp=$(printf "%s\n%s %s\n" "$supp_dscp" "${connmark_id}" "${hex}")
        fi
        connmark_id=$(( connmark_id + 1 ))
    done

    if [ -n "$supp_dscp" ]; then
        echo "$supp_dscp" >> "$DIR_CONN_TMP/dscp.map"    
        sort -grk 1 "$DIR_CONN_TMP/dscp.map" -o "$DIR_CONN_TMP/dscp.map"
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
    > "$DIR_CONN_TMP/dscp.ipt"
    > "$DIR_CONN_TMP/dscp.map"
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
# Parses configuration file, builds a dynamic conntrack filter and extracts active 
# unmarked connections that match the criteria, and applies the specified DSCP mark
#######################################################################################
build_filter_from_cfg () {
    cfg_F="$1"
    conn_include_rport=""
    conn_exclude_rport=""    
    conn_pro=""
    cf_dscp=""
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
                *)
                ;;
            esac
        done
    done < "$cfg_F"

    # Base conntrack command - Only include connections that have not been marked yet (--mark 0) 
    connt_cmd="conntrack -L -u ASSURED --mark 0 2>/dev/null | grep -vE \"src=127\.0\.0\.1\""
    
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
    connt_cmd="$connt_cmd | awk '/udp|icmp/ { print \$1, \$4, \$5, \$6, \$7, \$8, \$9, \$10, \$11} /tcp/ { print \$1, \$5, \$6, \$7, \$8, \$9, \$10, \$11, \$12}'"
    
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
        update_conntrack "$connt" "$cf_dscp"
    fi
}

#######################################################################################
# Writes unique rule to curr.ipt for active connections
#######################################################################################
write_to_ipt () {
    ipt_str="$1"

    ipt_file="$DIR_CONN_TMP/curr.ipt"
      
    if ! grep -Fxq -- "$ipt_str" "$ipt_file"; then
        echo "$ipt_str" >> "$ipt_file"
        log "\nipt written...\n"
    fi
}

#######################################################################################
# Checks rules existence using iptables-mangle 
#######################################################################################
check_rule () {
    chk_rule="$1"
    
    iptables-save -t mangle | grep -qF "${chk_rule}" 2>/dev/null

    return "$?"
}

#######################################################################################
# Validates a rule and add to curr.ipt. This ensures that only active       
# connections based from conntrack will have the iptable rules created                
# curr.ipt is also referenced for deleting iptable rules that are already inactive
#######################################################################################
rule_exist () {
    rule="$1"

    check_rule "$rule"
    rc_chk="$?"

    if [ "$rc_chk" -le 1 ]; then
        write_to_ipt "$rule"
    fi

    return "$rc_chk"
}

#######################################################################################
# Restore Mark from conntrack and retag DSCP
#######################################################################################
restore_mark_and_set_dscp () {
    while read -r dscp_mapping; do
        set -- $(echo "${dscp_mapping}" | awk '{print $1, $2}')
        connmark_id=$(dec_to_hex "$1")
        conn_mark="$2"
        echo "PREROUTING -m mark --mark ${connmark_id} -j DSCP --set-dscp ${conn_mark}" >> "$DIR_CONN_TMP/dscp.ipt"
    done < "$DIR_CONN_TMP/dscp.map"

    # Ensure rules are inserted in the correct order based from priority
    # Sort by column 5 (connmark_id from dscp mapping)
    sort -grk 5 "$DIR_CONN_TMP/dscp.ipt" -o "$DIR_CONN_TMP/dscp.ipt"

    # DSCP tagging rule for active connections to reduce clutter in the mangle table
    while read -r restore_cmd; do
        ipt_restore_pre="${restore_cmd}"

        log "ipt_restore_pre=$ipt_restore_pre"
        if ! rule_exist "${ipt_restore_pre}"; then
            iptables -t mangle -A ${ipt_restore_pre}
        fi
    done < "$DIR_CONN_TMP/dscp.ipt"

    # Ensure restore rule is always the first rule in PREROUTING chain
    restore_rule="PREROUTING -m mark --mark 0x0 -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff"
    if ! rule_exist "${restore_rule}"; then
        first_pre_rule=$(iptables-save -t mangle | grep -E "\-A PREROUTING.*" | head -n 1 | grep -oE "PREROUTING.*")
        if [ "$first_pre_rule" != "$restore_rule" ]; then
            iptables -t mangle -D ${restore_rule} 2>/dev/null
        fi
        restore_ins_cmd=$(echo "$restore_rule" | sed 's/PREROUTING/PREROUTING 1/') # Sequence 1
        iptables -t mangle -I ${restore_rule}
    fi
}

#######################################################################################
# Update conntrack with mark based from dscp mapping
# 
#######################################################################################
update_conntrack () {
    conns="$1"
    dscp="$2"   
    
    new_mark=$(grep -F "${dscp}" "$DIR_CONN_TMP/dscp.map" | awk '{print $1}')

    log "dscp $dscp maps to mark id $new_mark"

    echo "$conns" | while read -r conn; do
        set -- $(echo "$conn" | awk '{print $1, $2, $3, $4, $5, $6, $7, $8, $9}')
        conn_protocol="$1"
        clientIP=$(extract_value "$2")
        remoteIP=$(extract_value "$3")
        clientPort=$(extract_value "$4")
        remotePort=$(extract_value "$5")
        in_remoteIP=$(extract_value "$6")
        in_clientIP=$(extract_value "$7")
        in_remotePort=$(extract_value "$8")
        in_clientPort=$(extract_value "$9")        
                
        # Update conntrack entry
        update_stat=$(conntrack -U -p "${conn_protocol}" -u ASSURED -s "${clientIP}" --sport "${clientPort}" -d "${remoteIP}" --dport "${remotePort}" --mark "${new_mark}" 2>&1)
        
        log "${update_stat}"
    done 
}

# Clear temporary files
clear_tmp_files

# Apply tc filters to retain dscp for inbound traffic
if  ! tc filter show dev eth0 | grep -q "protocol ip pref 10 u32 chain 0"; then 
    tc filter del dev eth0
    tc filter add dev eth0 protocol ip pref 10 u32 match u32 0 0 action mirred egress redirect dev ifb4eth0
    log "TC FILTER ADDED:"
    log "$(tc filter show dev eth0)"
fi

# Make conntract keep entries longer
connTO="60" #default is 30
if [ "$(cat /proc/sys/net/netfilter/nf_conntrack_udp_timeout)" -lt "$connTO" ]; then 
    echo "$connTO" > /proc/sys/net/netfilter/nf_conntrack_udp_timeout
    log "\n\nCONNTRACK UDP TIMEOUT UPDATED TO $connTO SECONDS\n"
fi

# Prepare a priority map for supported DSCP values
build_dscp_priority_map

# Process config files and filter conntrack based from the matching rules from the config files
for file in $DIR_CONN_CFG/*.cfg; do
    log "Processing $file"
    # Clear generated regex files every time a new cfg is being processed
    clear_rgx_files 
    # Ensure any newly uploaded config is in unix format
    dos2unix $file
    
    build_filter_from_cfg $file
done

# Restore mark from conntrack and retag DSCP
restore_mark_and_set_dscp

# Perform iptables clean-up
iptables-save -t mangle | grep -E "\-A [a-zA-Z]+" | sed 's/^-A //' | grep -v " -j RETURN$" > "$DIR_CONN_TMP/all.ipt"
grep -Fxvf "$DIR_CONN_TMP/curr.ipt" "$DIR_CONN_TMP/all.ipt" > "$DIR_CONN_TMP/del.ipt"
del_count=$(wc -l < "$DIR_CONN_TMP/del.ipt")
log "Current Active Rules:\n$(cat $DIR_CONN_TMP/curr.ipt)\nAll Rules in Mangle:\n$(cat $DIR_CONN_TMP/all.ipt)"
if [ "$del_count" -gt 0 ]; then
    sed 's/^/iptables -t mangle -D /' "$DIR_CONN_TMP/del.ipt" > "$DIR_CONN_TMP/del_ipt.sh"
    chmod +x "$DIR_CONN_TMP/del_ipt.sh"
    "$DIR_CONN_TMP/del_ipt.sh"
    log "RULES DELETED (clean-up):\n$(cat "$DIR_CONN_TMP/del.ipt")\n"
fi

# Clear temporary files
clear_tmp_files
clear_rgx_files