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
    cf_cust_chain=""
    cf_mark_chain=""
    conn_pro=""
    cf_dscp=""
    connt_in_cmd=""
    connt_ex_cmd=""
    connt=""
    cf_match_by=""

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
                "MARKCHAIN")
                    # Re-assign whole value - Chain criteria will be evaluated separately
                    if [ -z "$cf_mark_chain" ]; then
                        cf_mark_chain=$(echo "${cfg_V}" | awk '{print $1}')
                    fi                    
                    ;;    
                "NCHAIN")
                    # Re-assign whole value - Chain criteria will be evaluated separately
                    if [ -z "$cf_cust_chain" ]; then
                        cf_cust_chain="${cfg_V}"
                    fi                    
                    ;;
                "MATCHBY")
                    # Re-assign whole value - Chain criteria will be evaluated separately
                    if [ -z "$cf_match_by" ]; then
                        cf_match_by="${cfg_V}"
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

    # Only include connections that have not been marked yet. 
    # This will also remove existing CONNMARK rules in FORWARD chain that are not needed anymore
    connt_cmd="$connt_cmd |  grep -F \"mark=0\""

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
        process_conntrack "$connt" "$cf_dscp" "$cf_mark_chain" "$cf_cust_chain" "$cf_match_by"
    fi
}

#######################################################################################
# Ensures that rules are sorted by dscp value, from highest to lowest for each chain  
# (NOT USED ANYMORE AFTER SWITCHING TO CONNMARK)
#######################################################################################
find_insert_seq () {
    ins_chain="$1" 
    ins_protocol="$2" #tcp, udp, icmp
    ins_dscp="$3" #in hex form
    
    # Get current iptable rules for the current chain including sequence number
    chain_rules=$(iptables-save -t mangle | grep -E "DSCP|CONNMARK" | grep "${ins_chain}" | awk '{print NR, $0}')

    dscp_lvl="0"
    chck_lvl="0"
    seq="0"

    # Loop through all the supported dscp value from highest to lowest
    while read -r dscp_map; do
        hex=$(echo "${dscp_map}" | awk '{print $2}')
        
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
    done < "$DIR_CONN_TMP/dscp.map"

    if [ "$seq" -eq 0 ]; then
        seq="1" #Default to 1 if insert position can't be found
    fi
       
    echo "$seq"    
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
    
    iptables-save -t mangle | grep -F "${chk_rule}"

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
restore_mark () {
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
    ipt_matchby="$8"
    ipt_dscp="$9"
    direction="$10"

    ipt_cmd="" 
    ipt_cmd_strip_line=""
    write_ipt="0"
    last_rule_in_chain=""

    # Retrieve Mark ID from dscp mapping
    mark_id=$(grep -F "$ipt_dscp" "$DIR_CONN_TMP/dscp.map" | awk '{print $1}')

    if [ -z "$mark_id" ]; then
        log "Unsupported DSCP value ($ipt_dscp) defined in the cfg file"
        exit 1
    fi

    # Convert mark ID to hex
    mark_id=$(dec_to_hex "$mark_id")

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
    
    set -- $(echo "$ipt_matchby" | awk '{print $1, $2}')    
    match1="$1"
    match2="$2"
    match_id="0"

    for m in "$match1" "$match2"; do
        case "${m}" in
            PORT)
                match_id="$(( match_id + 1))"
                ;;
            IP)
                match_id="$(( match_id + 2))"                
                ;;
        esac
    done

    # Need to strickly follow the sequence/order of arguments for current clean-up logic to work
    # STREAMING -d 8.8.8.8/32 -p tcp -m tcp --sport 5223 --dport 49978 -j DSCP --set-dscp 0x28
    case "$match_id" in
        0|3)
            ipt_r_spec2="${cust_chain_ip} -p ${ipt_p} -m ${ipt_p} ${cust_chain_port} -j CONNMARK --set-xmark ${mark_id}/0xffffffff"
            ;;        
        1)
            ipt_r_spec2="-p ${ipt_p} -m ${ipt_p} ${cust_chain_port} -j CONNMARK --set-xmark ${mark_id}/0xffffffff"        
            ;;        
        2)
            ipt_r_spec2="${cust_chain_ip} -p ${ipt_p} -m ${ipt_p} -j CONNMARK --set-xmark ${mark_id}/0xffffffff"        
            ;;
        *)
            log "ERROR in identifying match by"
            exit 1
            ;;
    esac
        
    for chain in $chains; do        
        ipt_main_chain="${chain}"
        
        ipt_main="$ipt_main_chain $ipt_r_spec1"
        log "ipt_main=$ipt_main"

        # Create redirection rules in main chain
        rule_exist "$ipt_main"
        rc="$?"
        log "case1=$rc"
        case "$rc" in 
            0)
                log "\nThis redirection rule already exists.. ignoring to avoid duplication\n"
                ;;
            1)
                iptables -t mangle -A ${ipt_main}
                log "\nRedirection rule created (${chain}) --> $ipt_main"
                ;;
            *)
                log "\nError executing iptables-save -t mangle! ${ipt_main}\n"
                ;;
        esac
        log "case1=$?"
        ipt_custom="$custom_chain $ipt_r_spec2"
        ipt_i_custom="$custom_chain 1 $ipt_r_spec2"
        log "ipt_custom=$ipt_custom"

        # Create handling rules in custom chain
        rule_exist "$ipt_custom"
        rc="$?"
        log "case2=$rc"
        case "$rc" in 
            0)
                log "\nThis handling rule already exists.. ignoring to avoid duplication\n"        
                ;;
            1)
                iptables -t mangle -I ${ipt_i_custom}
                log "\nHandling rule created (${custom_chain}) --> $ipt_i_custom"
                ;;
            *)
                log "\nError executing iptables-save -t mangle! ${ipt_custom}\n"
                ;;
        esac
        log "case2=$?"
    done 
}

#######################################################################################
# Extracts necessary parameters from the identified conntract connections and calls
# create_mangle function to the create the iptable rules
#######################################################################################
process_conntrack () {
    conns="$1"
    dscp="$2"   
    mark_in_chain="$3"
    handling_chain="$4"
    match_by="$5"

    tgt_chain_in="$mark_in_chain"
    tgt_chain_out="$mark_in_chain"
   
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
            create_mangle "$tgt_chain_out" "$handling_chain" "$conn_protocol" "$clientIP" "$remoteIP" "$clientPort" "$remotePort" "$match_by" "$dscp" "OUTBOUND"       
        fi

        if [ -n "$tgt_chain_in" ]; then
            create_mangle "$tgt_chain_in" "$handling_chain" "$conn_protocol" "$remoteIP" "$clientIP" "$remotePort" "$clientPort" "$match_by" "$dscp" "INBOUND"
        fi
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
connTO="90" #default is 30
if [ "$(cat /proc/sys/net/netfilter/nf_conntrack_udp_timeout)" -lt "$connTO" ]; then 
    echo "$connTO" > /proc/sys/net/netfilter/nf_conntrack_udp_timeout
    log "\n\nCONNTRACK UDP TIMEOUT UPDATED TO $connTO SECONDS\n"
fi

# Prepare a priority map for supported DSCP values
build_dscp_priority_map

# Process config files
for file in $DIR_CONN_CFG/*.cfg; do
    log "Processing $file"
    # Clear generated regex files every time a new cfg is being processed
    clear_rgx_files 
    # Ensure any newly uploaded config is in unix format
    dos2unix $file
    
    process_config $file
done

# Restore mark from conntrack and retag DSCP
restore_mark

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