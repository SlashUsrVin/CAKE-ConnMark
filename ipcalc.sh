#!/bin/sh
# CAKE-ConnMark - ipcalc - Generates ip range from cidr
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

#sample input: 192.168.1.1/24
#sample output: 192.168.1.0 192.168.1.255

set -- $(echo "$1" | awk -F/ '{print $1, $2}')
ip="$1"
maskbits="$2"

# Convert dotted IP to decimal
ip_to_decimal() {
  set -- $(echo "$1" | awk -F. '{print $1, $2, $3, $4}')
  o1="$1"
  o2="$2"
  o3="$3"
  o4="$4"

  d1=$(( o1 << 24 ))
  d2=$(( o2 << 16 ))
  d3=$(( o3 << 8 ))

  ret_d=$(( d1 + d2 + d3 + o4 ))

  echo "$ret_d"
}

# Convert decimal to dotted IP
decimal_to_ip() {
  dec=$1
  
  o1=$(( ( dec >> 24 ) & 255 ))
  o2=$(( ( dec >> 16 ) & 255 ))
  o3=$(( ( dec >> 8 ) & 255 ))
  o4=$(( dec & 255 ))

  echo "$o1.$o2.$o3.$o4"
}

# Calculate netmask from mask bits
mask=$(( 0xFFFFFFFF << ( 32 - maskbits ) & 0xFFFFFFFF ))

ip_dec=$(ip_to_decimal "$ip")
net_dec=$(( ip_dec & mask ))
bcast_dec=$(( net_dec | (~mask & 0xFFFFFFFF) ))

start_ip=$(decimal_to_ip "$net_dec")
end_ip=$(decimal_to_ip "$bcast_dec")

echo "$start_ip $end_ip"