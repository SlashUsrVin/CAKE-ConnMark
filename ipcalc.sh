#!/bin/sh
# CAKE-ConnMark - ipcalc - Generates ip range from cidr
# Copyright (C) 2025 https://github.com/SlashUsrVin
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