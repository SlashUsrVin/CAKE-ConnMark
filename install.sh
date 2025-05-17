#!/bin/sh
# CAKE-ConnMark - Installer
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

CCM_REPO="mvin321/CAKE-ConnMark"
BRANCH="main"
JFFS_DIR="/jffs/scripts"
TGT_DIR="/jffs/scripts/cake-connmark"
CFG_DIR="$TGT_DIR/cfg"

#Function to fetch scripts from github
fetch_file() {
    GIT_REPO="$1"
    GIT_FILE_PATH="$2"
    LOC_INSTALL_DIR="$3"

    curl -fsSL "https://raw.githubusercontent.com/$GIT_REPO/$BRANCH/$GIT_FILE_PATH" -o "$LOC_INSTALL_DIR/$(basename $GIT_FILE_PATH)"
}

backup_file() {
    sh_full_path="$1"
    pscript_n=$(basename "$sh_full_path")
    bk_pre_name=$(date +"%Y%m%d%H%M%S")
    if [ -f "$sh_full_path" ]; then
        mv -f "$sh_full_path" "$TMP_DIR/$bk_pre_name-$pscript_n"    
    fi
}

#Remove installation directory
rm -rf "$TGT_DIR"

#Re-create directory
mkdir -p "$TGT_DIR" 
mkdir -p "$CFG_DIR"
mkdir -p "$TGT_DIR/tmp"

#Fetch scripts from github
fetch_file "$CCM_REPO" "cake-connmark.sh" "$TGT_DIR"
fetch_file "$CCM_REPO" "ipcalc.sh" "$TGT_DIR"
fetch_file "mvin321/IP2Regex-Shell" "ip2regex.sh" "$TGT_DIR"
fetch_file "mvin321/ExecLock-Shell" "exec-lock.sh" "$JFFS_DIR"

#Fetch configuration files
for f in $(curl -s "https://api.github.com/repos/$CCM_REPO/contents/cfg?ref=$BRANCH" | jq -r '.[].name'); do
    fetch_file "$CCM_REPO" "cfg/${f}" "$CFG_DIR"
done

#Make scripts executable
chmod +x $TGT_DIR/cake-connmark.sh
chmod +x $TGT_DIR/ipcalc.sh
chmod +x $TGT_DIR/ip2regex.sh

#Convert line breaks to unix line breaks
dos2unix $TGT_DIR/cake-connmark.sh
dos2unix $TGT_DIR/ipcalc.sh
dos2unix $TGT_DIR/ip2regex.sh
dos2unix $JFFS_DIR/exec-lock.sh

#Finalize installation
cru d cake-connmark
cru a cake-connmark "* 9-23,0-3 * * * /jffs/scripts/exec-lock.sh /jffs/scripts/cake-connmark/cake-connmark.sh"

echo -e "\nInstallation Complete! CAKE-ConnMark will run every minute from 9:00 AM to 3:59 AM (daily)"