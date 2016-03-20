#!/bin/sh

usage() {
   cat 1>&2 << EOF

Usage: ./apkextract.sh apkfile
EOF
   return 0
}

if [[ ! "$1" ]]; then
   usage
   exit 1
fi

TRAGETFILE=$1
UNZIPDIR_PREFIX="_unziped"
UNZIPDIR=$1$UNZIPDIR_PREFIX

unzip -d $UNZIPDIR $1
dex2jar $UNZIPDIR/classes.dex


