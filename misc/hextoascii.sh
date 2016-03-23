#!/bin/sh

function hex2string () {
  I=0
  while [ $I -lt ${#1} ];
  do
    echo -en "\x"${1:$I:2}
    let "I += 2"
  done
}

hex2string $1

