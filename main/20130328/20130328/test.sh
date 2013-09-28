#!/bin/sh
sed -ne 's@^.*\(SRC\)=\([[:digit:]\.]\+\).*$@\2@pg' | sort | uniq -c | sort -n | while read n ip ; do echo "-- $n $ip" ; geoiplookup $ip ; done 
