#!/bin/sh
echo "[$#]" >&2
if [[ "$#" -gt 0 ]] ; then
  for f in $@ ; do
    for filepath in $( echo /var/log/net/iptables_new/*$f* ) ; do
#     echo "$filepath"
      tail $filepath \
| sed -e 's@([[:digit:]ABCDEF]\+)@ @' \
| sed -e 's@\b\(PREC\|ID\|TOS\|TTL\|LEN\|MAC\|URGP\|WINDOW\|RES\)\b=\([^[:blank:]]*\)[[:blank:]]\+@ @g' \
| sed -e 's@[[:blank:]]\+\b\(DF\|SYN\|OPT\|RST\|CWR\|ACK\|FIN\|PSH\)\b[[:blank:]]\+@ @g' \
| sed -e 's@[[:blank:]]\+\b\(DF\|SYN\|OPT\|RST\|CWR\|ACK\|FIN\|PSH\)\b[[:blank:]]\+@ @g' \
| sed -e 's@[[:blank:]]*\(IN=\)@. \1@' \
| sed -e 's@^[[:digit:]]\+:[[:digit:]]\+[[:blank:]]\+\(IPT\|ipt\)4:[[:blank:]]\+@@' \
| sed -e 's@\[[[:digit:]]\+\.[[:digit:]]\+\][[:blank:]]\+ipt4:[[:blank:]]*@@' \
| sed -e 's@\bOUT=\([^[:blank:]]*\)[[:blank:]]*@output=\1;@' \
| sed -e 's@\bSRC=\([^[:blank:]]*\)[[:blank:]]*\(.*\)\bSPT=\([^[:blank:]]*\)[[:blank:]]*@\1;\3;\2@' \
| sed -e 's@\bDST=\([^[:blank:]]*\)[[:blank:]]*\(.*\)\bDPT=\([^[:blank:]]*\)[[:blank:]]*@\1;\3;\2@' \
| sed -e 's@\bUID=\([^[:blank:]]*\)[[:blank:]]*@\1;@' \
| sed -e 's@\bGID=\([^[:blank:]]*\)[[:blank:]]*@\1;@' \
| sed -e 's@\bTYPE=\([^[:blank:]]*\)[[:blank:]]*@\1;@' \
| sed -e 's@^\(.*\)[[:blank:]]*\bIN=\([^[:blank:]]*\)[[:blank:]]*\(.*\)@[\1];input=\2;\3@' \
| sed -e 's@^\(.*\)\bPROTO=\([^[:blank:]]*\)[[:blank:]]*@\2;\1@' \
| awk -F';' '{printf "%-4s %-12s %-14s %16s %-6d %16s %-6d -- %s %s %s\n", $1, $3, $4, $5, $6, $7, $8, $9, $10, $11}'      


# | sed -e '/\[\(.*\)[[:blank:]]\+\(.*\)\]/s@ @_@g' \



# getent passwd 1022 | awk -F: '{print $1}'


# '\bOUT=\([^[:blank:]]*\)[[:blank:]]*'\
# '\bSRC=\([^[:blank:]]*\)[[:blank:]]*'\
# '\bDST=\([^[:blank:]]*\)[[:blank:]]*'\
# '\bPROTO=\([^[:blank:]]*\)[[:blank:]]*'\
# '\bSPT=\([^[:blank:]]*\)[[:blank:]]*'\
# '\bDPT=\([^[:blank:]]*\)[[:blank:]]*'\
# '\bGID=\([^[:blank:]]*\)[[:blank:]]*'\
# '\(.*\)$'\
# '@\6: "\1" in:\2 out:\3 src:\4:\7 dst:\5:\8 gid:\9@'

#### | sed -ne 's@^\(.*\)\bIN\b=\([^[:blank:]]*\)[[:blank:]]\+@\1 === \2@'
# | sed -ne 's@^\(.*\)\bIN\b=\([^[:blank:]]*\)[[:blank:]]\+'\
# '\bOUT\b=\([^[:blank:]]*\)[[:blank:]]\+'\
# '\bSRC\b=\([^[:blank:]]*\)[[:blank:]]\+'\
# '\bDST\b=\([^[:blank:]]*\)[[:blank:]]\+'\
# '\bPROTO\b=\([^[:blank:]]*\)[[:blank:]]\+'\
# '\bSPT\b=\([^[:blank:]]*\)[[:blank:]]\+'\
# '\bDPT\b=\([^[:blank:]]*\)[[:blank:]]\+'\
# '\(.*\)$'\
# '@\6: \1 in:\2; out:\3 [ \4:\7 => \5:\8 ] (\9)@p' \



# '\bPROTO\b=\([^[:blank:]]*\)\b[[:blank:]]\+'\
# '\bSPT\b=\([^[:blank:]]*\)\b[[:blank:]]\+'\
# '\bDPT\b=\([^[:blank:]]*\)\b[[:blank:]]\+'\
# '.*'\
# '\bUID\b=\([^[:blank:]]*\)\b[[:blank:]]\+'\
# '\bGID\b=\([^[:blank:]]*\)\b[[:blank:]]\+'\
# '\(.*\)$'\
# '@(msg:\1) -- (in:\2) -- (out:\3) -- (src:\4) -- (dst:\5) -- (proto:\6) -- (spt:\7) -- (dpt:\8) -- (\9) -- (\{10}) -- (\{11}) @p'
    done | sort | uniq
  done
else
  ls -l /var/log/net/iptables_new/*_drop_*.log
fi
