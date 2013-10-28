#/bin/sh
stamp=`datemt`
prev=`ls -1tr S/iptables*.S | tail -1`
iptables -F -t raw
iptables -F
iptables -X
iptables-restore ./iptables.built
iptables -S > S/iptables.${stamp}.S
last=`ls -1tr S/iptables*.S | tail -1`
if [[ "$prev" ]] && [[ "$last" ]] && ! [[ "$prev" == "$last" ]] && [[ -f "$prev" ]] && [[ -f "$last" ]] ; then
  if diff $prev $last >  S/iptables-S.${stamp}.diff ; then
    echo diff passed >&2
    rm S/iptables-S.${stamp}.diff
    rm S/iptables.${stamp}.S
  else
    echo diff NOT passed >&2
  fi
  ls -l  --time-style="+%b %d %Y %H:%M:%S" $prev $last S/iptables-S.${stamp}.diff 2>/dev/null
fi
find S/ -size 0 -exec rm \{} \;
