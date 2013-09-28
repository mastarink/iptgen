#!/bin/sh
unset TORRENTA_ADDR_688X_LIST
declare -a TORRENTA_ADDR_688X_LIST
  echo "[$LINENO] $MAS_IP_FUNCTIONS" >&2

unset IP6TABLES_APPLY
unset IPTABLES_APPLY
if ! [[ "$1" ]] || [[ "$1" == apply ]] || [[ "$1" == yes ]] ; then
    export IP6TABLES_APPLY=yes
    export IPTABLES_APPLY=yes
elif [[ "$1" == no ]] ; then
    export IP6TABLES_APPLY=
    export IPTABLES_APPLY=
fi
shift
if ! [[ "$1" ]] || [[ "$1" == apply ]] || [[ "$1" == yes ]] ; then
    export RESOLVE_APPLY=yes
elif [[ "$1" == no ]] ; then
    export RESOLVE_APPLY=
fi
shift

export MAS_IPTABLES_NTOOLS_DIR=$( realpath $( dirname ${BASH_SOURCE[0]} ) )
export MAS_IP_FUNCTIONS=$( realpath $MAS_IPTABLES_NTOOLS_DIR/functions.sh )
  echo "[$LINENO] $MAS_IP_FUNCTIONS" >&2
if [[ -f "$MAS_IP_FUNCTIONS" ]] ; then
. $MAS_IP_FUNCTIONS
  echo "[$LINENO] $MAS_IP_FUNCTIONS" >&2
  init $@
  echo "[$LINENO] $MAS_IP_FUNCTIONS" >&2
  echo ">>>>> : LAN_IP:$LAN_IP : LAN_BROADCAST:$LAN_BROADCAST : IP:$INET_IP : GW:$INET_GW : INET_BROADCAST:$INET_BROADCAST :" >&2
# load_torrent_a
  echo ">>> * ${#TORRENTA_ADDR_688X_LIST[@]} *  ${TORRENTA_ADDR_688X_LIST[1]} * <<<" >&2
  if [[ "$LAN_IP"  ]] && [[ "$LAN_BROADCAST"  ]] && [[ "$INET_IP"  ]] && [[ "$INET_GW"  ]] && [[ "$INET_BROADCAST"  ]] ; then
    if [[ "$IP6TABLES_APPLY" ]] && [[ "$IP6TABLES_RESTORE" ]] ; then
      (
        echo '*mangle'
	sh mangle6.rules
	echo 'COMMIT'
        echo '*nat'
	sh nat6.rules
	echo 'COMMIT'
	echo '*filter'
        sh filter6.rules
	echo 'COMMIT'
      ) | $IP6TABLES_RESTORE $IP6TABLES_RESTORE_OPTS
    else
      (
        echo '*mangle'
	sh mangle6.rules
	echo 'COMMIT'
        echo '*nat'
	sh nat6.rules
	echo 'COMMIT'
	echo '*filter'
        sh filter6.rules
	echo 'COMMIT'
      )
    fi
    if [[ "$IPTABLES_APPLY" ]] && [[ "$IPTABLES_RESTORE" ]] ; then
      (  
        echo '*nat'
	sh nat.rules
	echo 'COMMIT'
	echo '*filter'
	sh filter.rules
	echo 'COMMIT'
	echo '#'
      ) | $IPTABLES_RESTORE $IPTABLES_RESTORE_OPTS
    else
      (  
        echo '*nat'
	sh nat.rules
	echo 'COMMIT'
	echo '*filter'
	sh filter.rules
	echo 'COMMIT'
	echo '#'
      )    
    fi
  fi
else 
  echo "ERROR : no '$MAS_IP_FUNCTIONS'" >&2
fi
