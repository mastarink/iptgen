#!/bin/sh

function turnit
{
  local what=$1
  shift
  local action=$1
  shift  
  case $what in
    skype)
      iptables $action  http2inet                        -p tcp -m tcp -m comment --comment "tcp http for skype" -j skype_http2inet
      iptables $action  tcp2inet                         -p tcp -m tcp -m comment --comment skype                -j skype_tcp2inet
      iptables $action  tcpFinet  -d 193.222.140.165/32  -p tcp -m tcp -m comment --comment skype                -j skype_tcpFinet
      iptables $action  udp2inet                         -p udp -m udp -m comment --comment skype                -j skype_udp2inet
      iptables $action  udpFinet                         -p udp -m udp -m comment --comment skype                -j skype_udpFinet
      iptables $action  udpWin                           -p udp -m udp -m comment --comment skype                -j skype_udpWin
      iptables $action  udpWout                          -p udp -m udp -m comment --comment skype                -j skype_udpWout
    ;;
    sop|sopcast)
    ;;
    http)
    ;;
    radio)
    ;;
    gentoo)
    ;;
  esac
}

function turn
{
  local action=$1
  shift
  for what in $* ; do
    if [[ "$action" == 'on' ]] ; then
      turnit $what '-I'
    elif [[ "$action" == 'off' ]] ; then
      turnit $what '-D'
    fi
  done
}

turn $*
