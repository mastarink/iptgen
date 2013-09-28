#!/bin/sh

function resolve()
{
  if [[ "$RESOLVE_APPLY" ]] ; then
#   echo "dig $@" >&2
    dig +noall +answer +nottlid +noauthority +noadditional $@|sed '/^[[:alnum:]\-]\+\..*\bA\b/!d;s/^.*\bA\b\s\+\(.*\)\s*$/\1/'|sort|uniq|paste -sd ','
  else 
    echo 127.0.0.1
  fi
}
function iface_ip ()
{
  local iface comm p
  iface=$1
  shift
  comm=$1
  shift
  if ! [[ "$iface" ]] ; then iface=enp2s0 ; fi
  if ! [[ "$comm" ]] ; then comm=inet ; fi
  if [[ "$comm" == 'gw' ]] ; then
    /bin/ip -4 -o route show dev "$iface"|sed -n -e 's@^default[[:space:]]\+via[[:space:]]\+\([0-9\.]\+\)[[:space:]]\+metric[[:space:]]\+[[:digit:]]\+@\1@p'
  else
    if [[ "$comm" == 'inet' ]] ; then
      p=2
    elif [[ "$comm" == 'brd' ]] ; then
      p=4
    fi
    /bin/ip -4 -o address show dev "$iface" scope global primary | sed -e "s@^[[:digit:]]\\+:[[:space:]]*\\(eth[[:digit:]]\|enp[[:digit:]]s[[:digit:]]\\)[[:space:]]*inet[[:space:]]*\\([[:digit:]\\.]\\+\\)/\\([[:digit:]]\\+\\)[[:space:]]\\+brd[[:space:]]\\+\\([[:digit:]\\.]\\+\\)[[:space:]]\\+scope[[:space:]]\\+global[[:space:]]\\+\\1@\\$p@"
  fi
}
function init ()
{
  unset   command_not_found_handle
  echo ">>>>> $IPTABLES_BIN" >&2
  if [[ "${IPTABLES_BIN:=/sbin/iptables}" ]] ; then
   
#   export IPT_PREF_PREF="ipt`/bin/date '+%H%M%S'`"
    export IPT_PREF_PREF="ipt4"
    export INET_IFACE="enp2s0"
    export LAN_IFACE="enp4s0"
    export LO_IFACE="lo"
   
    export INET_IP=`iface_ip $INET_IFACE`  
    echo ">>>>>> INET_IP : $INET_IP" >&2
    export INET_GW=`iface_ip $INET_IFACE gw`
  #INET_BROADCAST=$(ip addr show primary $INET_IFACE | sed -e '/inet\b\s*\([0-9\.]\+\)\/[0-9]\+\s*brd\>/!d;s/^\s*inet\s\+\(\S\+\)\/[0-9]\+\s\+brd\s\+\(\S\+\).*/\2/' )
    export INET_BROADCAST=`iface_ip $INET_IFACE brd`


    export LAN_IP=`iface_ip $LAN_IFACE`  
    echo ">>>>>> LAN_IP : $LAN_IP" >&2
    export LAN_BROADCAST=`iface_ip $LAN_IFACE brd`
    #-----------------
    export LAN_3=$(echo $LAN_IP|sed -e 's/\.[0-9]\s*$//')
    echo ">>>>>> LAN_3 : $LAN_3" >&2
#   export LAN_IP_RANGE=$( echo $LAN_IP|sed -e 's/\.[0-9]\s*$/\.0\/24/')
#   export LAN_IP_RANGE0=$(echo $LAN_IP|sed -e 's/\.[0-9]\s*$/\.0\/25/')
#   export LAN_IP_RANGE1=$(echo $LAN_IP|sed -e 's/\.[0-9]\s*$/\.0\/26/')
#   export LAN_IP_RANGE2=$(echo $LAN_IP|sed -e 's/\.[0-9]\s*$/\.64\/26/')
#   export LAN_IP_RANGE3=$(echo $LAN_IP|sed -e 's/\.[0-9]\s*$/\.128\/26/')
#   export LAN_IP_RANGE4=$(echo $LAN_IP|sed -e 's/\.[0-9]\s*$/\.192\/26/')

     export LAN_IP_RANGE="${LAN_3}.0/24"
    export LAN_IP_RANGE0="${LAN_3}.0/25"
    export LAN_IP_RANGE1="${LAN_3}.0/26"
    export LAN_IP_RANGE2="${LAN_3}.64/26"
    export LAN_IP_RANGE3="${LAN_3}.128/26"
    export LAN_IP_RANGE4="${LAN_3}.192/26"
    export LAN_IP_RANGE_VB1="${LAN_3}.80/28"
    export LAN_IP_VB=$LAN_IP_RANGE_VB1
echo "LAN:$LAN_IP_RANGE ; 0:$LAN_IP_RANGE0 ; 1:$LAN_IP_RANGE1 ; 2:$LAN_IP_RANGE2 ; 3:$LAN_IP_RANGE3 ; 4:$LAN_IP_RANGE4 ; 5:$LAN_IP_RANGE5" >&2
      export MAC_LAN_ADDRESS=`resolve mac.mastar.lan`
     export BACK_LAN_ADDRESS=`resolve back.mastar.lan`
      export SSH_LAN_ADDRESS=`resolve ssh.mastar.lan`
      export DNS_LAN_ADDRESS=`resolve ns1.mastar.lan`
    export PROXY_LAN_ADDRESS=`resolve proxy.mastar.lan`
      export APC_LAN_ADDRESS=`resolve apc.mastar.lan`
     export MIKE_LAN_ADDRESS=`resolve mike.lan`
      export MPD_LAN_ADDRESS=`resolve mpd.mastar.lan`
     export ZOCROMAS_LAN_ADDRESS=`resolve zocromas.mastar.lan`
     export ZOCROMAS_LAN_PORT=5005
    echo ">>>>>> ZOCROMAS_LAN_ADDRESS : $ZOCROMAS_LAN_ADDRESS" >&2

 #NO export LO_IP=`iface_ip $LO_IFACE`  
 #   echo "$LO_IFACE LO: $LO_IP" >&2

    export LO_IP=127.0.0.1

    export LOG_NOT_MARK=NOT
    export LOG_YES_MARK=YES
    export LOG_Q_MARK=QST
    export LOG_S_MARK=SHOW

    export mDNS_ADDRESS=224.0.0.251
    unset IP6TABLES_RESTORE IP6TABLES_RESTORE_OPTS
    unset IPTABLES_RESTORE IPTABLES_RESTORE_OPTS
    export IP6TABLES_RESTORE="ip6tables-restore"
    export IPTABLES_RESTORE="iptables-restore"
#   export IP6TABLES_RESTORE_OPTS=' -T filter'
#   export IPTABLES_RESTORE_OPTS=' -T filter'
    

# --log-level level
#     Level of logging (numeric or see syslog.conf(5)). 
# --log-prefix prefix
#     Prefix log messages with the specified prefix; up to 29 letters long, and useful for distinguishing messages in the logs. 
# --log-tcp-sequence
#     Log TCP sequence numbers. This is a security risk if the log is readable by users. 
# --log-tcp-options
#     Log options from the TCP packet header. 
# --log-ip-options
#     Log options from the IP packet header. 
# --log-uid
#     Log the userid of the process which generated the packet. 

    export IPTABLES_LOG_OPTS='--log-uid --log-tcp-options --log-ip-options --log-level 7'

    export SSH_LAN_SERVERS=$MAC_LAN_ADDRESS
    export SSH_LOCAL_SERVERS=`resolve git.mastar.lan`,$SSH_LAN_ADDRESS
    echo ">>>>>> SSH_LOCAL_SERVERS : $SSH_LOCAL_SERVERS" >&2

    export SKYPE_ADDRESS_LIST=91.190.218.0/24,213.146.168.240/28,193.95.154.0/25

    export MSFTD_ADDRESS_LIST=70.37.0.0/17,70.37.128.0/18

    export MSFT_SKYPE_ADDRESS_LIST=157.54.0.0/15,157.56.0.0/14
    export MSFT_GFS_ADDRESS_LIST=$MSFT_SKYPE_ADDRESS_LIST,157.60.0.0/16

    export MSFT_1BLK=65.52.0.0/14
    export MSFT_GLOBAL_NET=207.46.0.0/16
    export MSFT_HOTMAIL=64.4.0.0/18
    export MSFT_IDC=213.199.160.0/19
    # bing.com ...
    export MSFT_NTCSIS_NET=131.253.21.0/24,131.253.22.0/23,131.253.24.0/21,131.253.32.0/20
    export MSFT_ADDRESS_LIST=$MSFT_GFS_ADDRESS_LIST,$MSFT_1BLK,$MSFT_GLOBAL_NET,$MSFT_HOTMAIL,111.221.64.0/18,$MSFT_IDC,$MSFTD_ADDRESS_LIST
#   export MSFT_ADDRESS_LIST=157.60.0.0/16,157.54.0.0/15,157.56.0.0/14,65.52.0.0/14,207.46.0.0/16,64.4.0.0/18,111.221.64.0/18,213.199.160.0/19,$MSFTD_ADDRESS_LIST

    export VERKHOVNA_RADA_ADDRESS_LIST=193.19.152.0/22
    export GOVUA_ADDRESS_LIST=195.78.68.0/23,193.29.204.0/24,$VERKHOVNA_RADA_ADDRESS_LIST
    
    export TRIOLAN_ADDRESS_LIST=109.87.83.0/24
    export MIROHOST_ETC_ADDRESS_LIST=193.178.144.0/22,89.184.64.0/20

    export LIVEI_ADDRESS_LIST=88.212.196.64/26
    export VK_ADDRESS_LIST=87.240.128.0/19,93.186.224.0/22,93.186.228.0/22
    export GOOGLE_ADDRESS_LIST=173.194.0.0/16,74.125.0.0/16,216.239.32.0/19
    export YAHOO_ADDRESS_LIST=98.136.0.0/14,188.125.80.0/21
    export FBSTATIC_ADDRESS_LIST=217.212.238.33,217.212.238.25,217.212.238.49
    export FACEBOOK_ADDRESS_LIST=31.13.64.0/18,173.252.64.0/18,69.171.224.0/19,69.63.176.0/20,66.220.144.0/20,204.15.20.0/22,$FBSTATIC_ADDRESS_LIST
    export WIKIMEDIA_ADDRESS_LIST=208.80.152.0/22
    export YANDEX_ADDRESS_LIST=87.250.250.0/24,93.158.134.0/24,213.180.193.0/24
    export AKAMAI_ADDRESS_LIST=23.32.0.0/11,23.64.0.0/14,95.100.96.0/23,213.248.112.128/25,80.239.178.128/25,2.16.0.0/13,46.33.64.0/21,46.33.72.0/22,46.33.76.0/23,195.27.154.0/24,193.45.10.128/25,62.115.64.128/25,195.59.122.0/24,81.52.207.128/25,217.212.238.0/24,195.27.155.0/24,77.67.91.0/24,213.198.95.128/25,195.10.8.0/23,217.89.107.0/24,62.208.24.0/23,95.100.0.0/20,92.122.189.0/24,195.10.11.0/24,195.59.126.0/24,194.221.64.0/24,80.150.142.0/25,195.59.55.0/24,89.149.151.0/24,92.123.72.0/24,80.157.149.0/24,82.112.106.0/24,213.200.108.0/24,195.59.150.0/24,77.67.96.0/22
    export TUMBLR_ADDRESS_LIST=66.6.32.0/20
    export MAXMIND_ADDRESS=`resolve maxmind.com`
    echo ">>>>>> MAXMIND_ADDRESS : $MAXMIND_ADDRESS"  >&2
    export YOUTUBE_ADDRESS_LIST=208.117.224.0/19
    export RAMBLER_ADDRESS_LIST=81.19.64.0/23,81.19.66.0/24
    export TWITTER_ADDRESS_LIST=`resolve twitter.com`,199.16.156.0/22,199.59.148.0/22
    echo ">>>>>> TWITTER : $TWITTER_ADDRESS_LIST"  >&2
    export DAILYMOTION_A=188.65.120.0/21
    export AMAZON_ADDRESS_LIST=107.20.0.0/14
    export FLIBUSTA_ADDRESS=`resolve static.flibusta.net`
    export BOOKS_ADDRESS_LIST=$FLIBUSTA_ADDRESS,`resolve mobileread.com`,108.162.192.0/18,109.163.230.0/23,93.174.88.192
    echo ">>>>>> BOOKS : $BOOKS_ADDRESS_LIST"  >&2

    export RADIO8000_ADDRESS_LIST=`resolve nrcu.gov.ua cast.radiogroup.com.ua stream.kissfm.ua ua.uar.net`,212.26.129.2,93.178.246.160
    export RADIO8014_ADDRESS_LIST=217.20.164.163
    export PRIVATBANK_ADDRESS_LIST=217.117.65.0/24
    export OBKOM_NET_UA_ADDRESS=`resolve obkom.net.ua`
    export PRAVDA_COM_UA_ADDRESS=`resolve pravda.com.ua blogs.pravda.com.ua tumba.pravda.com.ua tabloid.pravda.com.ua`
    echo ">>>>>> PRAVDA_COM_UA_ADDRESS : $PRAVDA_COM_UA_ADDRESS"  >&2
#  # cat /root/.digrc 
#  +noall
#  +answer

     export NTP_ADDRESSES="`resolve 0.europe.pool.ntp.org 1.europe.pool.ntp.org 2.europe.pool.ntp.org 3.europe.pool.ntp.org 0.gentoo.pool.ntp.org 1.gentoo.pool.ntp.org 2.gentoo.pool.ntp.org 3.gentoo.pool.ntp.org`"
    echo ">>>>>> NTP_ADDRESSES : $NTP_ADDRESSES"  >&2
     export GITHUB_ADDRESS=`resolve github.com`,192.30.252.0/22
    echo ">>>>>> GITHUB_ADDRESS : $GITHUB_ADDRESS"  >&2
     export HTTP_GENTOO_LIST="`resolve gentoo.org dev.gentooexperimental.org distfiles.gentoo.org gpo.zugaina.org download.virtualbox.org codeload.github.com svn.wildfiregames.com download.eclipse.org`"
    echo ">>>>>> HTTP_GENTOO : '$HTTP_GENTOO_LIST'"  >&2
     HTTP_GENTOO_LIST="$HTTP_GENTOO_LIST,$GITHUB_ADDRESS"
    echo ">>>>>> HTTP_GENTOO : '$HTTP_GENTOO_LIST'"  >&2
    export RSYNC_GENTOO_LIST=`resolve gentoo.zugaina.org rsync.gentoo.org`
    echo ">>>>> RSYNC_GENTOO : $RSYNC_GENTOO_LIST" >&2
      export FTP_GENTOO_LIST=`resolve  ftp.stack.nl ftp.iris.washington.edu ftp.csie.ncu.edu.tw ftp.stack.nl ftp.iris.washington.edu ftp.kernel.org ftp.ua.freebsd.org ftp.ua.freebsd.org`
    echo ">>>>> FTP_GENTOO   : $FTP_GENTOO_LIST" >&2
      export GIT_GENTOO_OTHER_LIST=`resolve  git.overlays.gentoo.org github.com git.tuxfamily.org gitorious.org git.mercenariesguild.net git2.kernel.org`
      export GIT_GENTOO_LIST=$GIT_GENTOO_OTHER_LIST
    echo ">>>>> GIT_GENTOO   : $GIT_GENTOO_LIST" >&2
     export TVI_ADDRESS_LIST=`resolve tvi.com.ua media.tvi.com.ua`,109.68.40.0/24
    echo "> TVI_ADDRESS_LIST : $TVI_ADDRESS_LIST" >&2
#     export INTV_ADDRESS_LIST=`resolve rtmp.intv.ua`
#    echo "> INTV_ADDRESS_LIST : $INTV_ADDRESS_LIST" >&2
     export CENSOR_NET_UA_ADDRESS_LIST=77.120.126.64/27
    echo "> CENSOR_NET_UA_ADDRESS_LIST : $CENSOR_NET_UA_ADDRESS_LIST" >&2
    export BBC_ADDRESS_LIST=212.58.224.0/19,`resolve bbcwssc.ic.llnwd.net`
    echo ">>>>>> BBC_ADDRESS_LIST : $BBC_ADDRESS_LIST"  >&2

    export DROPBOX_ADDRESS_LIST=199.47.216.0/22,108.160.160.0/20
    export BOXNET_ADDRESS_LIST=74.112.184.0/22
    export YANDEX_WEBDAV_ADDRESS_LIST=`resolve webdav.yandex.ru webdav.yandex.ua`
    echo ">>>>>> YANDEX_WEBDAV_ADDRESS_LIST : $YANDEX_WEBDAV_ADDRESS_LIST" >&2
    export DAVFS_ADDRESS_LIST=$BOXNET_ADDRESS_LIST,$YANDEX_WEBDAV_ADDRESS_LIST
    export INFORMERS_SINOPTIK_UA=`resolve informers.sinoptik.ua`
    echo ">>>>>> INFORMERS_SINOPTIK_UA : $INFORMERS_SINOPTIK_UA" >&2
    export AD_HIT_ADDRESS_LIST=`resolve ua.hit.gemius.pl`
    echo ">>>>>> AD_HIT_ADDRESS_LIST : $AD_HIT_ADDRESS_LIST" >&2

    export DROP_HTTP_ADDRESS_LIST=`resolve www.tourua.com`
    export DROP_ADDRESS_LIST=$MSFT_ADDRESS_LIST,$AD_HIT_ADDRESS_LIST,$LIVEI_ADDRESS_LIST,$VK_ADDRESS_LIST,$TRIOLAN_ADDRESS_LIST
    export SOURCEFORGE_ADDRESS_LIST=216.34.181.0/24
    export SAMFIND_ADDRESS=`resolve samfind.net samfind.com`
    echo ">>>>>> SAMFIND_ADDRESS : $SAMFIND_ADDRESS" >&2

# for china etc.
    export BAD_ADDRESS_LIST=106.128.0.0/10,66.175.208.0/20
    
    export POP_DOMASHKA_SERVER=`resolve mail.domashka.net`
    export CALIBRE_MASTAR_LAN_SERVER=`resolve calibre.mastar.lan`


    export POP_SERVERS=$POP_DOMASHKA_SERVER,$GOOGLE_ADDRESS_LIST,`resolve pop.gmail.com`
    echo ">>>>>> POP_SERVERS : $POP_SERVERS" >&2
    export SMTP_SERVERS=`resolve smtp.gmail.com`
    echo ">>>>>> SMTP_SERVERS : $SMTP_SERVERS" >&2

    export JP_KDDI=106.128.0.0/10
    export JAPAN_NETWORKS=$JP_KDDI
    export HTTP_PORTS=http,https,8080
     export SQUID_PORT=3128
    export RTMP_PORT=1935
    export BITCOIN_PORT=8333
    export TORRENT_STD_PORTS='6881:6889'
    
    export TCP_INET_OUT_OPTS="-o $INET_IFACE -m tcp -p tcp -s $INET_IP"
  else
    echo "IPTABLES_BIN not set" >&2
  fi
}
function do_iptables_files ()
{
  for name in $@ ; do
    echo -n "@ ${name}" >&2
    sh ${name}
  done
}
function init_script ()
{
  local script dir name
  script=${BASH_SOURCE[2]}
  dir=$( dirname $script )
  name=$( basename $script )
  cd $dir
# echo "[ $name ]	@	$( realpath --relative-to=$MAS_IPTABLES_NTOOLS_DIR . )" >&2
  printf "\n[ %-20s ] %s - " $name $( realpath --relative-to=$MAS_IPTABLES_NTOOLS_DIR . ) >&2
  export IPTABLES_ALLOW_TORRENT=1
# unset IPTABLES_ALLOW_TORRENT
}
function go_log ()
{
  local pword
  pword=$1
  shift
  local newchain
  newchain=$1
  shift
  local qlog
  qlog=$1
  shift
  local chain
  chain=$1
  shift
  if ! [[ "$qlog" == 'NO' ]] ; then
    echo "-A $chain -j LOG --log-prefix " \"$IPT_PREF_PREF: $pword $@ \" $IPTABLES_LOG_OPTS -m comment --comment '(go)'
  fi
  echo "-A $chain -j $newchain" -m comment --comment '(go)'
}
function accept_go_log ()
{
  go_log "$LOG_YES_MARK" $@
}
function accept_log ()
{
  accept_go_log ACCEPT $@
}
function drop_go_log ()
{
  go_log "$LOG_NOT_MARK" $@
}
function drop_log ()
{
  drop_go_log DROP $@
}
function load_torrent_a ()
{
  local list tt
  echo ">>> * ${TORRENTA_ADDR_688X_LIST[1]} * <<<" >&2
  if ! [[ "${TORRENTA_ADDR_688X_LIST[1]}" ]] && [[ -f $MAS_IPTABLES_NTOOLS_DIR/torrent_addresses.lst ]] ; then
    
    while read addr tt ; do
      if ! [[ "$list" ]] ; then
	list="$addr"
      elif [[ "$list" ]] && [[ ${#list} -lt 500 ]] ; then
	list="$list,$addr"
      else
	TORRENTA_ADDR_688X_LIST[${#TORRENTA_ADDR_688X_LIST[@]}]=$list
	list="$addr"
      fi
    done < $MAS_IPTABLES_NTOOLS_DIR/torrent_addresses.lst
    TORRENTA_ADDR_688X_LIST[${#TORRENTA_ADDR_688X_LIST[@]}]=$list
    echo "DONE read torrent list ${#list} -- ${#TORRENTA_ADDR_688X_LIST[@]}" >&2
    unset list
  else
    echo "NOT FOUND $MAS_IPTABLES_NTOOLS_DIR/torrent_addresses.lst at `pwd` -- $MAS_IPTABLES_NTOOLS_DIR" >&2
  fi
}
init_script $@
