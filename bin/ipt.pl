#!/usr/bin/perl

use strict;
use strict 'vars';
use strict 'refs';
use strict 'subs';
use v5.6.0;

use Net::DNS::Resolver;
use Net::IP;
use IO::Interface::Simple;

my $res = Net::DNS::Resolver->new;

my $if0   = IO::Interface::Simple->new('enp2s0');
if ( $#ARGV >=0 )
{
  my @hosts;
  my $ipinet=$if0->address;
  my $name=$ARGV[2];
  print "ipinet: $ipinet\n";
  @hosts=$ARGV[2
  
  ];
  print "hosts: ".join(',', @hosts);
  {
    my $query = $res->search($name);
    for my $rr ($query->answer)
    {
      next unless $rr->type eq "A";
      my $addr=$rr->address,"\n";
      if ($ARGV[1] eq 'ftp' )
      {
        my $cmd;
	$cmd='A' if ( $ARGV[0] eq 'add' );
	$cmd='D' if ( $ARGV[0] eq 'del' );
	if($cmd)
	{
	  system("iptables -$cmd ftp_tcp2inet -d $addr -p tcp -m tcp -m comment --comment ftp -j acpt2inet");
	  system("iptables -$cmd ftp_tcpFinet -s $addr -d $ipinet -p tcp -m tcp -m helper --helper ftp -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment ftp -j acptFinet");
	}
      }
    }
  }
}

# -A ftp_tcp2inet -d 128.39.3.170/32 -p tcp -m tcp -m comment --comment ftp -j acpt2inet
# -A ftp_tcpFinet -s 128.39.3.170/32 -d 193.222.140.165/32 -p tcp -m tcp -m helper --helper ftp -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment ftp -j acptFinet

