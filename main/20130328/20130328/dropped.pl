#!/usr/bin/perl
# ./dropped.pl  tcp input  drop
# ./dropped.pl  tcp forward  drop

use strict 'vars';
use strict 'refs';
use strict 'subs';
use v5.6.0;

sub main
{
  my ($param_proto, $param_way, @templates);
  my @files;
  my @file_lines;
  my @lines;
  my %printlines;
  my %services;
  my %groups;
  my %users;
  my @allprops;
  for my $p (@_)
  {
    if ($p=~/^(tcp|udp|icmp)$/i)
    { $param_proto=$1; }
    elsif ($p=~/^(input|output|forward)$/i)
    { $param_way=$1; }
    else
    { push @templates, $p; }
  }
  $param_proto='tcp' if (!$param_proto);
  $param_way='input' if (!$param_way);
  @templates=('drop') if ($#templates<0);
  for my $t ( @templates )
  {
    push @files, glob("/var/log/net/iptables_new/*$t*");
  }
# print "$param_proto : $param_way : ".join(',',@files)." - $#templates";
  if (open F, "</etc/services")
  {
    my @file_lines=<F>;
    for my $l (@file_lines)
    {
      chomp $l;
      if ($l=~/^(\S+)\s+(\d+)\/(\S+)\b.*$/)
      {
        my ($port, $service, $proto);
	$port=0+$2;
	$service=$1;
	$proto=$3;
	$services{$proto}={} if !exists($services{$proto});
	$services{$proto}{$port}=$service;
#	print ">>>>>>>> $proto / $port = $service \n";
      }
    }
#    print ">>>>>>>> $services{tcp}{445}\n";
    close F;
#   for my $k (sort keys %services)
#   {
#     print STDERR "$k\n";
#     for my $p (sort {$a <=> $b} keys %{$services{$k}})
#     {
#       print STDERR "  $p : $services{$k}{$p}\n";
#     }
#   }
  }
  $services{tcp}{3128}='squid' if (!exists($services{tcp}{3128}));
  if (open F, "</etc/group")
  {
    my @file_lines=<F>;
    for my $l (@file_lines)
    {
      chomp $l;
# mastar-xmpp:x:1073:mastar
      if ($l=~/^\s*(\S+):(\S*):(\S+):(\S*)\s*$/)
      {
        my $name=$1;
        my $gid=0+$3;
        $groups{$gid}=$name;
      }
    }
    close F;
  }
  if (open F, "</etc/passwd")
  {
    my @file_lines=<F>;
    for my $l (@file_lines)
    {
      chomp $l;
# squid:x:31:31:added by portage for squid:/var/cache/squid:/sbin/nologin
# 1     2 3  4  5                          6                7
      if ($l=~/^\s*(\S+):(\S*):(\S*):(\S*):(.*):(\S*):(\S*)\s*$/)
      {
        my $name=$1;
        my $uid=0+$3;
        $users{$uid}=$name;
      }
      else
      {
	print "Why 2 >>>>>> $l\n";
	exit;
      }
    }
    close F;
  }  
# for my $k ( sort { $a <=> $b } keys %users )
# {
#   print "$k - $users{$k}\n";
# }
# exit;
  for my $filepath ( @files )
  {
    local *F;
#   print "$param_proto : $param_way - $filepath\n";
#   print STDERR "Log:$filepath\n";
    if (open F, "<$filepath")
    {
      my $x;
#     print STDERR "$filepath opened\n";
      while (<F>)
      {
        chomp $_;
	push @lines, $_;
	shift @lines if $#lines > 100000;
#	print STDERR "$_\n";
      }
      close F;
    }
  }
  {
    my $line;
    while ($line = pop( @lines ))
    {
      my %props;
#     print STDERR "$line\n";
  #    0923:153215 IPT4: [418832.385984] ipt4: NOT from inet IN=enp2s0 OUT= MAC=mETH0:dmsh:08:00 SRC=212.25.55.48 DST=INET LEN=48 TOS=0x00 PREC=0x80 TTL=117 ID=42057 DF PROTO=TCP SPT=4395 DPT=4899 WINDOW=65535 RES=0x00 SYN URGP=0 OPT (020405A001010402) 
  #    0923:095746 ipt4: [398820.387188] ipt4: NOT lstd ports from ineIN=enp2s0 OUT= MAC=mETH0:dmsh:08:00 SRC=118.123.7.96 DST=INET LEN=40 TOS=0x00 PREC=0x80 TTL=100 ID=256 PROTO=TCP SPT=6000 DPT=1433 WINDOW=16384 RES=0x00 SYN URGP=0
      $props{line}=$line;
      $props{input}=$1    if (    $line=~s/IN=(\S*)\s//g && $1 );
      $props{output}=$1   if ( $line=~s/\bOUT=(\S*)\s//g && $1 );
      $props{MAC}=$1      if ( $line=~s/\bMAC=(\S*)\s//g && $1 );
      $props{src}=$1      if ( $line=~s/\bSRC=(\S*)\s//g && $1 );
      $props{spt}=0+$1    if ( $line=~s/\bSPT=(\S*)\s//g && $1 );
      $props{dst}=$1      if ( $line=~s/\bDST=(\S*)\s//g && $1 );
      $props{dpt}=0+$1    if ( $line=~s/\bDPT=(\S*)\s//g && $1 );
      $props{gid}=0+$1    if ( $line=~s/\bGID=(\S*)\s//g && $1 );
      $props{uid}=0+$1    if ( $line=~s/\bUID=(\S*)\s//g && $1 );
      $props{mac}=0+$1    if ( $line=~s/\bMAC=(\S*)\s//g && $1 );
      $props{proto}=lc( $1 ) if ( $line=~s/\bPROTO=(\S*)\b//g && $1 );
      $props{"-$1"}=0+$2 while ( $line=~s/\b([A-Z]+)=(\S*)\b//g && $2 );
      if ( exists($services{$props{proto}}) )
      {
	my $protser=$services{$props{proto}};
	$props{spts}=$protser->{$props{spt}}   if ( exists($protser->{$props{spt}}) );
	$props{dpts}=$protser->{$props{dpt}}   if ( exists($protser->{$props{dpt}}) );
	delete $props{spts} if ( $props{dpts}=~/^(ms-sql-s|x11)$/ );
	delete $props{dpts} if ( $props{dpts}=~/^(ms-sql-s|x11)$/ );
      }
      if ( exists($groups{$props{gid}}) )
      {
	$props{group}=$groups{$props{gid}};
      }
      if ( exists($users{$props{uid}}) )
      {
	$props{user}=$users{$props{uid}};
      }
      if (exists($props{dst}))
      {
	if ( $props{dst} eq '224.0.0.251' )
	{  $props{dst}='mDNS'  }
      }
      if (exists($props{src}))
      {
	if ( $props{dst} eq '224.0.0.251' )
	{  $props{dst}='mDNS'  }
      }
      
  #    mDNS=224.0.0.251

  #   print STDERR "$input; ::: $line\n";
  #   for my $k ( keys(%props) )
  #   {
  #     print "$k => $props{$k}\n" if $k ne 'line';
  #   }
      {
	my ($inf, $outf);
	$inf=exists($props{'input'});
	$outf=exists($props{'output'});
	if ($inf && $outf)
	{
	# forward/...
	  $props{way}='forward';
	}
	elsif ($inf)
	{
	# input/...
	  $props{way}='input';
	}
	elsif ($outf)
	{
	# output/...
	  $props{way}='output';
	}
	else
	{
	  print STDERR "Why ? $props{line}";
	  exit;
	}
  #     print STDERR "way:$param_way ? $props{way} ".(exists($props{'input'})?"I":"?").(exists($props{'output'})?"O":"?")." -- $props{line}\n";
      }
      push @allprops, \%props;
    }
  }
  if ($param_way eq 'input')
  {
    for my $props ( sort { $b->{dpt} <=> $a->{dpt} } @allprops )
    {
#     if ($props->{way} && exists($props->{proto}) && $param_proto eq $props->{proto} && $param_way eq $props->{way} && $props->{dst} eq 'INET' )
      if ($props->{way} && exists($props->{proto}) && $param_proto eq $props->{proto} && $param_way eq $props->{way} )
      {
#       for my $k ( grep !/^(way|input|dst|MAC|line)$/, keys(%$props) )
#       {
#         print "$#file_lines. $k => $props->{$k}\n";
#       }
        $printlines{ sprintf "%-4s %5d (%14s) <= %16s:%-5d (%14s)", $props->{proto}, $props->{dpt}, $props->{dpts}, $props->{src}, $props->{spt}, $props->{spts} } = 1;
#	print "--\n";
      }  
      else
      {
      }
    }
  }
  elsif ($param_way eq 'output')
  {
    for my $props ( sort { $b->{spt} <=> $a->{spt} } @allprops )
    {
#     if ($props->{way} && exists($props->{proto}) && $param_proto eq $props->{proto} && $param_way eq $props->{way} && $props->{src} eq 'INET' )
      if ($props->{way} && exists($props->{proto}) && $param_proto eq $props->{proto} && $param_way eq $props->{way} )
      {
#       for my $k ( grep !/^(way|$param_way|src|MAC)$/, keys(%$props) )
#       {
#         print "$k => $props->{$k}\n";
#       }
        $printlines{ sprintf "%-4s => %16s:%-5d (%14s)", $props->{proto}, $props->{dst}, $props->{dpt}, $props->{dpts} } =1;
#	print "--\n";
      }  
    }
  }
  elsif ($param_way eq 'forward')
  {
    for my $props ( @allprops )
    {
      if ($props->{way} && exists($props->{proto}) && $param_proto eq $props->{proto} && $param_way eq $props->{way} )
      {
##      for my $k ( grep !/^(way|$param_way|MAC)$/, keys(%$props) )
##      {
##        print "$k => $props->{$k}\n";
##      }
        if ($props->{input} eq 'enp2s0')
        {
	  $printlines{ sprintf "%-4s %s %5d (%14s) <= %16s:%-5d (%14s)", $props->{proto}, $props->{dst}, $props->{dpt}, $props->{dpts}, $props->{src}, $props->{spt}, $props->{spts} } = 1;
	}
	elsif ($props->{output} eq 'enp2s0')
        {
	  $printlines{ sprintf "%-4s %s => %16s:%-5d (%14s)", $props->{proto}, $props->{src}, $props->{dst}, $props->{dpt}, $props->{dpts} } =1;
	}
	else
        {
	  $printlines{ sprintf "%-4s %s %5d (%14s) <=? %16s:%-5d (%14s)", $props->{proto}, $props->{dst}, $props->{dpt}, $props->{dpts}, $props->{src}, $props->{spt}, $props->{spts} } = 1;
	  $printlines{ sprintf "%-4s %s ?=> %16s:%-5d (%s)", $props->{proto}, $props->{src}, $props->{dst}, $props->{dpt}, $props->{dpts} } =1;
	}
#	print "--\n";
      }  
    }
  }
  elsif ($param_way eq 'all')
  {
    for my $props ( sort { $b->{spt} <=> $a->{spt} } @allprops )
    {
      if ($props->{way} && exists($props->{proto}) && $param_proto eq $props->{proto} )
      {
        for my $k ( grep !/^(way|MAC)$/, keys(%$props) )
        {
          print "$k => $props->{$k}\n";
        }
#       $printlines{ sprintf "%-4s => %16s:%-5d", $props->{proto}, $props->{dst}, $props->{dpt} } =1;
 	print "--\n";
      }  
    }
  }  
  for my $pl (sort keys %printlines)
  {
    print "$pl\n"
  }
}

# print STDERR "Wow again - ".join(',', @ARGV)."\n";
main @ARGV;
