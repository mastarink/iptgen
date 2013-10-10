#!/usr/bin/perl
use strict;
use strict 'vars';
use strict 'refs';
use strict 'subs';
use v5.6.0;

my %services;

sub load_services
{
  local *serv;
  if (open serv, '< /etc/services')
  {
    while(<serv>)
    {
       $services{$3}->{0+$2}=$1 if /^(\w+)\b\s+(\d+)\/(\w+)\b/;
    }
    close serv;
  }
}
sub main
{
  while(<>)
  {
    my %param;
    
    # TRACE: filter:dropFinet:return:33
    $param{_filter}=[$1 , $2 ,$3] if /TRACE\:\s*filter\:(drop|acpt)(2|F|W)(inet|lan|local|in|out)/;
    push @{$param{_dir}}, qw/main table filter chain/;
    push @{$param{_dir}}, 'output' if ($param{_filter}->[1] eq '2');
    push @{$param{_dir}}, 'input' if ($param{_filter}->[1] eq 'F');
    push @{$param{_dir}}, 'forward' if ($param{_filter}->[1] eq 'W');
    push @{$param{_dir}}, $param{_filter}->[2];
    $param{src}=$1 if /\bSRC=(\d+\.\d+\.\d+\.\d+)\b/;
    $param{dst}=$1 if /\bDST=(\d+\.\d+\.\d+\.\d+)\b/;
    $param{spt}=$1 if /\bSPT=(\d+)\b/;
    $param{dpt}=$1 if /\bDPT=(\d+)\b/;
    $param{proto}=lc $1 if /\bPROTO=(\w*)\b/;
    push @{$param{_dir}}, $param{proto};
    $param{input}=$1 if /\bIN=(\w*)\b/;
    $param{output}=$1 if /\bOUT=(\w*)\b/;
    $param{dir}=join('/', @{$param{_dir}});
    $param{dpt}=$services{$param{proto}}->{$param{dpt}} if exists($services{$param{proto}}->{$param{dpt}});
    $param{spt}=$services{$param{proto}}->{$param{spt}} if exists($services{$param{proto}}->{$param{spt}});
##  print $param{proto}." >> ".join(',', keys %services)."\n";
##  print $param{proto}." >> ".join(',', keys %{$services{tcp}})."\n";
##  print $param{proto}." >> ".join(',', keys %{$services{$param{proto}}})."\n";
    print join("\n", map( {"$_=".$param{$_}} sort grep(/^[a-z]/, keys %param)))."\n--------------------------------\n";
  }
}
load_services;
main;
