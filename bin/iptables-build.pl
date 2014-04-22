#!/usr/bin/perl
# ./bin/iptables-build.pl 1000  | grep -- '\(^\s*[[:digit:]]\+\s*-A\s*F\(lan\|inet\)\|ERROR\)'
# ./bin/iptables-build.pl 1000  | grep -- '\(^\s*[[:digit:]]\+\s*-A\s*\(tcp\|udp\|icmp\|drop\|accept\|\)\(F\|2\)\(lan\|inet\|local\|lan_vbox\)\|ERROR\)'
# ./bin/iptables-build.pl 1000  | grep -- '\(^\s*[[:digit:]]\+\s*-A\s*\(\(tcp\|udp\|icmp\|drop\|acpt\|\)\(F\|2\)\(lan\|inet\|local\|lan_vbox\)\|INPUT\|OUTPUT\|FORWARD\|POSTROUTING\)\|ERROR\)'
# ./bin/iptables-build.pl 1000  | grep --color=yes -- '\(^\s*[[:digit:]]\+\s*-A\s*\(\(tcp\|udp\|icmp\|drop\|acpt\|\(icmp\|tcp\|udp\)_acpt\|\)\(F\|2\)\(lan\|inet\|local\|lan_vbox\)\|INPUT\|OUTPUT\|FORWARD\|POSTROUTING\)\|ERROR\)'

#  iptables -F -t raw ; iptables -X -t raw ; iptables -F ; iptables -X ; iptables-restore old.iptables 
#  iptables -F -t raw ; iptables -X -t raw ; iptables -F ; iptables -X ; iptables-restore /home/mastar/.mas/config/iptables-build/iptables.built

# bin/iptables-build.pl ; cp ./iptables.built ./iptables.built.`datemt` ; diff iptables.built iptables.built.20131004.good >/dev/null || echo -e "\n\n>>>>>>>>> DIFFERENCES DETECTED<<<<<<<<<<<<\n\n\n"


use strict;
use strict 'vars';
use strict 'refs';
use strict 'subs';
use v5.6.0;

use Net::DNS::Resolver;
use Net::IP;
use IO::Interface::Simple;

my @ftest;

my $current_build_file;

my $incdir;
my $upname;
my $incname;
my $thisname;
my $workdir;
my $confdir;
my %control;
my $current_table;
my %tables;
my %variables;
my $output_active=1;
my $only_chain;
my $output_line_comments=1;
my $output_namecomment=1;
my $output_empty_lines=1;
my $ipt_num=0;
my %resolved;
my %targets_disabled;
my %includes_disabled;
my @errors;
my @messages;
my ($last_literal, $last_command, $cmp_disabled);
my @basic_propset=qw/chain target interface output input proto dst src macdst macsrc dpt not-dpt dpts spt not-spt spts ctstate uid-owner gid-owner icmp-type helper comment/;
sub build_names;

sub outerr
{
  my ($code, @msg)=@_;
  my $err=[$#errors + 1, $code, join(' ', @msg), $current_build_file];
  push @errors, $err;
  printf save "### %3d ERROR : %03d: %s\n###       AT file %120s\n", @$err;
}
sub outmsg
{
  my ($code, @msg)=@_;
  my $msg=[$#messages + 1, $code, join(' ', @msg), $current_build_file];
  push @messages, $msg;
  printf save "#                        MSG : %03d: %s\n", $code, join(' ', @msg);
}

sub outlog
{
  my (@msg)=@_;
# printf "%s\n", join(' ', @msg);
}

sub output_literal
{
  my (@command)=@_;
  $ipt_num++;
  if (0)
  {
    $last_literal=join(' ', @command);
    $last_literal=~s/^\s+//;
    $last_literal=~s/^(:)\s+/$1/;
#nizzya:   $last_literal=~s/^(\-A.*)$/$1\t\t\t  #--/;
    print save "$last_literal\n" if (($output_active > 0) && (!$only_chain || $tables{$current_table}{current_chain} eq $only_chain));
  }
  else
  {
    my $prefix=shift @command;
    my $cmd=join(' ', @command);
    $prefix=~s/^\s+//;
    $cmd=~s/^\s+//;
    $last_literal=$prefix.$cmd;
#   print save "($ipt_num)";
    print save $last_literal,"\n" if (($output_active > 0) && (!$only_chain || $tables{$current_table}{current_chain} eq $only_chain));
  }
}
sub output_command
{
  output_literal @_;
  $last_command=$last_literal;
}

sub resolve
{
  my ($name)=@_;
  my @result;
  my $res;
# my $res = Net::DNS::Resolver->new(udp_timeout=>1, tcp_timeout=>1);
  my $res = Net::DNS::Resolver->new;
# if (!exists($resolved{$name}))
  {
    my $query = $res->search($name);
    
  # outmsg __LINE__,"RESOLVE $name";
    if ($query)
    {
      foreach my $rr ($query->answer)
      {
	next unless $rr->type eq "A";
	$resolved{$name}->{$rr->address}=1;
      }
    }
  }
  if (exists($resolved{$name}))
  {
    @result = keys %{$resolved{$name}};
#   outmsg __LINE__,"resolve P: $name : ".$resolved{$name}."\n";
  }
# outmsg __LINE__,"resolve J: $name : ".join(',', @result)."\n";
  return @result;
}
sub ip_compare
{
  my ($a,$b)=@_;
  if ($a && $b && $a!~/:/ && $b!~/:/)
  {
    $a=~s/\/\d+$//;
    $b=~s/\/\d+$//;
    my $ip1 = new Net::IP ($a);
    my $ip2 = new Net::IP ($b);
    die "Bad address $a" if (!$ip1);
    die "Bad address $b" if (!$ip2);
  # print '########## 1:',$ip1->ip(),'              2:',$ip2->ip()," CMP:",($ip1->intip() <=> $ip2->intip()),"\n";
    return $ip1->intip() <=> $ip2->intip();
  }
  else
  {  return 0;  }
}
sub make_address_array
{
  my (@addresses)=map { split /\s*,\s*/ } @_;
  my @ips;
# outmsg __LINE__, "A ".join(';',@addresses);
  for my $address (@addresses)
  {
    if ($address=~/^\s*include\s+(.*)$/)
    {    
      my(@ipst, @iplines);
      @iplines=map {'+'.$_} map { split /\s+/ } $1;
      @ipst=make_address_array(@iplines);
      push(@ips, @ipst);
    }
    elsif ($confdir && ($address=~/^\s*\+([\w\-\/]+?)\s*$/))
    {
      local *ipfile;
      my @names=split(/\s+/, $1);
      for my $name (@names)
      {
        my $ipfname="$confdir/main/ip/$name.ip";
#       outmsg __LINE__, "IP file: $name";
	if (-f $ipfname && open ipfile, $ipfname)
	{
	  my @iplines=grep !/^\s*#/, <ipfile>;
	  chomp @iplines;      
	  close ipfile;
	  my @ipst;
	  @ipst=make_address_array(@iplines);
	  push(@ips, @ipst);
	}
	else
	{
	  outerr __LINE__, "no file $ipfname";
	}
      }
    }
    elsif ($address=~/^([\da-f]{2}:[\da-f]{2}:[\da-f]{2}:[\da-f]{2}:[\da-f]{2}:[\da-f]{2})$/i)
    {
      push @ips, $1;
#     push @ips, split /\s*,\s*/, $1;
    }
    elsif ($address=~/^\d+\.\d+\.\d+\.\d+(\/\d+|)$/)
    { 
      push @ips, ($address);
    }
    elsif ($address=~/^([\w\-\.]+\.[\w\-]+)$/)
    {
      my @ipsr=resolve($address);
      if ($#ipsr<0)
      {
	outerr __LINE__, "wrong address '$address'";
	die("wrong address '$address'");
      }
      else
      {
        push @ips, @ipsr;
      }
    }
    else
    {
      die("Is it bad: [$address]");
    }
  }
# outmsg __LINE__, "Z ".join(';',@ips);
  die("?? ") if !@ips;
  my %ips;
  $ips{$_}=1 for (@ips);
  return  sort( {ip_compare($a, $b)}  keys %ips);
}

sub make_address_list
{
  my $r;
  
  $r=join(',', make_address_array( @_  ));
  return $r;
}
sub make_address_x
{
  my (@a)=map {'+'.$_} map { split /\s*,\s*/ } @_; 
  return make_address_list @a;
}
sub make_comment
{
  my (@comments)=map { split /\s+/ } @_;
  my $c;
  if ($#comments>0) { $c='"'.join(' ',@comments).'"'; }
  else { $c=join(' ',@comments) ;}
}

sub make_substitutionz
{
  my ($command)=@_;
  my $subs=0;
  do
  {
    $subs=0;
    for (@$command)
    {
      $subs++      if (s/\^/$upname/);
      $subs++      if (s/@/$incname/);
      $subs++      if (s/&/$thisname/);
    }
  } while $subs>0;
# outmsg __LINE__, join(';', @$command);
}
sub make_substitution
{
  my ($command)=@_;
  my $subs=0;
  do
  {
    $subs=0;
    for (@$command)
    {
      my $fl=/virtual/;
      if (s/\$\{([\w\-]+)\}/$variables{$1}/)
      {
        outerr __LINE__, "variable '$1' not defined" unless exists($variables{$1});
	$subs++;
      }
      if (s/\$([\w\-]+)\b/$variables{$1}/)
      {
        outerr __LINE__, "variable '$1' not defined" unless exists($variables{$1});
	$subs++;
      }
#     $subs++      if (s/(\+[\+\w\-\,\/\.]+)\b/make_address_list($1)/e);
      $subs++      if (s/(\+[\w\-\/]+)\b/make_address_list($1)/ge);
      $subs++      if (s/(\+\{([\w\-\,\/]+)\b\})/make_address_x($2)/e);
    }
  } while $subs>0;
# outmsg __LINE__, join(';', @$command);
}

sub make_command_table
{
  my (@command)=@_;
  if ( $command[0] eq 'begin' )
  {
    $current_table=$command[1];
    output_command '*'.$command[1];
    output_literal '';
  }
  elsif ( $current_table eq $command[1] && $command[0] eq 'end' )
  {
    undef $current_table;
    output_literal '';
    output_literal '';
    output_command 'COMMIT';
  }
  else
  {
    outerr __LINE__, "structure error\n";
  }
}
sub make_command_policy
{
  my (@command)=@_;
  # last!
  my $policy=pop @command;
  my $table=$current_table;
  for my $chain (@command)
  {
    if ($chain)
    {
      if ( !exists($tables{$table}{chain}->{$chain}->{policy}) )
      {
	if ((($policy && $policy ne '-') || $chain!~/^((IN|OUT)PUT|(PRE|POST)ROUTING|FORWARD|LOG)$/))
	{
	  output_command ':', $chain, $policy;
	}
	$tables{$table}{chain}->{$chain}->{policy}=$policy;
      }
    }
    else
    {
      outerr __LINE__, "empty chain name";
    }
  }
}
sub make_command_chain
{
  my (@command)=@_;
  for my $chain (@command)
  {
    if ($chain)
    {
      if (!exists($tables{$current_table}{chain}->{$chain}->{policy}))
      {
	make_command_policy $chain, '-';
      }
      $tables{$current_table}{current_chain}=$chain;
    }
    else
    {
      outerr __LINE__, "empty chain name";
    }
  }
}
sub make_command_rule
{
  my (@command)=@_;
  if (exists($tables{$current_table}{current_chain}))
  {
    my %opts;
    my @line;
#    =("-A $tables{$current_table}{current_chain}");
    my %names=(
		 chain=>{name=>'A', order=>0},
		 comment=>{name=>'-comment', order=>990000, module=>{comment=>'comment'}, process=>'make_comment'},
		 ctstate=>{name=>'-ctstate', order=>10000, module=>{ctstate=>'conntrack'}},
		 'uid-owner'=>{name=>'-uid-owner', order=>10000, module=>{'uid-owner'=>'owner'}},
		 'gid-owner'=>{name=>'-gid-owner', order=>10000, module=>{'gid-owner'=>'owner'}},
		 'icmp-type'=>{name=>'-icmp-type', order=>170},
		 dpt=>{name=>'-dport', order=>1040},
		 'not-dpt'=>{name=>'-dport', order=>1040, prefix=>'!'},
		 dpts=>{name=>'-dports', order=>1040, module=>{dpts=>'multiport'}},
		 'not-dpts'=>{name=>'-dports', order=>1040, module=>{'not-dpts'=>'multiport'}, prefix=>'!'},
		 dst=>{name=>'d', order=>1030, process=>'make_address_list'},
		 foreign=>{name=>{input=>'s', output=>'d'}, order=>1030, process=>'make_address_list'},
		 helper=>{name=>'-helper', order=>200, module=>{helper=>'helper'}},
		 input=> {name=>'i', order=>110},
		 lit=>{name=>'', order=>80000},
		 macdst=>{name=>'-mac-dst?', order=>1030, module=>{macdst=>'mac'}},
		 macsrc=>{name=>'-mac-source', order=>1010, module=>{macsrc=>'mac'}},
		 output=>{name=>'o', order=>120},
		 proto=>{name=>'p', order=>150, module=>{tcp=>'tcp',udp=>'udp',icmp=>'icmp'}},
		 spt=>{name=>'-sport', order=>1020},
		 'not-spt'=>{name=>'-sport', order=>1020, prefix=>'!'},
		 spts=>{name=>'-sports', order=>1020, module=>{spts=>'multiport'}},
		 'not-spts'=>{name=>'-sports', order=>1020, module=>{'not-spts'=>'multiport'}, prefix=>'!'},
		 src=>{name=>'s', order=>1010, process=>'make_address_list'},
		 tail=>{name=>'', order=>100000},
		 target=>{name=>'j', order=>100000},
	      );
    my $cmd;
    while( $cmd = shift(@command) )
    {
      my $name;
      my $opt;
      # do parenthesis
      while(@command && $cmd =~/^\s*(\S+)\s*\([^\)]*$/)
      {
        $cmd="$cmd ".shift(@command);
      }
      if ($cmd =~/^\s*(\S+)\s*\(\s*([^\)]*)\s*\)\s*$/ && exists($names{$1}->{name}))
      {
	$name=$1;
	$opt=$2;
#       outmsg __LINE__, "CMD:$cmd";
      }
      else
      {
        $name='tail';
	$opt=$cmd;
      }
      if ($opts{$name})
      {
	$opts{$name}=$opts{$name}.' '.$opt;
      }
      else
      {
	$opts{$name}=$opt;
      }
    }
    for my $node (@basic_propset)
    {
      if (!exists($opts{$node}) && exists($tables{$current_table}{$node}))
      {
        if ( $node eq 'chain' )
	{
	  $opts{$node}=$tables{$current_table}{current_chain};
	}
	else
	{
	  $opts{$node}=$tables{$current_table}{$node};
	}
      }
      delete $opts{$node}	if (exists($opts{$node}) && $opts{$node} eq '-' || length($opts{$node}) == 0);
    }
    my %linemodules;
    for my $name (sort({ $names{$a}->{order} <=> $names{$b}->{order} } keys(%opts)))
    {
      if (exists $names{$name}->{process} )
      {
        my $process=$names{$name}->{process};
 	$opts{$name}=eval "$process('$opts{$name}')";
      }
      {
        my $line;
        if (           exists     $names{$name}->{module}->{$opts{$name}}       )
        {
	  my $val=$names{$name}->{module}->{$opts{$name}};
          $line="-m $val ";
        }
	elsif (        exists     $names{$name}->{module}->{$name}   )
	{
	  my $val=$names{$name}->{module}->{$name};
	  if (!exists($linemodules{$val}) )
	  {
	    $linemodules{$val}=$name;
            $line="-m $val ";
	  }
	}
        if ($name eq 'tail' || $name eq 'lit')
	{
	  push @line, $opts{$name};
	}
	else
	{
	  my $prefix;
	  $prefix=$names{$name}->{prefix}.' ' if exists($names{$name}->{prefix});
	  {
	    my $k=$names{$name}->{name};
	    if (ref($k) eq 'HASH' )
	    { $k=$k->{$variables{in_out}}; }
	    $line.=$prefix.'-'.$k.' '.$opts{$name};
	  }
	  push @line, $line;
	}
      }
    }
    $cmp_disabled=1;
    if (!exists $opts{target} || !exists($targets_disabled{$opts{target}}) )
    {
      output_command '', @line;
      undef $cmp_disabled;
    }
  }
  else
  {
    outerr __LINE__, "unknown chain '".$tables{$current_table}{chain}."'";
  }
}
sub make_switch
{
  my (@command)=@_;
  my $num=shift @command;
  if (defined $num)
  {
    $num=~s/^\s*on\s*$/1/;
    $num=~s/^\s*off\s*$/-1/;
  }
  else
  { $num=1; }
  return $num;
}
sub make_command_lcomment
{
  $output_line_comments+=make_switch(@_);
}
sub make_command_onoff
{
  $output_active+=make_switch(@_);
}
sub make_command_namecomment
{
  $output_namecomment+=make_switch(@_);
}
sub make_command_emptylines
{
  $output_empty_lines+=make_switch(@_);
}
sub make_command_variable
{
  my ($var, @command)=@_;
# variables  
  my $v=join(' ', @command);

  1 while $v=~s/\$([\w\-]+)/\${$1}/;


  $variables{$var}=$v;
# outmsg __LINE__,"DEFINING [$var]=$variables{$var}";
}
sub make_command_cmp
{
  my (@command)=@_;
  my $this_command=join(' ', @command);
# outmsg __LINE__, $last_command;
# outmsg __LINE__, join(' ', @command);
  if (!$cmp_disabled && "$last_command" ne "$this_command")
  {
    outerr __LINE__, "-- cmp FAIL: --L(".length($last_command).'/'.length($this_command).")", "\n#       $last_command", "\n#       $this_command";
  }
  undef $last_command;
  undef $cmp_disabled;
}
sub make_command_target_ctl
{
  my (@command)=@_;
  my $subcmd=shift @command;
  if ($subcmd eq 'off')
  {
#   outerr __LINE__, 'TARGET OFF: '.join(' ', @command);
    $targets_disabled{$_}=1 for (@command);
  }
}
sub make_command_each
{
  my ($level, @command)=@_;
  my $subcmd=shift @command;
  for my $mac (split(/\s*,\s*/, $subcmd))
  {
    my (@c)=@command;
    s/\%/$mac/g for (@c);
#   outerr __LINE__, "$mac --- ".join(',',@c);
    make_command_array($level, \@c);
  }
}
sub make_command_interface
{
  my (@command)=@_;
  my $v=join(' ', @command);
  if (exists($variables{'in_out'}))
  { $tables{$current_table}{$variables{'in_out'}}=$v; }
  else
  { outerr __LINE__, "to use 'interface' variable 'in_out' should be set : ",join(',',sort keys %variables); }
}
sub make_command_array
{
  my ($level, $command)=@_;
  my $main;
  $main=shift @$command;
  if ($main eq 'table')
  {
    make_substitution $command;
    make_command_table @$command;
  }
  elsif ($main eq 'policy')
  {
    make_substitution $command;
    make_command_policy @$command;
  }
  elsif ($main eq 'chain')
  {
    make_substitution $command;
    make_command_chain @$command;
  }
  elsif ($main eq 'rule')
  {
    @ftest=grep /\+virtualbox,\+vboxnet/, @$command;
    make_substitution $command;
    make_command_rule @$command;
  }
  elsif ($main eq 'cmp')
  {
    make_substitution $command;
    make_command_cmp @$command;
  }
  elsif ($main eq 'target-ctl')
  {
    make_substitution $command;
    make_command_target_ctl @$command;
  }
  elsif ($main eq 'each')
  {
    make_substitution $command;
    make_command_each $level, @$command;
  }
  elsif ($main eq 'interface')
  {
    make_substitution $command;
    make_command_interface @$command;
  }
  elsif ($main eq 'off' || $main eq 'on') { make_command_onoff $main, @$command; }
  elsif ($main eq 'l-comment-off') { make_command_lcomment 'off', @$command; }
  elsif ($main eq 'l-comment-on')  { make_command_lcomment 'on', @$command; }
  elsif ($main eq 'l-comment') { make_command_lcomment @$command; }
  elsif ($main eq 'name-comment-off') { make_command_namecomment 'off', @$command; }
  elsif ($main eq 'name-comment-on')  { make_command_namecomment 'on', @$command; }
  elsif ($main eq 'name-comment') { make_command_namecomment @$command; }
  elsif ($main eq 'empty-lines') { make_command_emptylines @$command; }
  elsif ($main =~/^([\w-]+)=(.*$)/)
  { 
    make_command_variable $1, ($2,@$command);
  }
  elsif ($main eq 'include')
  {
    build_names $level + 1, @$command;
  }
  elsif ($main eq 'wd' )
  {
    $workdir=shift @$command;
#   outmsg __LINE__, "WORKDIR [$workdir]";
  }
  elsif ($main eq 'target' 
  	|| $main eq 'proto'
	|| $main eq 'output'
	|| $main eq 'input'
	|| $main eq 'src'
	|| $main eq 'dst'
	|| $main eq 'mac-source'
	|| $main eq 'mac-dst?'
	|| $main eq 'spt'
	|| $main eq 'not-spt'
	|| $main eq 'spts'
	|| $main eq 'dpt'
	|| $main eq 'not-dpt'
	|| $main eq 'dpts'
	|| $main eq 'ctstate'
	|| $main eq 'icmp-type'
	|| $main eq 'uid-owner'
	|| $main eq 'gid-owner'
	|| $main eq 'comment'
	)
  {
    make_substitution $command;
#   $tables{$current_table}{$main}=$command[0];
    my $v=join(' ', @$command);
    $tables{$current_table}{$main}=$v;
  }
  else
  {
    outerr  __LINE__, "unknown command '$main(".join(' ', @$command).")'";
  }
}
sub make_shortcuts
{
  my ($command)=@_;
  my $name=shift @$command;
  if ($name eq 'allow')
  {
    my $dst=shift @$command;
    my $dpt=shift @$command;
# allow media.brg.ua 8014 radio 8014
# rule dst(media.brg.ua) dpt(8014) comment(radio 8014)
    @$command=('rule', 'dst('.$dst.')', 'dpt('.$dpt.')', 'comment('.join(' ', @$command).')');
    
#   die("$name -- ".join(';', @$command)); 
  }
  else
  {
    unshift @$command, $name;
  }
}
sub make_command
{
  my ($level, $command)=@_;
  my @command;
  @command=split /\s+/, $command;
  make_substitutionz \@command;
  make_shortcuts \@command;
  make_command_array $level, \@command;
}

sub make_commands
{
  my $level=shift @_;
  for (@_)
  {
    if (/^\s*[#\-]/)
    {
      outlog __LINE__,"\t\t\tliteral '$_'";
      output_literal "$_" if  $output_line_comments >0;
    }
    elsif (/^\s*$/)
    {
      output_literal ''   if  $output_empty_lines >0;
    }
    elsif (/^\s*(.*?)\s*$/)
    {
      make_command $level, $1;
    }
    else
    {
      output_literal "##??? [$_]";
    }
  }
}
sub make_opened_file
{
  my ($level, $conf)=@_;
  my $nl=0;
  my @command_lines;
  while(<$conf>)
  {
    chomp;
    if (/^\s*#/ || /^\s*$/)
    {
      push @command_lines, $_;
    }
    else
    {
      push @command_lines, split /\s*;\s*/ if !(/^\s*;/ || /^\s*$/);
#     push @command_lines, split /\s*;\s*/ if !(/^\s*;/);
    }
    $nl++;
  }
  make_commands $level, @command_lines;
}

sub make_file
{
  my ($level, $conffile)=@_;
  local *conf;
  outlog __LINE__,"opening $conffile\n";
# output_literal "# --                      file: $conffile";
  if (open conf, "<$conffile")
  {
    outlog __LINE__,"opened $conffile\n";
    make_opened_file $level, \*conf;
    close conf;
    outlog __LINE__,"closed $conffile\n";
  }
  else
  {
    outerr __LINE__, "can't open $conffile";
  }
}

sub build_iptables
{
  my ($level, $fname)=@_;
  $incdir="$confdir/main" if (!$incdir);
  my $conffile=$incdir;
# outmsg __LINE__, "DIR $incdir";
# outmsg __LINE__, "WORKDIR $incdir";
# outmsg __LINE__, "NAME $fname";
  unless (exists($includes_disabled{$fname}))
  {
    $conffile.="/$workdir" if $workdir;
    $conffile.="/$fname.ipt";
    $current_build_file=$conffile;
    $workdir='';
  # outmsg __LINE__, "FILE $conffile";
    if ( -f "$conffile" )
    {
      if ($conffile=~/^(.*?)\/+([^\/]+)\.ipt$/)
      { 
        $incdir=$1;
	$thisname=$2;
      }
      $upname='';
      if ($incdir=~/^(.*?)\/+([^\/]+)\/+([^\/]+)$/)
      {  $upname=$2; $incname=$3;  }
      elsif ($incdir=~/^(.*?)\/+([^\/]+)$/)
      {  $incname=$2;  }
      else
      { $incname=$incdir; }
  #   outmsg __LINE__, "$incdir -- $workdir -- $incname -- $thisname";
  ##  outmsg __LINE__, "$incdir / $workdir @ $conffile";
  ##  outmsg __LINE__, "$conffile exists";
      outlog __LINE__, "$conffile exists";
      make_file $level, $conffile;
    }
    else
    {
      outerr __LINE__, "$conffile not exists ($fname)";
    }
  }
  else
  {
    outmsg __LINE__, "DISABLED include $incdir/$fname";
  }
}

sub make_confdir
{
  if ($ENV{MSH_CONF_DIR} && -d $ENV{MSH_CONF_DIR})
  {
    $confdir="$ENV{MSH_CONF_DIR}/iptables-build";
    if (-d  $confdir)
    {
      outlog __LINE__,"$confdir exists";
    }
    else
    {
      outlog __LINE__,"$confdir not exists, creating";
      mkdir $confdir;
    }
  }
  else
  {
    outerr __LINE__, "MSH_CONF_DIR not set or directory '$ENV{MSH_CONF_DIR}' not exists";
  }
  return $confdir;
}
sub save_context
{
  my $chain;
  my $saved;
  $chain=$tables{$current_table}{current_chain};
  $saved->{current_chain}=$chain;
  $saved->{workdir}=$workdir;
  $saved->{incdir}=$incdir;
  $saved->{upname}=$upname;
  $saved->{incname}=$incname;
  $saved->{current_build_file}=$current_build_file;
#     outmsg __LINE__, "PUSH chain $chain";
  for my $prop (@basic_propset)
  {      $saved->{$prop}=$tables{$current_table}{$prop};     }
  push @{$tables{$current_table}{saved}}, $saved;
}
sub restore_context
{
  my $chain;
  my $saved;
  $saved=pop  @{$tables{$current_table}{saved}};
  for my $prop (@basic_propset)
  {     $tables{$current_table}{$prop}=$saved->{$prop};     }
  $chain=$saved->{current_chain};
  $workdir=$saved->{workdir};
  $incdir=$saved->{incdir};
  $upname=$saved->{upname};
  $incname=$saved->{incname};
  $current_build_file=$saved->{current_build_file};
  if ($chain)
  {
    make_command_chain $chain;
#	outmsg __LINE__, "POP chain $chain";
  }
  else
  {
#     outerr __LINE__, "empty chain name";
  }      
}
sub build_names
{
  my ($level, @names)=@_;
  if ( $confdir )
  {
    for my $name (@names)
    {
      save_context;
      {
	if ( $output_namecomment >0 ) { output_literal "# ++++++++++++++++++++++++++++++++++++++ name: $name"; }
	printf STDERR "> [%".($level*3)."s] ------\r", ${name};
	build_iptables $level, $name;
	printf STDERR "< [%".($level*3)."s] ------\r", ${name};
	if ( $output_namecomment >0 ) { output_literal "# -------------------------------------- name: $name"; }
      }
      restore_context;
    } 
  }
}
sub main
{
  my (@args)=@_;
  local *save;
  local *tocat;
  make_confdir;
  my $save_file="$confdir/iptables.built";
  unlink "$save_file";
  
  {
    my $if0   = IO::Interface::Simple->new('enp2s0');
    $variables{ipinet}=$if0->address;
  }
  print STDERR "$save_file\n";
  if ( open save, '>', $save_file )
  {
    for (@args)
    {
      if (/^\d+$/ && $_ > 0)
      { $output_active=$_; }
      else
      { $only_chain=$_; }
    }
    {
      if (-r "$confdir/main/opts/main.opts")
      {
        local *loadopts;
	if ( open loadopts, '<', "$confdir/main/opts/main.opts" )
	{
	  while(<loadopts>)
	  {
	    if (/^\s*([\w\-\/]+)\s*:\s*(\w*)\s*$/)
	    {
	      my $id=$1;
	      my $opt=$2;
	      if ($opt eq 'off')
	      {
	        $includes_disabled{$id}=1;
		outmsg __LINE__, "DISABLING include '$id'";
	      }
	      elsif ($opt eq 'on')
	      {
	        delete $includes_disabled{$id};
	      }
	    }
	  }
	  close loadopts;
	}
      }
    }
    {
      if (-r "$confdir/iptables.ip")
      {
        local *loadip;
	if ( open loadip, '<', "$confdir/iptables.ip" )
	{
	  while(<loadip>)
	  {
	    my @a;
	    my $name;
	    my @iplist;
	    if (/^(.*):(.*)$/)
	    {
	      my $iplist;
	      $name=$1;
	      $iplist=$2;
	      @iplist=split /\s*,\s*/, $iplist;
	      for my $ip (@iplist)
	      {
	        $resolved{$name}->{$ip}=1;
	      }
	    }
	  }
	  close loadip;
	}
      }
    }
    {
      local *saveip;
      if ( open saveip, '>', "$confdir/iptables0.ip" )
      {
	for my $name (sort keys %resolved)
	{
	  print saveip $name,':', join(',', keys %{$resolved{$name}}),"\n";
	}
	close saveip;
      }
    }
    build_names 0, 'main';
    {
      local *saveip;
      if ( open saveip, '>', "$confdir/iptables.ip" )
      {
	for my $name (sort keys %resolved)
	{
	  print saveip $name,':', join(',',keys %{$resolved{$name}}),"\n";
	}
	close saveip;
      }
    }
    output_literal '';
    output_literal '';
    output_literal '# vi: ft=iptables';
    close save;
  }
# if ( open tocat, '<', $save_file )
  if ( open tocat, "cat -n $save_file |" )
  {
    print while(<tocat>);
    close tocat;
  }
  {
    print STDERR "\n\n#-------------------------\n";
    if ($#messages >= 0)
    {
      print STDERR "\n\n@@ >>>>>>>>> ".($#messages+1)." MESSAGES <<<<<<<<<<<<\n\n";
      for my $msg (@messages)
      { printf STDERR "@@ --- (%3d) MSG : %03d: %s\n", @$msg; }
#     { printf STDERR "@@ --- (%3d) MSG : %03d: %s\n\n@@ >> AT file %-s\n\n", @$msg; }
    }
    print STDERR "\n\n#-------------------------\n";
    if ($#errors >= 0)
    {
      print STDERR "\n\n@@ >>>>>>>>> ".($#errors+1)." ERRORS DETECTED <<<<<<<<<<<<\n\n";
      for my $err (@errors)
      { printf STDERR "@@ --- (%3d) ERROR : %03d: %s\n\n@@ >> AT file %-s\n\n", @$err; }
    }
    elsif (system('diff iptables.built iptables.good >built.diff'))
    { print STDERR "\n\n@@ >>>>>>>>> DIFFERENCES from iptables.good DETECTED <<<<<<<<<<<<\n\n"; }
    
    printf STDERR "\n\n@@ >>>>>>>> CHECK %s <<<<<<<<<<<<\n", system("/sbin/iptables-restore -t $save_file") == 0?'OK':'FAIL';
    print STDERR "#-------------------------\n";
  }
}
main @ARGV;
