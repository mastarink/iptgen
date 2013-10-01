#!/usr/bin/perl
# ./bin/iptables-build.pl 1000  | grep -- '\(^\s*[[:digit:]]\+\s*-A\s*F\(lan\|inet\)\|ERROR\)'
# ./bin/iptables-build.pl 1000  | grep -- '\(^\s*[[:digit:]]\+\s*-A\s*\(tcp\|udp\|icmp\|drop\|accept\|\)\(F\|2\)\(lan\|inet\|local\|lan_vbox\)\|ERROR\)'
# ./bin/iptables-build.pl 1000  | grep -- '\(^\s*[[:digit:]]\+\s*-A\s*\(\(tcp\|udp\|icmp\|drop\|acpt\|\)\(F\|2\)\(lan\|inet\|local\|lan_vbox\)\|INPUT\|OUTPUT\|FORWARD\|POSTROUTING\)\|ERROR\)'
# ./bin/iptables-build.pl 1000  | grep --color=yes -- '\(^\s*[[:digit:]]\+\s*-A\s*\(\(tcp\|udp\|icmp\|drop\|acpt\|\(icmp\|tcp\|udp\)_acpt\|\)\(F\|2\)\(lan\|inet\|local\|lan_vbox\)\|INPUT\|OUTPUT\|FORWARD\|POSTROUTING\)\|ERROR\)'


use strict;
use strict 'vars';
use strict 'refs';
use strict 'subs';
use v5.6.0;

use Net::DNS::Resolver;
use Net::IP;

my $errorcnt=0;

my $incdir;
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
my %resolved;
my ($last_literal, $last_command);
my @basic_propset=qw/chain target output input proto dst src macdst macsrc dpt spt ctstate helper comment/;
sub build_names;

sub outerr
{
  my ($code, @msg)=@_;
  printf save "### $errorcnt ERROR : %03d: %s\n", $code, join(' ', @msg);
  $errorcnt++;
}
sub outmsg
{
  my ($code, @msg)=@_;
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
    print save "$last_literal\n" if (($output_active > 0) && (!$only_chain || $tables{$current_table}{current_chain} eq $only_chain));
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
  my $res = Net::DNS::Resolver->new;
  my $query = $res->search($name);

  if ($query)
  {
    foreach my $rr ($query->answer)
    {
      next unless $rr->type eq "A";
      push @result, $rr->address;
      $resolved{$name}=$rr->address;
      print STDERR "$name : ".$rr->address."\n";
    }
  }
  return @result;
}
sub make_address_array
{
  my (@addresses)=map { split /\s*,\s*/ } @_;
  my @ips;
# outmsg __LINE__, "A ".join(';',@addresses);
  for my $address (@addresses)
  {
    if ($confdir && ($address=~/^\s*\+(.*?)\s*$/ || $address=~/^\s*include\b\s*(.*?)\s*$/))
    {
      local *ipfile;
      my @names=split(/\s+/, $1);
      for my $name (@names)
      {
        my $ipfname="$confdir/main/ip/$name.ip";
#       outmsg __LINE__, "B +$name";
	if (-f $ipfname && open ipfile, $ipfname)
	{
	  my @iplines=<ipfile>;
	  chomp @iplines;      
	  close ipfile;
#	  outmsg __LINE__,">>IP>> ( $ipfname ) -- ".join(';',@iplines);
	  my @ipst;
	  @ipst=map { make_address_array($_) } @iplines;
#	  outmsg __LINE__,"!!IP!! ( $ipfname ) -- ".join(';',@iplines);
	  push(@ips, @ipst);
#	  outmsg __LINE__,"<<IP<< ( $ipfname ) -- ".join(';',@iplines);
	}
	else
	{
	  outerr __LINE__, "no file $ipfname";
	}
      }
    }
    elsif ($address!~/^\d+\.\d+\.\d+\.\d+(\/\d+|)$/)
    { 
      my @ipsr=resolve($address);
#     outmsg __LINE__, "C ".join(',',@ipsr);
      if ($#ipsr<0)
      {
	outerr __LINE__, "wrong address '$address'";
      }
      else
      {
        push @ips, @ipsr;
      }
    }
    else
    {
      push @ips, ($address);
#     outmsg __LINE__, "D ".join(',',@ips);
    }
  }
# outmsg __LINE__, "Z ".join(';',@ips);
  return @ips;
}
sub ip_compare
{
  my ($a,$b)=@_;
  my $ip1 = new Net::IP ($a);
  my $ip2 = new Net::IP ($b);
# print '########## 1:',$ip1->ip(),'              2:',$ip2->ip()," CMP:",($ip1->intip() <=> $ip2->intip()),"\n";
  return $ip1->intip() <=> $ip2->intip();
}
sub make_address
{
  return join(',', sort( {ip_compare($a, $b)} make_address_array( @_)));
}
sub make_comment
{
  my (@comments)=map { split /\s+/ } @_;
  my $c;
  if ($#comments>1) { $c='"'.join(' ',@comments).'"'; }
  else { $c=join(' ',@comments) ;}
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
		 comment=>{name=>'-comment', order=>99000, module=>{comment=>'comment'}},
		 ctstate=>{name=>'-ctstate', order=>1000, module=>{ctstate=>'conntrack'}},
		 dpt=>{name=>'-dport', order=>104},
		 dpts=>{name=>'-dports', order=>104, module=>{dpts=>'multiport'}},
		 dst=>{name=>'d', order=>103},
		 helper=>{name=>'-helper', order=>20, module=>{helper=>'helper'}},
		 input=> {name=>'i', order=>12},
		 lit=>{name=>'', order=>8000},
		 macdst=>{name=>'-mac-dst?', order=>103, module=>{macdst=>'mac'}},
		 macsrc=>{name=>'-mac-source', order=>101, module=>{macsrc=>'mac'}},
		 output=>{name=>'o', order=>11},
		 proto=>{name=>'p', order=>15, module=>{tcp=>'tcp',udp=>'udp',icmp=>'icmp'}},
		 spt=>{name=>'-sport', order=>102},
		 spts=>{name=>'-sports', order=>102, module=>{spts=>'multiport'}},
		 src=>{name=>'s', order=>101},
		 tail=>{name=>'', order=>10000},
		 target=>{name=>'j', order=>10000},
	      );
    my %process=( src=>'make_address', dst=>'make_address', comment=>'make_comment' );
    my $cmd;
    while( $cmd = shift(@command) )
    {
      my $name;
      my $opt;
      while(@command && $cmd =~/^\s*(\S+)\s*\([^\)]*$/)
      {
        $cmd="$cmd ".shift(@command);
      }
#     outmsg __LINE__, $cmd;
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
	$opts{$name}="$opts{$name} $opt";
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
    
    for my $name (sort({ $names{$a}->{order} <=> $names{$b}->{order} } keys(%opts)))
    {
      if (exists $process{$name} )
      {
	$opts{$name}=eval "$process{$name}('$opts{$name}')"
      }
      {
        my $line;
        if (           exists(    $names{$name}->{module}->{$opts{$name}})      )
        {
	  my $val=$names{$name}->{module}->{$opts{$name}};
          $line="-m $val ";
        }
	elsif (        exists(    $names{$name}->{module}->{$name})   )
	{
	  my $val=$names{$name}->{module}->{$name};
          $line="-m $val ";
	}
        if ($name eq 'tail' || $name eq 'lit')
	{
	  push @line, $opts{$name};
	}
	else
	{
	  $line.='-'.$names{$name}->{name}.' '.$opts{$name};
	  push @line, $line;
	}
      }
    }
    output_command '', @line;
  }
  else
  {
    outerr( __LINE__, "unknown chain '".$tables{$current_table}{chain}."'");
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
  if ("$last_command" ne "$this_command")
  {
    outerr __LINE__, '-- cmp FAIL: --L('.length($last_command).'/'.length($this_command).')';
    outerr __LINE__, "'$last_command'";
    outerr __LINE__, "'$this_command'";
  }
}

sub make_command
{
  my ($command)=@_;
  my @command;
  my $main;
  @command=split /\s+/, $command;
  $main=shift @command;
  if ($main eq 'table')
  {
    make_substitution \@command;
    make_command_table @command;
  }
  elsif ($main eq 'policy')
  {
    make_substitution \@command;
    make_command_policy @command;
  }
  elsif ($main eq 'chain')
  {
    make_substitution \@command;
    make_command_chain @command;
  }
  elsif ($main eq 'rule')
  {
    make_substitution \@command;
    make_command_rule @command;
  }
  elsif ($main eq 'cmp')
  {
    make_substitution \@command;
    make_command_cmp @command;
  }
  elsif ($main eq 'off' || $main eq 'on') { make_command_onoff $main, @command; }
  elsif ($main eq 'l-comment-off') { make_command_lcomment 'off', @command; }
  elsif ($main eq 'l-comment-on')  { make_command_lcomment 'on', @command; }
  elsif ($main eq 'l-comment') { make_command_lcomment @command; }
  elsif ($main eq 'name-comment-off') { make_command_namecomment 'off', @command; }
  elsif ($main eq 'name-comment-on')  { make_command_namecomment 'on', @command; }
  elsif ($main eq 'name-comment') { make_command_namecomment @command; }
  elsif ($main eq 'empty-lines') { make_command_emptylines @command; }
  elsif ($main =~/^([\w-]+)=(.*$)/)
  { make_command_variable $1, ($2,@command); }
  elsif ($main eq 'include')
  {
    build_names @command;
  }
  elsif ($main eq 'wd' )
  {
    $workdir=shift @command;
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
	|| $main eq 'dpt'
	|| $main eq 'comment'
	)
  {
    make_substitution \@command;
#   $tables{$current_table}{$main}=$command[0];
    $tables{$current_table}{$main}=join(' ', @command);
  }
  else
  {
    outerr  __LINE__, "unknown command '$main(".join(' ', @command).")'";
  }
}

sub make_commands
{
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
      make_command $1;
    }
    else
    {
      output_literal "##??? [$_]";
    }
  }
}
sub make_opened_file
{
  my $nl=0;
  my ($conf)=@_;
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
  make_commands @command_lines;
}

sub make_file
{
  my ($conffile)=@_;
  local *conf;
  outlog __LINE__,"opening $conffile\n";
# output_literal "# --                      file: $conffile";
  if (open conf, "<$conffile")
  {
    outlog __LINE__,"opened $conffile\n";
    make_opened_file \*conf;
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
  my ($fname)=@_;
  $incdir="$confdir/main" if (!$incdir);
  my $conffile="$incdir/$workdir/$fname.ipt";
  $workdir='';
  if ( -f "$conffile" )
  {
    if ($conffile=~/^(.*)\/([^\/]+)$/)
    {
      $incdir=$1;
    }
##  outmsg __LINE__, "$incdir / $workdir @ $conffile";
##  outmsg __LINE__, "$conffile exists";
    outlog __LINE__, "$conffile exists";
    make_file $conffile;
  }
  else
  {
    outerr __LINE__, "$conffile not exists ($fname)";
  }
}

sub make_confdir
{
  if ($ENV{MAS_CONF_DIR} && -d $ENV{MAS_CONF_DIR})
  {
    $confdir="$ENV{MAS_CONF_DIR}/iptables-build";
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
    outerr __LINE__, "MAS_CONF_DIR not set or directory '$ENV{MAS_CONF_DIR}' not exists";
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
  my (@names)=@_;
  if ( $confdir )
  {
    for my $name (@names)
    {
      save_context;
      {
	if ( $output_namecomment >0 ) { output_literal "# ++++++++++++++++++++++++++++++++++++++ name: $name"; }
	build_iptables $name;
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
  unlink '/tmp/iptables.build.tmp';
  if ( open save, '>', '/tmp/iptables.build.tmp' )
  {
    for (@args)
    {
      if (/^\d+$/ && $_ > 0)
      { $output_active=$_; }
      else
      { $only_chain=$_; }
    }

    make_confdir;
    build_names 'main';
    output_literal '';
    output_literal '';
    output_literal '# vi: ft=iptables';
    close save;
  }
# if ( open tocat, '<', '/tmp/iptables.build.tmp' )
  if ( open tocat, 'cat -n /tmp/iptables.build.tmp |' )
  {
    print while(<tocat>);
    close tocat;
  }
  print "\n\n#-------------------------\n";
  printf "# check %s\n", system('/sbin/iptables-restore -t /tmp/iptables.build.tmp')==0?'OK':'FAIL';
  print "#-------------------------\n";
}

main @ARGV;
