#!/usr/bin/perl

use strict;
use strict 'vars';
use strict 'refs';
use strict 'subs';
use v5.6.0;

use  IO::Interface::Simple;
my @interfaces = IO::Interface::Simple->interfaces;

print "$_\n" for (@interfaces);

my $if0   = IO::Interface::Simple->new('enp2s0');
print $if0->address;
