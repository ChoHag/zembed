#!/usr/bin/perl

use warnings;
use strict;
use IPC::Open2 qw(open2);

use constant {
  # FTEXT unused
  FHCRC    => 0x02,
  FEXTRA   => 0x04,
  FNAME    => 0x08,
  FCOMMENT => 0x10,
  MAGIC    => 0x8b1f,
};

sub sign (@);

binmode STDIN;
sub get ($) { if (sysread STDIN, my $buf, shift) { return $buf } else { return } }
sub getz {
  my @got;
  while (defined (my $byte = get 1)) { push @got, $byte; return @got unless ord $byte }
}

my $header = get 10;
my @head = unpack SCCLCC => $header;
die 'Not gzip' unless $head[0] == MAGIC;
my $flags = $head[2];              # Save original flags

my (@fextra, @fname, @fcomment, @fhcrc, $payload);
# Yes the order's weird.
if ($flags & FEXTRA) {
  push @fextra, get 2;
  push @fextra, get unpack S => $fextra[-1];
}
@fname = getz if $flags & FNAME;
@fcomment = getz if $flags & FCOMMENT;
@fhcrc = (get 2) if $flags & FHCRC;
while (defined (my $buf = get 4096)) { $payload .= $buf }

$head[2] |= FCOMMENT;
my $mangled_header = pack SCCLCC => @head;
my $uxhead = join '', (@fextra, @fname, @fcomment, @fhcrc);
my $signature = sign $header, $uxhead, $payload;
my @scomment = (0+!!@fcomment, $signature, @fcomment);
push @scomment, pack 'Z' unless @fcomment;
my $sxhead = join '', (@fextra, @fname, @scomment, @fhcrc);
print $mangled_header, $sxhead, $payload;

sub sign (@) {
  my ($out, $in);
  my $signer = open2 $out, $in, @ARGV;
  print $in $_ for @_;
  close $in;
  waitpid $signer, 0; # timeout?
  die "sign $?" if $?;
  join '', readline $out;
}
