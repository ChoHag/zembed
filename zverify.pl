#!/usr/bin/perl

use warnings;
use strict;
use File::Temp qw(tempdir);
use IPC::Open2 qw(open2);

use constant {
  # FTEXT unused
  FHCRC    => 0x02,
  FEXTRA   => 0x04,
  FNAME    => 0x08,
  FCOMMENT => 0x10,
  MAGIC    => 0x8b1f,
};

sub verify ($@);

binmode STDIN;
sub get ($) { if (sysread STDIN, my $buf, shift) { return $buf } else { return } }
sub getz {
  my @got;
  while (defined (my $byte = get 1)) { push @got, $byte; return @got unless ord $byte }
}

my $mangled_header = get 10;
my @head = unpack SCCLCC => $mangled_header;
die 'Not gzip' unless $head[0] == MAGIC;
my $flags = $head[2];              # Save mangled flags

my (@fextra, @fname, @fcomment, @fhcrc, $payload, @signature);
# Yes the order's weird.
if ($flags & FEXTRA) {
  push @fextra, get 2;
  push @fextra, get unpack S => $fextra[-1];
}
@fname = getz if $flags & FNAME;
if (not $flags & FCOMMENT) {
  die 'Not gzs-encoded';
} else {
  my $had_comment = unpack A => get 1;
  my $line = '';
  my $wait = '';
 LINE:
  while (defined (my $byte = get 1)) {
    $line .= $byte;
    last LINE unless ord $byte;
    if ($byte eq "\n") {
      push @signature, $line;
      my $was = $line; $line = '';
      if (@signature == 1) {
        $wait = ($was =~ /^-----BEGIN.*-----$/) ? $& : '.*';
        $wait =~ s/BEGIN/END/;
      } else {
        last LINE if $was =~ /^$wait$/;
      }
    }
  }
  if ($had_comment) {
    @fcomment = getz;
  } else {
    $head[2] &= (0xff & ~FCOMMENT);
    die 'Unexpected byte' if ord get 1; # trailing null
  }
}
@fhcrc = (get 2) if $flags & FHCRC;
while (defined (my $buf = get 4096)) { $payload .= $buf }

my $unmangled_header = pack SCCLCC => @head;
my $uxhead = join '', (@fextra, @fname, @fcomment, @fhcrc);
exit $?>>8 unless verify join('', @signature), $unmangled_header, $uxhead, $payload;
print $unmangled_header, $uxhead, $payload;

sub verify ($@) {
  my $signature = shift;
  my $dir = tempdir CLEANUP => 1;
  my @sigfn = ("$dir/message.sig");
  open my $sigfh, '>', @sigfn or die $!;
  binmode $sigfh;
  print $sigfh $signature;
  close $sigfh or die $!;
  my ($out, $in, @cli);
  # If @ARGV contains --, replace it with the signature file,
  # otherwise it is appended.
  push @cli, $_ eq '--' ? shift @sigfn : $_ for @ARGV;
  my $verifier = open2 $out, $in, @cli, @sigfn;
  print $in $_ for @_;
  close $in;
  waitpid $verifier, 0; # timeout?
  return !$?;
}
