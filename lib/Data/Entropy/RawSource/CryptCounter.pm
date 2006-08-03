=head1 NAME

Data::Entropy::RawSource::CryptCounter - counter mode of block cipher
as I/O handle

=head1 SYNOPSIS

	use Data::Entropy::RawSource::CryptCounter;

	my $rawsrc = Data::Entropy::RawSource::CryptCounter
			->new(Crypt::Rijndael->new($key));

	$c = $rawsrc->getc;
	# and the rest of the I/O handle interface

=head1 DESCRIPTION

This class provides an I/O handle connected to a virtual file which
contains the output of a block cipher in counter mode.  This makes a
good source of pseudorandom bits.  The handle implements a substantial
subset of the interfaces described in L<IO::Handle> and L<IO::Seekable>.

For use as a general entropy source, it is recommended to wrap an object
of this class using C<Data::Entropy::Source>, which provides methods to
extract entropy in more convenient forms than mere octets.

The amount of entropy the virtual file actually contains is only the
amount that is in the key, which is at most the length of the key.
It superficially appears to be much more than this, if (and to the
extent that) the block cipher is secure.  This technique is not
suitable for all problems, and requires a careful choice of block
cipher and keying method.  Applications requiring true entropy
should generate it (see L<Data::Entropy::RawSource::Local>) or
download it (see L<Data::Entropy::RawSource::RandomnumbersInfo> and
L<Data::Entropy::RawSource::RandomOrg>).

=cut

package Data::Entropy::RawSource::CryptCounter;

use warnings;
use strict;

use Fcntl 1.04 qw(SEEK_SET SEEK_CUR SEEK_END);
use Params::Classify 0.000 qw(is_number is_ref is_string);

our $VERSION = "0.001";

use fields qw(cipher blksize counter subpos buffer);

=head1 CONSTRUCTOR

=over

=item Data::Entropy::RawSource::CryptCounter->new(KEYED_CIPHER)

KEYED_CIPHER must be a cipher object supporting the standard C<blocksize>
and C<encrypt> methods.  For example, an instance of C<Crypt::Rijndael>
(with the default C<MODE_ECB>) would be appropriate.  A handle object
is created and returned which refers to a virtual file containing the
output of the cipher's counter mode.

=cut

sub new($$) {
	my($class, $cipher) = @_;
	my __PACKAGE__ $self = fields::new($class);
	$self->{cipher} = $cipher;
	$self->{blksize} = $cipher->blocksize;
	$self->{counter} = "\0" x $self->{blksize};
	$self->{subpos} = 0;
	return $self;
}

=back

=head1 METHODS

A subset of the interfaces described in L<IO::Handle> and L<IO::Seekable>
are provided.  The methods implemented are: C<clearerr>, C<close>, C<eof>,
C<error>, C<getc>, C<getpos>, C<opened>, C<read>, C<seek>, C<setpos>,
C<sysread>, C<sysseek>, C<tell>, C<ungetc>.

C<close> does nothing.

The buffered (C<read> et al) and unbuffered (C<sysread> et al) sets
of methods are interchangeable, because no such distinction is made by
this class.

C<tell>, C<seek>, and C<sysseek> only work within the first 4 GiB of the
virtual file.  The file is actually much larger than that: for Rijndael
(AES), or any other cipher with a 128-bit block, the file is 2^52 YiB
(2^132 B).  C<getpos> and C<setpos> work throughout the file.

Methods to write to the file are unimplemented because the virtual file
is fundamentally read-only.

=cut

sub ensure_buffer($) {
	my __PACKAGE__ $self = shift;
	$self->{buffer} = $self->{cipher}->encrypt($self->{counter})
		unless exists $self->{buffer};
}

sub clear_buffer($) {
	my __PACKAGE__ $self = shift;
	delete $self->{buffer};
}

sub increment_counter($) {
	my __PACKAGE__ $self = shift;
	for(my $i = 0; $i != $self->{blksize}; $i++) {
		my $c = ord(substr($self->{counter}, $i, 1));
		unless($c == 255) {
			substr $self->{counter}, $i, 1, chr($c + 1);
			return;
		}
		substr $self->{counter}, $i, 1, "\0";
	}
	$self->{counter} = undef;
}

sub decrement_counter($) {
	my __PACKAGE__ $self = shift;
	for(my $i = 0; ; $i++) {
		my $c = ord(substr($self->{counter}, $i, 1));
		unless($c == 0) {
			substr $self->{counter}, $i, 1, chr($c - 1);
			return;
		}
		substr $self->{counter}, $i, 1, "\xff";
	}
}

sub close($) { 1 }

sub opened($) { 1 }

sub error($) { 0 }

sub clearerr($) { 0 }

sub getc($) {
	my __PACKAGE__ $self = shift;
	return undef unless defined $self->{counter};
	$self->ensure_buffer;
	my $ret = substr($self->{buffer}, $self->{subpos}, 1);
	if(++$self->{subpos} == $self->{blksize}) {
		$self->increment_counter;
		$self->{subpos} = 0;
		$self->clear_buffer;
	}
	return $ret;
}

sub ungetc($$) {
	my __PACKAGE__ $self = shift;
	unless($self->{subpos} == 0) {
		$self->{subpos}--;
		return;
	}
	return if $self->{counter} =~ /\A\0*\z/;
	$self->decrement_counter;
	$self->{subpos} = $self->{blksize} - 1;
	$self->clear_buffer;
}

sub read($$$;$) {
	my __PACKAGE__ $self = shift;
	my(undef, $length, $offset) = @_;
	return undef if $length < 0;
	$_[0] = "" unless defined $_[0];
	if(!defined($offset)) {
		$offset = 0;
		$_[0] = "";
	} elsif($offset < 0) {
		return undef if $offset < -length($_[0]);
		substr $_[0], $offset, -$offset, "";
		$offset = length($_[0]);
	} elsif($offset > length($_[0])) {
		$_[0] .= "\0" x ($offset - length($_[0]));
	} else {
		substr $_[0], $offset, length($_[0]) - $offset, "";
	}
	my $original_offset = $offset;
	while($length != 0 && defined($self->{counter})) {
		$self->ensure_buffer;
		my $avail = $self->{blksize} - $self->{subpos};
		if($length < $avail) {
			$_[0] .= substr($self->{buffer}, $self->{subpos},
					$length);
			$offset += $length;
			$self->{subpos} += $length;
			last;
		}
		$_[0] .= substr($self->{buffer}, $self->{subpos}, $avail);
		$offset += $avail;
		$length -= $avail;
		$self->increment_counter;
		$self->{subpos} = 0;
		$self->clear_buffer;
	}
	return $offset - $original_offset;
}

*sysread = \&read;

sub tell($) {
	use integer;
	my __PACKAGE__ $self = shift;
	my $ctr = $self->{counter};
	my $nblocks;
	if(defined $ctr) {
		return -1 if $ctr =~ /\A.{4,}[^\0]/s;
		$ctr .= "\0\0\0\0" if $self->{blksize} < 4;
		$nblocks = unpack("V", $ctr);
	} else {
		return -1 if $self->{blksize} >= 4;
		$nblocks = 1 << ($self->{blksize} << 3);
	}
	my $pos = $nblocks * $self->{blksize} + $self->{subpos};
	return -1 unless ($pos-$self->{subpos}) / $self->{blksize} == $nblocks;
	return $pos;
}

sub sysseek($$$) {
	my __PACKAGE__ $self = shift;
	my($offset, $whence) = @_;
	if($whence == SEEK_SET) {
		use integer;
		return undef if $offset < 0;
		my $ctr = $offset / $self->{blksize};
		my $subpos = $offset % $self->{blksize};
		$ctr = pack("V", $ctr);
		if($self->{blksize} < 4) {
			return undef unless
			my $chopped = substr($ctr, $self->{blksize},
					     4-$self->{blksize}, "");
			if($chopped =~ /\A\x{01}\0*\z/ && $subpos == 0) {
				$self->{counter} = undef;
				$self->{subpos} = 0;
				$self->clear_buffer;
				return $offset;
			} elsif($chopped !~ /\A\0+\z/) {
				return undef;
			}
		} else {
			$ctr .= "\0" x ($self->{blksize} - 4);
		}
		$self->{counter} = $ctr;
		$self->{subpos} = $subpos;
		$self->clear_buffer;
		return $offset || "0 but true";
	} elsif($whence == SEEK_CUR) {
		my $pos = $self->tell;
		return undef if $pos == -1;
		return $self->sysseek($pos + $offset, SEEK_SET);
	} elsif($whence == SEEK_END) {
		use integer;
		return undef if $offset > 0;
		return undef if $self->{blksize} >= 4;
		my $nblocks = 1 << ($self->{blksize} << 3);
		my $pos = $nblocks * $self->{blksize};
		return undef unless $pos/$self->{blksize} == $nblocks;
		return $self->sysseek($pos + $offset, SEEK_SET);
	} else {
		return undef;
	}
}

sub seek($$$) { shift->sysseek(@_) ? 1 : 0 }

sub getpos($) {
	my __PACKAGE__ $self = shift;
	return [ $self->{counter}, $self->{subpos} ];
}

sub setpos($$) {
	my __PACKAGE__ $self = shift;
	my($pos) = @_;
	return undef unless is_ref($pos, "ARRAY") && @$pos == 2;
	my($ctr, $subpos) = @$pos;
	unless(!defined($ctr) && $subpos == 0) {
		return undef unless is_string($ctr) &&
			length($ctr) == $self->{blksize} &&
			is_number($subpos) &&
			$subpos >= 0 && $subpos < $self->{blksize};
	}
	$self->{counter} = $ctr;
	$self->{subpos} = $subpos;
	$self->clear_buffer;
	return "0 but true";
}

sub eof($) {
	my __PACKAGE__ $self = shift;
	return !defined($self->{counter});
}

=head1 SEE ALSO

L<Crypt::Rijndael>,
L<Data::Entropy::RawSource::Local>,
L<Data::Entropy::RawSource::RandomOrg>,
L<Data::Entropy::RawSource::RandomnumbersInfo>,
L<Data::Entropy::Source>

=head1 AUTHOR

Andrew Main (Zefram) <zefram@fysh.org>

=head1 COPYRIGHT

Copyright (C) 2006 Andrew Main (Zefram) <zefram@fysh.org>

This module is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
