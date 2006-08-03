=head1 NAME

Data::Entropy::RawSource::RandomOrg - download entropy from random.org

=head1 SYNOPSIS

	use Data::Entropy::RawSource::RandomOrg;

	my $rawsrc = Data::Entropy::RawSource::RandomOrg->new;

	$c = $rawsrc->getc;
	# and the rest of the I/O handle interface

=head1 DESCRIPTION

This class provides an I/O handle connected to a stream of random octets
being generated by an electromagnetic noise detector connected to the
random.org server.  This is a strong source of random bits, but is not
suitable for security applications because the bits are passed over the
Internet unencrypted.  The handle implements a substantial subset of
the interface described in L<IO::Handle>.

For use as a general entropy source, it is recommended to wrap an object
of this class using C<Data::Entropy::Source>, which provides methods to
extract entropy in more convenient forms than mere octets.

The bits generated at random.org are, theoretically and as far as anyone
can tell, totally unbiased and uncorrelated.  However, they are sent
over the Internet in the clear, and so are subject to interception and
alteration by an adversary.  This is therefore generally unsuitable for
security applications.  The capacity of the random bit server is also
limited.  This class will slow down requests if the server's entropy
pool is less than half full, and (as requested by the server operators)
pause entirely if the entropy pool is less than 20% full.

Applications requiring secret entropy should generate it locally
(see L<Data::Entropy::RawSource::Local>).  Applications requiring a
large amount of entropy should generate it locally or download it from
randomnumbers.info (see L<Data::Entropy::RawSource::RandomnumbersInfo>).
Applications requiring a large amount of apparently-random data,
but not true entropy, might prefer to fake it cryptographically (see
L<Data::Entropy::RawSource::CryptCounter>).

=cut

package Data::Entropy::RawSource::RandomOrg;

use warnings;
use strict;

use Errno 1.00 qw(EIO);
use LWP 5.53_94;
use LWP::UserAgent;

our $VERSION = "0.001";

use fields qw(ua buffer bufpos error);

=head1 CONSTRUCTOR

=over

=item Data::Entropy::RawSource::RandomOrg->new

Creates and returns a handle object referring to a stream of random
octets generated by random.org.

=cut

sub new($$) {
	my($class) = @_;
	my __PACKAGE__ $self = fields::new($class);
	$self->{ua} = LWP::UserAgent->new;
	$self->{buffer} = "";
	$self->{bufpos} = 0;
	$self->{error} = 0;
	return $self;
}

=back

=head1 METHODS

A subset of the interfaces described in L<IO::Handle> and L<IO::Seekable>
are provided.  The methods implemented are: C<clearerr>, C<close>,
C<eof>, C<error>, C<getc>, C<opened>, C<read>, C<sysread>, C<ungetc>.

C<close> does nothing.

The buffered (C<read> et al) and unbuffered (C<sysread> et al) sets
of methods are interchangeable, because no such distinction is made by
this class.

Methods to write to the file are unimplemented because the stream is
fundamentally read-only.  Methods to seek are unimplemented because the
stream is non-rewindable; C<ungetc> works, however.

=cut

sub checkbuf($) {
	my __PACKAGE__ $self = shift;
	my $response =
		$self->{ua}->get("http://www.random.org/cgi-bin/checkbuf");
	unless($response->code == 200) {
		$! = EIO;
		return undef;
	}
	my $content = $response->content;
	unless($content =~ /\A\s*(\d{1,3})\%\s*\z/) {
		$! = EIO;
		return undef;
	}
	return $1;
}

sub ensure_buffer($) {
	my __PACKAGE__ $self = shift;
	return 1 unless $self->{bufpos} == length($self->{buffer});
	while(1) {
		my $fillpct = $self->checkbuf;
		return 0 unless defined $fillpct;
		if($fillpct >= 20) {
			sleep((50 - $fillpct)*0.2) if $fillpct < 50;
			last;
		}
		sleep 10;
	}
	my $response = $self->{ua}->get(
		"http://www.random.org/cgi-bin/randbyte?nbytes=256&format=f");
	unless($response->code == 200) {
		$! = EIO;
		return 0;
	}
	$self->{buffer} = $response->content;
	if($self->{buffer} eq "") {
		$! = EIO;
		return 0;
	}
	$self->{bufpos} = 0;
	return 1;
}

sub close($) { 1 }

sub opened($) { 1 }

sub error($) {
	my __PACKAGE__ $self = shift;
	return $self->{error};
}

sub clearerr($) {
	my __PACKAGE__ $self = shift;
	$self->{error} = 0;
	return 0;
}

sub getc($) {
	my __PACKAGE__ $self = shift;
	unless($self->ensure_buffer) {
		$self->{error} = 1;
		return undef;
	}
	return substr($self->{buffer}, $self->{bufpos}++, 1);
}

sub ungetc($$) {
	my __PACKAGE__ $self = shift;
	my($cval) = @_;
	if($self->{bufpos} == 0) {
		$self->{buffer} = chr($cval).$self->{buffer};
	} else {
		$self->{bufpos}--;
	}
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
	while($length != 0) {
		unless($self->ensure_buffer) {
			$self->{error} = 1;
			last;
		}
		my $avail = length($self->{buffer}) - $self->{bufpos};
		if($length < $avail) {
			$_[0] .= substr($self->{buffer}, $self->{bufpos},
					$length);
			$offset += $length;
			$self->{bufpos} += $length;
			last;
		}
		$_[0] .= substr($self->{buffer}, $self->{bufpos}, $avail);
		$offset += $avail;
		$length -= $avail;
		$self->{bufpos} += $avail;
	}
	my $nread = $offset - $original_offset;
	return $nread == 0 ? undef : $nread;
}

*sysread = \&read;

sub eof($) { 0 }

=head1 SEE ALSO

L<Data::Entropy::RawSource::CryptCounter>,
L<Data::Entropy::RawSource::Local>,
L<Data::Entropy::RawSource::RandomnumbersInfo>,
L<Data::Entropy::Source>,
L<http://www.random.org>

=head1 AUTHOR

Andrew Main (Zefram) <zefram@fysh.org>

=head1 COPYRIGHT

Copyright (C) 2006 Andrew Main (Zefram) <zefram@fysh.org>

This module is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
