=head1 NAME

Data::Entropy::Algorithms - basic entropy-using algorithms

=head1 SYNOPSIS

	use Data::Entropy::Algorithms
		qw(rand_bits rand_int rand_prob);

	$str = rand_bits(17);
	$i = rand_int(12345);
	$i = rand_int(Math::BigInt->new("1000000000000"));
	$j = rand_prob(1, 2, 3);
	$j = rand_prob([ 1, 2, 3 ]);

	use Data::Entropy::Algorithms qw(rand_fix rand rand_flt);

	$x = rand_fix(48);
	$x = rand(7);
	$x = rand_flt(0.0, 7.0);

	use Data::Entropy::Algorithms
		qw(pick pick_r choose choose_r shuffle shuffle_r);

	$item = pick($item0, $item1, $item2);
	$item = pick_r(\@items);
	@chosen = choose(3, $item0, $item1, $item2, $item3, $item4);
	$chosen = choose_r(3, \@items);
	@shuffled = shuffle($item0, $item1, $item2, $item3, $item4);
	$shuffled = shuffle_r(\@items);

=head1 DESCRIPTION

This module contains a collection of fundamental algorithms that
use entropy.  They all use the entropy source mechanism described in
L<Data::Entropy>.

=cut

package Data::Entropy::Algorithms;

use warnings;
use strict;

use Carp qw(croak);
use Data::Entropy qw(entropy_source);
use Data::Float 0.002 qw(
	have_subnormal min_normal_exp significand_bits
	float_is_finite float_parts float_sign mult_pow2 copysign
);
use Params::Classify 0.000 qw(is_ref);

our $VERSION = "0.001";

use base "Exporter";
our @EXPORT_OK = qw(
	rand_bits rand_int rand_prob
	rand_fix rand rand_flt
	pick_r pick choose_r choose shuffle_r shuffle
);

=head1 FUNCTIONS

All of these functions use entropy.  The entropy source is not an
explicit input in any case.  All functions use the current entropy source
maintained by the C<Data::Entropy> module.  To select an entropy source
use the C<with_entropy_source> function in that module, or alternatively
do nothing to use the default source.

=head2 Fundamental entropy extraction

=over

=item rand_bits(NBITS)

Returns NBITS bits of entropy, as a string of octets.  If NBITS is
not a multiple of eight then the last octet in the string has its most
significant bits set to zero.

=cut

sub rand_bits($) {
	my($nbits) = @_;
	croak "need a non-negative number of bits to dispense"
		unless $nbits >= 0;
	return entropy_source->get_bits($nbits);
}

=item rand_int(LIMIT)

LIMIT must be a positive integer.  Returns a uniformly-distributed random
integer in the range [0, LIMIT).  LIMIT may be either a native integer,
a C<Math::BigInt> object, or an integer-valued C<Math::BigRat> object;
the returned number is of the same type.

=cut

sub rand_int($) {
	my($limit) = @_;
	croak "need a positive upper limit for random variable"
		unless $limit > 0;
	return entropy_source->get_int($limit);
}

=item rand_prob(PROB ...)

=item rand_prob(PROBS)

Returns a random integer selected with non-uniform probability.  The
relative probabilities are supplied as a list of non-negative integers
(multiple PROB arguments) or a reference to an array of integers (the
PROBS argument).  The relative probabilities may be native integers,
C<Math::BigInt> objects, or integer-valued C<Math::BigRat> objects;
they must all be of the same type.  At least one probability value must
be positive.

The first relative probability value (the first PROB or the first element
of PROBS) is the relative probability of returning 0.  The absolute
probability of returning 0 is this value divided by the total of all
the relative probability values.  Similarly the second value controls
the probability of returning 1, and so on.

=cut

sub rand_prob(@) {
	my $probs = @_ == 1 && is_ref($_[0], "ARRAY") ? $_[0] : \@_;
	my $total = 0;
	for(my $i = @$probs; $i--; ) {
		my $prob = $probs->[$i];
		croak "probabilities must be non-negative" unless $prob >= 0;
		$total += $prob;
	}
	croak "can't have nothing possible" if $total == 0;
	for(my $i = @$probs; $i--; ) {
		my $prob = $probs->[$i];
		$total -= $prob;
		return $i if entropy_source->get_prob($total, $prob);
	}
}

=back

=head2 Numbers

=over

=item rand_fix(NBITS)

Returns a uniformly-distributed random NBITS-bit fixed-point fraction in
the range [0, 1).  That is, the result is a randomly-chosen multiple of
2^-NBITS, the multiplier being a random integer in the range [0, 2^NBITS).
The value is returned in the form of a native floating point number, so
NBITS can be at most one greater than the number of bits of significand
in the floating point format.

With NBITS = 48 the range of output values is the same as that of the
Unix C<drand48> function.

=cut

my @fixbit;
for(my $e = 1.0; ; ) {
	my $ne = $e * 0.5;
	push @fixbit, $ne;
	last unless (1.0 + $ne) - 1.0 == $ne;
	$e = $ne;
}

sub rand_fix($) {
	my($nbits) = @_;
	croak "need a non-negative number of bits to dispense"
		unless $nbits >= 0;
	croak "can't generate more than ".scalar(@fixbit).
			" bits of fixed-point fraction"
		if $nbits > @fixbit;
	my $frac = 0.0;
	for(my $pos = 24; $pos <= $nbits; $pos += 24) {
		$frac += rand_int(1 << 24) * $fixbit[$pos - 1];
	}
	$frac += rand_int(1 << ($nbits % 24)) * $fixbit[$nbits - 1];
	return $frac;
}

=item rand[(LIMIT)]

Generates a random fixed-point fraction by C<rand_fix(48)> and then
multiplies it by LIMIT (default 1, and 0 also gets treated as 1) and
returns the result.  This is a drop-in replacement for C<CORE::rand>:
it produces exactly the same range of output values, but using the
current entropy source instead of a sucky PRNG with linear relationships
between successive outputs.  (C<CORE::rand> does the type of calculation
described, but using the PRNG C<drand48> to generate the fixed-point
fraction.)  The details of behaviour may change in the future if the
behaviour of C<CORE::rand> changes, to maintain the match.

Where the source of a module can't be readily modified, it can be made
to use this C<rand> by an incantation such as

	*Foreign::Module::rand =
		\&Data::Entropy::Algorithms::rand;

This function should not be used in any new code, because the kind
of output supplied by C<rand> is hardly ever the right thing to use.
The C<int(rand($n))> idiom to generate a random integer has non-uniform
probabilities of generating each possible value, except when C<$n> is a
power of two.  For floating point numbers, C<rand> can't generate most
representable numbers in its output range, and the output is biased
towards zero.  In new code use C<rand_int> to generate integers and
C<rand_flt> to generate floating point numbers.

=cut

sub rand(;$) {
	my($limit) = @_;
	return rand_fix(48) *
		(!defined($limit) || $limit == 0.0 ? 1.0 : $limit);
}

=item rand_flt(MIN, MAX)

Selects a uniformly-distributed real number (with infinite precision)
in the range [MIN, MAX] and then rounds this number to the nearest
representable floating point value, which it returns.  (Actually it is
only B<as if> the function worked this way: in fact it never generates
the number with infinite precision.  It selects between the representable
floating point values with the probabilities implied by this process.)

This can return absolutely any floating point value in the range [MIN,
MAX]; both MIN and MAX themselves are possible return values.  All bits
of the floating point type are filled randomly, so the range of values
that can be returned depends on the details of the floating point format.
(See L<Data::Float> for low-level floating point utilities.)

The function C<die>s if MIN and MAX are not both finite.  If MIN is
greater than MAX then their roles are swapped: the order of the limit
parameters actually doesn't matter.  If the limits are identical then
that value is always returned.  As a special case, if the limits are
positive zero and negative zero then a zero will be returned with a
randomly-chosen sign.

=cut

sub rand_flt($$) {
	my($a, $b) = @_;
	croak "bounds for rand_flt() must be finite"
		unless float_is_finite($a) && float_is_finite($b);
	if($a == $b) {
		return $_[rand_int(2)]
			if $a == 0.0 && float_sign($a) ne float_sign($b);
		return $_[0];
	}
	($a, $b) = ($b, $a) if abs($a) < abs($b);
	my($prm_sign, $prm_max_exp, $prm_max_sgnf) =
		$a == 0.0 ? ("+", min_normal_exp, 0.0) : float_parts($a);
	my($b_sign, $b_exp, $b_sgnf) =
		$b == 0.0 ? ("+", min_normal_exp, 0.0) : float_parts($b);
	my($min_exp, $min_sgnf);
	my($opp_max_exp, $opp_max_sgnf);
	if($b_sign eq $prm_sign) {
		($min_exp, $min_sgnf) = ($b_exp, $b_sgnf);
		($opp_max_exp, $opp_max_sgnf) = (min_normal_exp, 0.0);
	} else {
		($min_exp, $min_sgnf) = (min_normal_exp, 0.0);
		($opp_max_exp, $opp_max_sgnf) = ($b_exp, $b_sgnf);
	}
	TRY_AGAIN:
	my $exp = $prm_max_exp;
	my $bseg = significand_bits;
	$bseg = 28 if $bseg > 28;
	my $prm_frng = $prm_max_sgnf * (1 << $bseg);
	my $prm_range = int($prm_frng);
	$prm_range++ if $prm_frng != $prm_range;
	my $min_bits = $bseg - ($exp - $min_exp);
	my $min_range = $min_bits >= 0 ? int($min_sgnf * (1 << $min_bits)) : 0;
	my $opp_bits = $bseg - ($exp - $opp_max_exp);
	my $opp_frng = $opp_bits >= 0 ? $opp_max_sgnf * (1 << $opp_bits) : 0;
	my $opp_range = int($opp_frng);
	$opp_range++ if $opp_frng != $opp_range;
	my $n = $min_range + rand_int($prm_range - $min_range + $opp_range);
	my($sg, $max_exp, $max_sgnf);
	if($n >= $prm_range) {
		$n -= $prm_range;
		($sg, $max_exp, $max_sgnf) = ($b, $opp_max_exp, $opp_max_sgnf);
	} else {
		($sg, $max_exp, $max_sgnf) = ($a, $prm_max_exp, $prm_max_sgnf);
	}
	while($n == 0 && $exp - $bseg - 1 >= min_normal_exp) {
		$exp -= $bseg + 1;
		$bseg = significand_bits;
		$bseg = 28 if $bseg > 28;
		$n = rand_int(2 << $bseg);
	}
	for(my $bit = 16; $bit; $bit >>= 1) {
		if($bseg >= $bit && $exp - $bit >= min_normal_exp &&
				$n < (2 << ($bseg - $bit))) {
			$bseg -= $bit;
			$exp -= $bit;
		}
	}
	goto TRY_AGAIN if $exp < $min_exp;
	my $top_sgnf = $exp == $max_exp ? $max_sgnf : 2.0;
	my $bot_sgnf = $exp == $min_exp ? $min_sgnf : 1.0;
	my $sgnf = mult_pow2($n, -$bseg);
	if(!have_subnormal && $exp == min_normal_exp && $sgnf < 1.0) {
		$top_sgnf = 1.0;
		$sgnf = 0.0;
	} else {
		$bot_sgnf = 1.0 if !have_subnormal && $exp == min_normal_exp &&
					$bot_sgnf < 1.0;
		for(my $bdone = $bseg; $bdone != significand_bits; ) {
			my $bseg = significand_bits - $bdone;
			$bseg = 28 if $bseg > 28;
			$bdone += $bseg;
			$sgnf += mult_pow2(rand_int(1 << $bseg), -$bdone);
		}
	}
	goto TRY_AGAIN if $sgnf < $bot_sgnf || $sgnf >= $top_sgnf;
	$sgnf = $top_sgnf if $sgnf == $bot_sgnf && rand_int(2);
	return copysign($sgnf == 0.0 ? 0.0 : mult_pow2($sgnf, $exp), $sg);
}

=back

=head2 Combinatorics

=over

=item pick(ITEM ...)

Randomly selects and returns one of the ITEMs.  Each ITEM has equal
probability of being selected.

=item pick_r(ITEMS)

ITEMS must be a reference to an array.  Randomly selects and returns
one of the elements of the array.  Each element has equal probability
of being selected.

This is the same operation as that performed by C<pick>, but using
references to avoid expensive copying of arrays.

=cut

sub pick_r($) {
	my($a) = @_;
	croak "need a non-empty array to pick from"
		unless is_ref($a, "ARRAY") && @$a;
	return $a->[rand_int(@$a)];
}

sub pick(@) { pick_r(\@_) }

=item choose(NCHOOSE, ITEM ...)

Randomly selects NCHOOSE of the ITEMs.  Each ITEM has equal probability
of being selected.  The chosen items are returned in a list in the same
order in which they appeared in the argument list.

=item choose_r(NCHOOSE, ITEMS)

ITEMS must be a reference to an array.  Randomly selects NCHOOSE of
the elements in the array.  Each element has equal probability of being
selected.  Returns a reference to an array containing the chosen items
in the same order in which they appeared in the input array.

This is the same operation as that performed by C<choose>, but using
references to avoid expensive copying of arrays.

=cut

sub choose_r($$) {
	my($nchoose, $a) = @_;
	croak "need a non-negative number of items to choose"
		unless $nchoose >= 0;
	croak "need a sufficiently large array to pick from"
		unless is_ref($a, "ARRAY") && @$a >= $nchoose;
	my $ntotal = @$a;
	my $nleave = $ntotal - $nchoose;
	my @chosen;
	for(my $i = 0; $i != $ntotal; $i++) {
		if(entropy_source->get_prob($nleave, $nchoose)) {
			push @chosen, $a->[$i];
			$nchoose--;
		} else {
			$nleave--;
		}
	}
	return \@chosen;
}

sub choose(@) { @{choose_r(shift, \@_)} }

=item shuffle(ITEM ...)

Reorders the ITEMs randomly, and returns them in a list in random order.
Each possible order has equal probability.

=item shuffle_r(ITEMS)

ITEMS must be a reference to an array.  Reorders the elements of the
array randomly.  Each possible order has equal probability.  Returns a
reference to an array containing the elements in random order.

This is the same operation as that performed by C<shuffle>, but using
references to avoid expensive copying of arrays.

=cut

sub shuffle_r($) {
	my($a) = @_;
	croak "need an array to shuffle"
		unless is_ref($a, "ARRAY");
	$a = [ @$a ];
	for(my $i = @$a; $i > 1; ) {
		my $j = rand_int($i--);
		@{$a}[$i, $j] = @{$a}[$j, $i];
	}
	return $a;
}

sub shuffle(@) { @{shuffle_r(\@_)} }

=back

=head1 SEE ALSO

L<Data::Entropy>

=head1 AUTHOR

Andrew Main (Zefram) <zefram@fysh.org>

=head1 COPYRIGHT

Copyright (C) 2006 Andrew Main (Zefram) <zefram@fysh.org>

This module is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
