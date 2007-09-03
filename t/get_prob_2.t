use Test::More tests => 752;

use IO::File 1.03;

BEGIN { use_ok Data::Entropy::Source; }

my $rawsource = IO::File->new("t/test0.entropy", "r") or die $!;
my $source = Data::Entropy::Source->new($rawsource, "getc");
ok $source;

while(<DATA>) {
	while(/(\d)/g) {
		is $source->get_prob(2, 1), $1;
	}
}

__DATA__
010010000000010000000001011000000000010000000001010000010100100110000010101
110010000111000001000000000101011010001011101110000000010011111010010111100
101010000000000001001000000011000000000101000010011110001100110000001101010
100110100010101000000001100100000111010011000000100100010100000110001000010
110000000001101100010000011111100000100110111010010011000100100101110000110
000111000011010010000011101001101000000000100100011000000000000100100100110
001010000001101010000100111000011100000011001010000010001001001101001100010
010110110010000100000000000010110101000100000100000001011111100001000000000
000000101000011000000100010100000000010000010101011110100010010101000001100
000010001000001100001000101000001100011011000010100100000000000000100001111