use Test::More tests => 2051;

use IO::File;

BEGIN { use_ok Data::Entropy::Source; }

my $rawsource = IO::File->new("t/test0.entropy", "r") or die $!;
my $source = Data::Entropy::Source->new($rawsource, "getc");
ok $source;
$rawsource = IO::File->new("t/test0.entropy", "r") or die $!;

until($rawsource->eof) {
	is $source->get_octet, $rawsource->getc;
}

eval { $source->get_octet; };
like $@, qr/\Aentropy source failed:/;
