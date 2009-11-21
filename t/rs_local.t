use Test::More tests => 4;

BEGIN { use_ok "Data::Entropy::RawSource::Local"; }

$rawsrc = Data::Entropy::RawSource::Local->new("t/test0.entropy");
ok $rawsrc;
is $rawsrc->getc, "\x93";

eval { Data::Entropy::RawSource::Local->new("t/notexist.entropy"); };
isnt $@, "";
