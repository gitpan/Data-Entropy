use Test::More tests => 2;

BEGIN { use_ok "Data::Entropy::RawSource::RandomnumbersInfo"; }

$rawsrc = Data::Entropy::RawSource::RandomnumbersInfo->new;
ok $rawsrc;
