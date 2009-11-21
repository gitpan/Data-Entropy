use Test::More tests => 2;

BEGIN { use_ok "Data::Entropy::RawSource::RandomOrg"; }

$rawsrc = Data::Entropy::RawSource::RandomOrg->new;
ok $rawsrc;
