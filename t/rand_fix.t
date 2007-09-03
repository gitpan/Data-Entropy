use Test::More tests => 261;

use IO::File 1.03;

BEGIN {
	use_ok Data::Entropy::Source;
	use_ok Data::Entropy, qw(with_entropy_source);
	use_ok Data::Entropy::Algorithms, qw(rand_fix);
}

with_entropy_source +Data::Entropy::Source->new(
		IO::File->new("t/test0.entropy", "r") || die($!), "getc"
), sub {
	while(<DATA>) {
		chop;
		is rand_fix(10), $_;
	}
	is rand_fix(1), 0.0;
	eval { rand_fix(-1); };
	like $@, qr/\Aneed a non-negative number of bits to dispense/;
}

__DATA__
0.681640625
0.47265625
0.1708984375
0.9013671875
0.892578125
0.7470703125
0.6708984375
0.6083984375
0.341796875
0.7705078125
0.0390625
0.5068359375
0.146484375
0.2421875
0.904296875
0.326171875
0.609375
0.3935546875
0.392578125
0.5498046875
0.259765625
0.6650390625
0.125
0.0244140625
0.7138671875
0.91015625
0.1337890625
0.1318359375
0.4775390625
0.0576171875
0.0322265625
0.2255859375
0.390625
0.2216796875
0.9111328125
0.861328125
0.72265625
0.2958984375
0.0576171875
0.8037109375
0.0078125
0.580078125
0.0224609375
0.703125
0.005859375
0.5107421875
0.2265625
0.5302734375
0.853515625
0.640625
0.833984375
0.0986328125
0.8466796875
0.9853515625
0.7998046875
0.36328125
0.9287109375
0.0986328125
0.619140625
0.794921875
0.8056640625
0.619140625
0.646484375
0.44921875
0.1591796875
0.2041015625
0.51953125
0.8095703125
0.2451171875
0.693359375
0.1201171875
0.1630859375
0.7978515625
0.7470703125
0.6455078125
0.8125
0.140625
0.78125
0.9404296875
0.6748046875
0.71484375
0.4609375
0.2841796875
0.5634765625
0.3037109375
0.4189453125
0.0810546875
0.52734375
0.3583984375
0.3984375
0.744140625
0.0693359375
0.7919921875
0.6044921875
0.89453125
0.0009765625
0.365234375
0.89453125
0.9765625
0.8349609375
0.7880859375
0.765625
0.646484375
0.9130859375
0.28515625
0.66015625
0.3369140625
0.23046875
0.37890625
0.87109375
0.6533203125
0.486328125
0.70703125
0.75
0.0927734375
0.8330078125
0.1259765625
0.8173828125
0.9609375
0.7294921875
0.0625
0.0986328125
0.578125
0.0341796875
0.1591796875
0.625
0.294921875
0.490234375
0.2978515625
0.2275390625
0.5068359375
0.4443359375
0.486328125
0.8701171875
0.5810546875
0.0751953125
0.1708984375
0.8671875
0.9345703125
0.8076171875
0.111328125
0.97265625
0.4404296875
0.212890625
0.4716796875
0.0029296875
0.625
0.1240234375
0.779296875
0.271484375
0.548828125
0.16796875
0.5009765625
0.5341796875
0.7548828125
0.369140625
0.890625
0.23828125
0.0927734375
0.068359375
0.8271484375
0.4873046875
0.70703125
0.8193359375
0.7451171875
0.302734375
0.8291015625
0.474609375
0.18359375
0.4892578125
0.9990234375
0.5390625
0.2392578125
0.63671875
0.703125
0.400390625
0.30078125
0.5869140625
0.578125
0.890625
0.798828125
0.646484375
0.080078125
0.005859375
0.7001953125
0.02734375
0.072265625
0.8623046875
0.9375
0.7998046875
0.591796875
0.998046875
0.6171875
0.0009765625
0.673828125
0.052734375
0.2021484375
0.7197265625
0.9560546875
0.001953125
0.0986328125
0.375
0.375
0.234375
0.173828125
0.5341796875
0.9423828125
0.80859375
0.1083984375
0.134765625
0.5478515625
0.1533203125
0.5458984375
0.3564453125
0.9697265625
0.591796875
0.9375
0.345703125
0.248046875
0.3876953125
0.984375
0.8203125
0.9453125
0.5380859375
0.79296875
0.833984375
0.6796875
0.7841796875
0.9609375
0.5009765625
0.845703125
0.4716796875
0.6201171875
0.0048828125
0.169921875
0.0859375
0.0546875
0.3134765625
0.6376953125
0.9072265625
0.392578125
0.3330078125
0.7880859375
0.986328125
0.849609375
0.115234375
0.7041015625
0.0751953125
0.1650390625
0.24609375
0.7958984375
0.681640625
0.04296875
0.9326171875
0.12890625
0.763671875
