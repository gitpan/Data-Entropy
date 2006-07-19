use ExtUtils::MakeMaker;

WriteMakefile(
	NAME => "Data::Entropy",
	VERSION_FROM => "lib/Data/Entropy.pm",
	PREREQ_PM => {
		Crypt::Rijndael => undef,
		Errno => "1.00",
		Fcntl => "1.04",
		IO::File => "1.03",
		LWP => "5.53_94",
		LWP::UserAgent => undef,
		Math::BigInt => "1.60",
		Math::BigRat => "0.04",
		Params::Classify => "0.000",
	},
);
