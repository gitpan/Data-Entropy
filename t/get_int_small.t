use Test::More tests => 4930;

use IO::File 1.03;

BEGIN { use_ok Data::Entropy::Source; }

sub match($$) {
	my($a, $b) = @_;
	ok ref($a) eq ref($b) && $a == $b;
}

my $rawsource = IO::File->new("t/test0.entropy", "r") or die $!;
my $source = Data::Entropy::Source->new($rawsource, "getc");
ok $source;

while(<DATA>) {
	while(/([0-9])/g) {
		match $source->get_int(10), $1;
	}
}

eval { $source->get_int(10); };
like $@, qr/\Aentropy source failed:/;

__DATA__
576597749637294638347592570212132217704252351927564932761346046298673314465
668853933377323224597373282421406979484664696530643140294636676733089781390
852819136829337430031748018528742296912772037431612173090375601966749578637
815623470219055917566908369838793829442964859636606869243810773032374937201
076193983874217596160983742436116114156773008085562061188224112516226229305
718361413585456989575877886335362076026479937315689370071657265613304548936
568137516315943381369187098658096758809069585316441236980447977452657131262
905652003385539566854252647432736302517027765656896767008609235813694445014
829490805429464027338575093225826912766172652427107982571719391987722351043
670020937392214836321066739360057662681177640381147462712394026215222368020
157881317111179038329520086191206069805259435956853601726810222327780026821
430663074824731558095930818692624316936660123315956538309662497732408467331
146755109216229856043356788063193998090446339759745648041717846217679603008
616428919612421424014758440021788579501614143027226537621310022829054650454
599660884942423418004261941369390841427305430244643217785888619502069928776
566903089339448307731814385025882693970483249461624083221558060171319706314
740660963526378401055789048993012089307296041411564799705022404264062787675
080619918401314795239217804669105391335346148898445465499608595695282076180
457016966518952770534157751818707817489009789064178788942781407594171253563
125308120637277563115813179531789045256547221995565074925120161385529617183
331672918200815603355924071247669582379666274238894884344782887628239494364
884345026187619402727092325785367792870993356637753530433038715972965549728
616924843649643868274562032967376850571260700090393489208278649001446682735
175059354183105995182047903435672325342335281433915185767767131278031291665
208703556727160133812159876954529339917443504783565857143127826051431773011
425559878335514203523098740392278708001882708876313875419436430694731061138
423159153519017742100278509724360528336072639760096772502639662227151677307
836268659250483414343403203403915008979683602450844471056779861210013459941
954146126134392457465586792898761072578023722487804304688793071129636698546
436219205948195121259446000322082764860433365706313877183574574784207187469
743324067872288487111357661913643271801147404494810087698206708443525287507
512132693539143670352670040980452192898840958297086965092991030367438964637
223795055382043603274217109668777943114251395716318126247957017514507899143
230362139383134863712556324010095123401737878648973176507854842280379352023
333098467904595218491860236430065438046837148762445347034907530299407576778
909576740690121714138428543259652263153784885844437298224244551068096884843
629482030840564052864903443421809641523456540495783836439564675342401624030
829995415056812154130533262113690393095408764219978298857439395626722781062
900480723702801320729620679653170160439454997247424637834936855874611831344
654489013894154698762718860469863995180595113901198276225765045560214021792
410456690201629504172774055727875726333185421471607129616301444008779395296
654280608905036233077759759084559839521986247885626571935982230475929573606
507242697081690252574111568239906256544779596887511724870018169041571295481
707247861251723338197500897451226099242779600888155194986633688534499785720
492534506645195503069109866470340162514363169975039928866651494857827024760
083655162818953002483613336172370587636427406335669225107047581594604037645
193614405497277094659324420353959979544839216717162009449019160093832647259
549739780461144479998417501906909016629635330051142602194535041680562423216
250567151864781405656131439300603011049554734132816478805401026149704676531
752423307675078112287129247507525140640933193385141898874487307184862239590
629756268249988556621395785385456523937736027319361718265818971432802924044
767744716850343751557769951979948866182209106783517474904239105538265120602
433276833007670553207700029886459793054582148957352110688890415394407278665
636852421880007580077258978199711897738061108982873273478697780541277623790
138524099987743252437361285915159589645146335149846858572741923877234290861
081264507377264281363690904230135057584390065641780500051421010260704631553
747559980376518220436842767728903764441329913698161940478687402916953183517
729492931538678031158894971819348967338843150260580760575831075523584292605
154163776214818358356414157119953134966794347811680654359615379013710814850
224076935067055933765108565124870126600679741085999907333530555131128927968
201276073603100811782862584905512808550152002147784348720714076273677616048
259112737186912013219848430724442380382808511476199782062448469690616574012
224566789542992612679594747452284232670651581169121591210144316322242608972
747165916119711541986176068663516316233961013786299429149430020179604349191
494056916884590911617409837854749794512294784578045702889638972135346862374
6318881893957752968464847295145156893370957319113323
