module PacketAnalyzer::Geneve;

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_UDP, 6081, PacketAnalyzer::ANALYZER_GENEVE);

	# This is defined by IANA as being "Trans Ether Bridging" but the Geneve RFC
	# says to use it for Ethernet. See
	# https://datatracker.ietf.org/doc/html/draft-gross-geneve-00#section-3.4
	# for details.
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GENEVE, 0x6558, PacketAnalyzer::ANALYZER_ETHERNET);
	}
