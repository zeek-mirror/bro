module PacketAnalyzer::AYIYA;

const IPPROTO_IPV4 : count = 4;
const IPPROTO_IPV6 : count = 41;

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_protocol_detection(PacketAnalyzer::ANALYZER_UDP, PacketAnalyzer::ANALYZER_AYIYA);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_UDP, 5072, PacketAnalyzer::ANALYZER_AYIYA);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_AYIYA, IPPROTO_IPV4, PacketAnalyzer::ANALYZER_IPTUNNEL);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_AYIYA, IPPROTO_IPV6, PacketAnalyzer::ANALYZER_IPTUNNEL);
	}
