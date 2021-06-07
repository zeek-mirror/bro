module PacketAnalyzer;

event encapsulation_protocol(c: connection, aname: string)
	{
	add c$service[aname];
	}
