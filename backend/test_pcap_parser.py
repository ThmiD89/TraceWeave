from services.pcap_parser import parse_heartbeat_packets

pcap = "evidence/pcaps/heartbeat-test.pcapng"

packets = parse_heartbeat_packets(pcap)

print("Total heartbeat requests:", len(packets))

for packet in packets:
    print(packet)
