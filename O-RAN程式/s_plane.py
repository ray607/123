from scapy.all import *

# Define a custom Scapy layer for the PTP Delay_Req message
class PTPDelayRequest(Packet):
    name = "PTP Delay Request"
    fields_desc = [
        BitField("majorSdoID", 0x0, 4),
        BitEnumField("messageType", 1, 4, {1: "Delay_Req Message"}),
        BitField("reserved_1", 0, 4),
        BitField("minorversionPTP", 0, 2),
        BitField("versionPTP", 0x2, 2),
        BitField("messageLength", 44, 16),
        BitField("domainNumber", 24, 8),
        BitField("reserved_2", 0, 8),
        BitField("flags", 0, 16),
        BitField("correctionField", 0, 64),
        BitField("reserved_3", 0, 32),
        BitField("sourcePortIdentity", 30, 80),
        BitField("sequenceId", 3, 16),
        BitField("control", 0x01, 8),
        BitField("logMeanMessageInterval", 127, 8),
        BitField("originTimestamp_second", 0, 48),
        BitField("originTimestamp_nanosecond", 0, 32),
    ]


# # Create an instance of the custom PTPDelayRequest layer
# ptp_delay_req = PTPDelayRequest(domainNumber=12)

# # Create an Ethernet frame and encapsulate the PTP Delay Request layer
# eth_frame = Ether(type=0x88f7) / ptp_delay_req

# # Display the resulting packet
# eth_frame.show()

# # You can send, save, or manipulate the packet as needed

# # 保存封包到文件
# wrpcap("s_packet.pcap", eth_frame)

# # 发送eCPRI封包
# x = 0
# while x < 50:
#     sendp(eth_frame, iface="ens33")  # Change "eth0" to your desired interface
#     x += 1
