from scapy.all import *
# 定义一个自定义的Packet类
class CPlanHeader(Packet):
    name = "C-Plan Header"
    fields_desc = [
        ShortField("pc_id", 0x1234),
        ShortField("seq_id", 0x8765),
        BitField("dataDirection", 1, 1),
        BitField("payloadVersion", 1, 3),
        BitField("filterIndex", 0, 4),
        ByteField("frameId", 175),
        BitField("subframeId", 3, 4),
        BitField("slotId", 0, 6),
        BitField("startSymbolid", 0, 6),
        ByteField("numberOfsections",1),
        ByteField("sectionType", 3),
    ]

class CPlanSectionType3Header(Packet):
    name = "C-Plan Section Type3 Header"
    fields_desc = [
        BitField("timeOffset", 0, 16),
        ByteField("frameStructure",1),
        BitField("cpLength", 0, 16),
        ByteField("udCompHdr", 1), 
    ]


class ECpriCommonHeader(Packet):
    name = "eCPRI Common Header"
    fields_desc = [
        BitField("protocol_revision", 1, 4),
        BitField("reserved_1", 0, 3),
        BitField("c_bit", 0, 1),
        ByteField("message_type", 0x02),
        ShortField("payload_size", 0),
    ]
class CPlanSectionType3(Packet):
    name = "C-Plan Section Type3"
    fields_desc = [
        BitField("sectionId",0,12),
        BitField("rb",0,1),
        BitField("symInc", 0,1),
        BitField("startPrbc",0,10),
        BitField("numPrbc",12,8),
        BitField("reMask",0xfff,12),
        BitField("numSymbol",6,4),
        BitField("ef",0,1),
        BitField("beamId",0,15),
        BitField("frequencyOffset",-792,24),
        BitField("reserved",0,8),
    ]
# def generate_c_plan_type_3():
#     ecpri_frame = Ether(type=0xaefe) 
#     ecpri_packet =  ecpri_frame / ECpriCommonHeader(payload_size=28)  / CPlanHeader(sectionType=3) / CPlanSectionType3Header() / CPlanSectionType3()
#     return ecpri_packet

# 创建一个CustomPacket对象
# ecpri_packet =  generate_c_plan_type_3()
# ecpri_packet =  generate_c_plan_type_1()
# ecpri_packet.show()

# # 保存封包到文件
# wrpcap("c_plane_packet.pcap", ecpri_packet)

# # 发送eCPRI封包
# x = 0
# while x < 10:
#     sendp(ecpri_packet, iface="Killer(R) Wi-Fi 6E AX1675i 160MHz Wireless Network Adapter (211NGW)")
#     x = x + 1