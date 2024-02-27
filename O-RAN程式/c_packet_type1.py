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
        ByteField("sectionType", 1),
    ]

class CPlanSectionType1Header(Packet):
    name = "C-Plan Section Type1 Header"
    fields_desc = [
        ByteField("udCompHdr", 1),
        ByteField("reserved", 0), 
    ]
class CPlanSectionType1(Packet):
    name = "C-Plan Section Type1"
    fields_desc = [
        BitField("sectionId",0,12),
        BitField("rb",0,1),
        BitField("symInc", 0,1),
        BitField("startPrbc",0,10),
        BitField("numPrbc",1,8),
        BitField("reMask",0,12),
        BitField("numSymbol",1,4),
        BitField("ef",0,1),
        BitField("beamId",0,15),
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

# def generate_c_plan_type_1():
#     ecpri_frame = Ether(type=0xaefe) 
#     ecpri_packet =  ecpri_frame / ECpriCommonHeader(payload_size=20)  / CPlanHeader(sectionType=1) / CPlanSectionType1Header() / CPlanSectionType1()
#     return ecpri_packet


# ecpri_packet =  generate_c_plan_type_1()
# ecpri_packet.show()



# # 发送eCPRI封包
# x = 0
# while x < 10:
#     sendp(eth_frame, iface="ens33")
#     x = x + 1