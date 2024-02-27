from scapy.all import *
# 定义一个自定义的Packet类
class UPlaneHeader(Packet):
    name = "U-Plane Header"
    fields_desc = [
        # ShortField("pc_id", 0x1234),
        # ShortField("seq_id", 0x8765),
        BitField("dataDirection", 0, 1),
        BitField("payloadVersion", 1, 3),
        BitField("filterIndex", 0, 4),
        ByteField("frameId", 0),
        BitField("subframeId", 0, 4),
        BitField("slotId", 0, 6),
        BitField("symbolid",0, 6)
    ]

class UPlaneSection(Packet):
    name = "U-Plane "
    fields_desc = [
        BitField("sectionid", 1, 12),  # Add reMask field (12 bits)
        BitField("rb", 0, 2),
        BitField("symlnc", 0, 1),
        BitField("startPrbc", 0, 9),
        ByteField("numPrbu", 2),
        ByteField("udCompHdr", 0),
        ByteField("reserved", 0),
    ]

class ECpriCommonHeader(Packet):
    name = "eCPRI Common Header"
    fields_desc = [
        BitField("protocol_evision", 1, 4),
        BitField("reserved_1", 0, 3),
        BitField("c_bit", 0, 1),
        ByteField("message_type", 0x00),
        ShortField("payload_size", 0),
        ShortField("ecpriRtcid", 0),
        ShortField("ecpriSeqid", 0),
    ]
class udCompParam(Packet):
    name = "eCPRI Sample"
    fields_desc = [
        ByteField("udCompParam", 0),  # User data compression parameter
    ]
class ECpri(Packet):
    name = "eCPRI Sample"
    fields_desc = [
        # ByteField("udCompParam", 0),  # User data compression parameter
        ShortField("iSample", 0x01),  # In-phase sample
        ShortField("qSample", 0x01),  # Quadrature sample
    ]

def generate_u_plane():
    ecpri_frame = Ether(type=0xaefe) 
    ecpri_packet =  ecpri_frame / ECpriCommonHeader(payload_size=111)  / UPlaneHeader() / UPlaneSection() 
    ecpri_packet /=  UPlaneSection() 
    ecpri_packet /=  udCompParam()    
    for i in range(12):
        ecpri_packet /=  ECpri()
    ecpri_packet /=  udCompParam()    
    for i in range(12):
        ecpri_packet /=  ECpri() 
    return ecpri_packet

ecpri_packet =  generate_u_plane()
ecpri_packet.show()

wrpcap("u_plane_packet.pcap", ecpri_packet)

# 发送eCPRI封包
x = 0
while x < 10:
    sendp(ecpri_packet, iface="ens33")
    x = x + 1