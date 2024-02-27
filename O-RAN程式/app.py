from flask import Flask, render_template, request
from scapy.all import *
from s_plane import PTPDelayRequest
from c_plane_type1 import ECpriCommonHeader
from c_plane_type1 import CPlanHeader, CPlanSectionType1Header, CPlanSectionType1
from c_plane_type3 import CPlanSectionType3, CPlanSectionType3Header
from u_plane import UPlaneHeader, UPlaneSection, udCompParam, ECpri, ECpriCommonHeader

app = Flask(__name__)
@app.route('/')
def index():
    # Set default values for the fields
    default_data = {
        "majorSdoID": "default_majorSdoID",
        "messageType": "default_messageType",
        "reserved_1": "default_reserved_1",
        "minorversionPTP": "default_minorversionPTP",
        "versionPTP": "default_versionPTP",
        "messageLength": "default_messageLength",
        "domainNumber": "default_domainNumber",
        "reserved_2": "default_reserved_2",
        "flags": "default_flags",
        "correctionField": "default_correctionField",
        "reserved_3": "default_reserved_3",
        "sourcePortIdentity": "default_sourcePortIdentity",
        "sequenceId": "default_sequenceId",
        "control": "default_control",
        "logMeanMessageInterval": "default_logMeanMessageInterval",
        "originTimestamp_second": "default_originTimestamp_second",
        "originTimestamp_nanosecond": "default_originTimestamp_nanosecond",
        # Add other fields with default values
    }
    
    return render_template('test.html', default_data=default_data)
################################s_plane###########
@app.route('/process_data/s_plane', methods=['POST'])
def process_data_s_plane():
    s_plane_data = {
        "majorSdoID": request.form.get("majorSdoID"),
        "messageType": request.form.get("messageType"),
        "reserved_1": request.form.get("reserved_1"),
        "minorversionPTP": request.form.get("minorversionPTP"),
        "versionPTP": request.form.get("versionPTP"),
        "messageLength": request.form.get("messageLength"),
        "domainNumber": request.form.get("domainNumber"),
        "reserved_2": request.form.get("reserved_2"),
        "flags": request.form.get("flags"),
        "correctionField": request.form.get("correctionField"),
        "reserved_3": request.form.get("reserved_3"),
        "sourcePortIdentity": request.form.get("sourcePortIdentity"),
        "sequenceId": request.form.get("sequenceId"),
        "control": request.form.get("control"),
        "logMeanMessageInterval": request.form.get("logMeanMessageInterval"),
        "originTimestamp_second": request.form.get("originTimestamp_second"),
        "originTimestamp_nanosecond": request.form.get("originTimestamp_nanosecond"),
    }
    # speed_value = int(request.form.get('speed'))
    eth_frame = Ether(type=0x88f7) / PTPDelayRequest(
        majorSdoID=int(request.form.get("majorSdoID"),16),
        messageType=int(request.form.get("messageType")),
        reserved_1=int(request.form.get("reserved_1")),
        minorversionPTP=int(request.form.get("minorversionPTP")),
        versionPTP=int(request.form.get("versionPTP"),16),
        messageLength=int(request.form.get("messageLength")),
        domainNumber=int(request.form.get("domainNumber")),
        reserved_2=int(request.form.get("reserved_2")),
        flags=int(request.form.get("flags")),
        correctionField=int(request.form.get("correctionField")),
        reserved_3=int(request.form.get("reserved_3")),
        sourcePortIdentity=int(request.form.get("sourcePortIdentity")),
        sequenceId=int(request.form.get("sequenceId")),
        control=int(request.form.get("control"),16),
        logMeanMessageInterval=int(request.form.get("logMeanMessageInterval")),
        originTimestamp_second=int(request.form.get("originTimestamp_second")),
        originTimestamp_nanosecond=int(request.form.get("originTimestamp_nanosecond")),
        )
    # sendpfast(eth_frame, pps=speed_value, iface='ens33', loop=1)
    wrpcap("/home/a/Downloads/s_packet.pcap", eth_frame)

    return render_template('result.html', data=s_plane_data)
################################s_plane###########
################################c_plane_type1###########
@app.route('/process_data/c_plane_type1', methods=['POST'])
def process_data_c_plane_type1():
    c_plane_type1 = {
        "pc_id": request.form.get("pc_id"),
        "seq_id": request.form.get("seq_id"),
        "dataDirection": request.form.get("dataDirection"),
        "payloadVersion": request.form.get("payloadVersion"),
        "filterIndex": request.form.get("filterIndex"),
        "frameId": request.form.get("frameId"),
        "subframeId": request.form.get("subframeId"),
        "slotId": request.form.get("slotId"),
        "startSymbolid": request.form.get("startSymbolid"),
        "numberOfsections": request.form.get("numberOfsections"),
        "sectionType": 1,
        "udCompHdr": request.form.get("udCompHdr"),
        "reserved": request.form.get("reserved"),
        "sectionId": request.form.get("sectionId"),
        "rb": request.form.get("rb"),
        "symInc": request.form.get("symInc"),
        "startPrbc": request.form.get("startPrbc"),
        "numPrbc": request.form.get("numPrbc"),
        "reMask": request.form.get("reMask"),
        "numSymbol": request.form.get("numSymbol"),
        "ef": request.form.get("ef"),
        "beamId": request.form.get("beamId"),
        "protocol_revision": request.form.get("protocol_revision"),
        "reserved_1": request.form.get("reserved_1"),
        "c_bit": request.form.get("c_bit"),
        "message_type": request.form.get("message_type"),
        "payload_size": 20,
    }
    speed_value = int(request.form.get('speed'))
    ecpri_packet = Ether(type=0xaefe) / ECpriCommonHeader(
        protocol_revision=int(request.form.get("protocol_revision")),
        reserved_1=int(request.form.get("reserved_1")),
        c_bit=int(request.form.get("c_bit")),
        message_type=int(request.form.get("message_type"),16),
        payload_size=20
        ) / CPlanHeader(
        pc_id=int(request.form.get("pc_id"),16),
        seq_id=int(request.form.get("seq_id"),16),
        dataDirection=int(request.form.get("dataDirection")),
        payloadVersion=int(request.form.get("payloadVersion")),
        filterIndex=int(request.form.get("filterIndex")),
        frameId=int(request.form.get("frameId")),
        subframeId=int(request.form.get("subframeId")),
        slotId=int(request.form.get("slotId")),
        startSymbolid=int(request.form.get("startSymbolid")),
        numberOfsections=int(request.form.get("numberOfsections")),
        sectionType=1) / CPlanSectionType1Header(
        udCompHdr=int(request.form.get("udCompHdr")),
        reserved=int(request.form.get("reserved"))
        ) / CPlanSectionType1(
        sectionId=int(request.form.get("sectionId")),
        rb=int(request.form.get("rb")),
        symInc=int(request.form.get("symInc")),
        startPrbc=int(request.form.get("startPrbc")),
        numPrbc=int(request.form.get("numPrbc")),
        reMask=int(request.form.get("reMask"),16),
        numSymbol=int(request.form.get("numSymbol")),
        ef=int(request.form.get("ef")),
        beamId=int(request.form.get("beamId"))
        )
    sendpfast(ecpri_packet, pps=speed_value, iface='ens33', loop=1)
    wrpcap("c_packet_type1.pcap", ecpri_packet)

    return render_template('result.html', data=c_plane_type1)
################################c_plane_type1###########
################################c_plane_type3###########
@app.route('/process_data/c_plane_type3', methods=['POST'])
def process_data_c_plane_type3():
    c_plane_type3 = {
        "protocol_revision": request.form.get("protocol_revision"),
        "reserved_1": request.form.get("reserved_1"),
        "c_bit": request.form.get("c_bit"),
        "message_type": request.form.get("message_type"),
        "payload_size": 28,
        "pc_id": request.form.get("pc_id"),
        "seq_id": request.form.get("seq_id"),
        "dataDirection": request.form.get("dataDirection"),
        "payloadVersion": request.form.get("payloadVersion"),
        "filterIndex": request.form.get("filterIndex"),
        "frameId": request.form.get("frameId"),
        "subframeId": request.form.get("subframeId"),
        "slotId": request.form.get("slotId"),
        "startSymbolid": request.form.get("startSymbolid"),
        "numberOfsections": request.form.get("numberOfsections"),
        "sectionType": 3,
        "timeOffset": request.form.get("timeOffset"),
        "frameStructure": request.form.get("frameStructure"),
        "cpLength": request.form.get("cpLength"),
        "udCompHdr": request.form.get("udCompHdr"),
        "sectionId": request.form.get("sectionId"),
        "rb": request.form.get("rb"),
        "symInc": request.form.get("symInc"),
        "startPrbc": request.form.get("startPrbc"),
        "numPrbc": request.form.get("numPrbc"),
        "reMask": request.form.get("reMask"),
        "numSymbol": request.form.get("numSymbol"),
        "ef": request.form.get("ef"),
        "beamId": request.form.get("beamId"),
        "frequencyOffset": request.form.get("frequencyOffset"),
        "reserved": request.form.get("reserved"),
    }
    speed_value = int(request.form.get('speed'))
    ecpri_packet =  Ether(type=0xaefe) / ECpriCommonHeader(
        protocol_revision=int(request.form.get("protocol_revision")),
        reserved_1=int(request.form.get("reserved_1")),
        c_bit=int(request.form.get("c_bit")),
        message_type=int(request.form.get("message_type"),16),
        payload_size=28
        )  / CPlanHeader(
        pc_id=int(request.form.get("pc_id"),16),
        seq_id=int(request.form.get("seq_id"),16),
        dataDirection=int(request.form.get("dataDirection")),
        payloadVersion=int(request.form.get("payloadVersion")),
        filterIndex=int(request.form.get("filterIndex")),
        frameId=int(request.form.get("frameId")),
        subframeId=int(request.form.get("subframeId")),
        slotId=int(request.form.get("slotId")),
        startSymbolid=int(request.form.get("startSymbolid")),
        numberOfsections=int(request.form.get("numberOfsections")),
        sectionType=3) / CPlanSectionType3Header(
        timeOffset=int(request.form.get("timeOffset")),
        frameStructure=int(request.form.get("frameStructure")),
        cpLength=int(request.form.get("cpLength")),
        udCompHdr=int(request.form.get("udCompHdr"))
        ) / CPlanSectionType3(
        sectionId=int(request.form.get("sectionId")),
        rb=int(request.form.get("rb")),
        symInc=int(request.form.get("symInc")),
        startPrbc=int(request.form.get("startPrbc")),
        numPrbc=int(request.form.get("numPrbc")),
        reMask=int(request.form.get("reMask"),16),
        numSymbol=int(request.form.get("numSymbol")),
        ef=int(request.form.get("ef")),
        beamId=int(request.form.get("beamId")),
        frequencyOffset=int(request.form.get("frequencyOffset")),
        reserved=int(request.form.get("reserved")),
        )
    sendpfast(ecpri_packet, pps=speed_value, iface='ens33', loop=1)

    wrpcap("c_packet_type3.pcap", ecpri_packet)
    return render_template('result.html', data=c_plane_type3)
    
################################c_plane_type3###########
################################u_plane###########
@app.route('/process_data/u_plane', methods=['POST'])
def process_data_u_plane():
    u_plane = {
        "protocol_revision": request.form.get("protocol_revision"),
        "reserved_1": request.form.get("reserved_1"),
        "c_bit": request.form.get("c_bit"),
        "message_type": request.form.get("message_type"),
        "payload_size": request.form.get("payload_size"),
        "ecpriRtcid": request.form.get("ecpriRtcid"),
        "ecpriSeqid": request.form.get("ecpriSeqid"),
        "dataDirection": request.form.get("dataDirection"),
        "payloadVersion": request.form.get("payloadVersion"),
        "filterIndex": request.form.get("filterIndex"),
        "frameId": request.form.get("frameId"),
        "subframeId": request.form.get("subframeId"),
        "slotId": request.form.get("slotId"),
        "symbolid": request.form.get("symbolid"),
        "sectionId": request.form.get("sectionId"),
        "rb": request.form.get("rb"),
        "symInc": request.form.get("symInc"),
        "startPrbc": request.form.get("startPrbc"),
        "numPrbc": request.form.get("numPrbc"),
        "udCompHdr": request.form.get("udCompHdr"),
        "reserved": request.form.get("reserved"),
        "udCompParam": request.form.get("udCompParam"),
        "udCompParam": request.form.get("udCompParam"),
        "udCompParam": request.form.get("udCompParam"),
        "udCompParam": request.form.get("udCompParam"),
        "udCompParam": request.form.get("udCompParam"),
        "udCompParam": request.form.get("udCompParam"),
        "udCompParam": request.form.get("udCompParam"),
        "udCompParam": request.form.get("udCompParam"),
        "udCompParam": request.form.get("udCompParam"),
        "udCompParam": request.form.get("udCompParam"),
        "udCompParam": request.form.get("udCompParam"),
        "udCompParam": request.form.get("udCompParam"),
        "iSample": request.form.get("iSample"),
        "qSample": request.form.get("qSample"),
        "iSample": request.form.get("iSample"),
        "qSample": request.form.get("qSample"),
        "iSample": request.form.get("iSample"),
        "qSample": request.form.get("qSample"),
        "iSample": request.form.get("iSample"),
        "qSample": request.form.get("qSample"),
        "iSample": request.form.get("iSample"),
        "qSample": request.form.get("qSample"),
        "iSample": request.form.get("iSample"),
        "qSample": request.form.get("qSample"),
        "iSample": request.form.get("iSample"),
        "qSample": request.form.get("qSample"),
        "iSample": request.form.get("iSample"),
        "qSample": request.form.get("qSample"),
        "iSample": request.form.get("iSample"),
        "qSample": request.form.get("qSample"),
        "iSample": request.form.get("iSample"),
        "qSample": request.form.get("qSample"),
        "iSample": request.form.get("iSample"),
        "qSample": request.form.get("qSample"),
        "iSample": request.form.get("iSample"),
        "qSample": request.form.get("qSample"),
    }
    speed_value = int(request.form.get('speed'))

    ecpri_packet =  Ether(type=0xaefe) / ECpriCommonHeader(
        protocol_revision=int(request.form.get("protocol_revision")),
        reserved_1=int(request.form.get("reserved_1")),
        c_bit=int(request.form.get("c_bit")),
        message_type=int(request.form.get("message_type"),16),
        payload_size=111,
        ecpriRtcid=int(request.form.get("ecpriRtcid")),
        ecpriSeqid=int(request.form.get("ecpriSeqid")),
        )  / UPlaneHeader(
        dataDirection=int(request.form.get("dataDirection")),
        payloadVersion=int(request.form.get("payloadVersion")),
        filterIndex=int(request.form.get("filterIndex")),
        frameId=int(request.form.get("frameId")),
        subframeId=int(request.form.get("subframeId")),
        slotId=int(request.form.get("slotId")),
        symbolid=int(request.form.get("symbolid")),
        ) / UPlaneSection(
        sectionId=int(request.form.get("sectionId")),
        rb=int(request.form.get("rb")),
        symInc=int(request.form.get("symInc")),
        startPrbc=int(request.form.get("startPrbc")),
        numPrbc=int(request.form.get("numPrbc")),
        udCompHdr=int(request.form.get("udCompHdr")),
        reserved=int(request.form.get("reserved")),
        ) / UPlaneSection(
        udCompParam=int(request.form.get("udCompParam")),
        # udCompParam=int(request.form.get("udCompParam")),
        # udCompParam=int(request.form.get("udCompParam")),
        # udCompParam=int(request.form.get("udCompParam")),
        # udCompParam=int(request.form.get("udCompParam")),
        # udCompParam=int(request.form.get("udCompParam")),
        # udCompParam=int(request.form.get("udCompParam")),
        # udCompParam=int(request.form.get("udCompParam")),
        # udCompParam=int(request.form.get("udCompParam")),
        # udCompParam=int(request.form.get("udCompParam")),
        # udCompParam=int(request.form.get("udCompParam")),
        # udCompParam=int(request.form.get("udCompParam")),
        ) / ECpri(
        iSample=int(request.form.get("iSample"),16),
        qSample=int(request.form.get("qSample"),16),
        # iSample=int(request.form.get("iSample"),16),
        # qSample=int(request.form.get("qSample"),16),
        # iSample=int(request.form.get("iSample"),16),
        # qSample=int(request.form.get("qSample"),16),
        # iSample=int(request.form.get("iSample"),16),
        # qSample=int(request.form.get("qSample"),16),
        # iSample=int(request.form.get("iSample"),16),
        # qSample=int(request.form.get("qSample"),16),
        # iSample=int(request.form.get("iSample"),16),
        # qSample=int(request.form.get("qSample"),16),
        # iSample=int(request.form.get("iSample"),16),
        # qSample=int(request.form.get("qSample"),16),
        # iSample=int(request.form.get("iSample"),16),
        # qSample=int(request.form.get("qSample"),16),
        # iSample=int(request.form.get("iSample"),16),
        # qSample=int(request.form.get("qSample"),16),
        # iSample=int(request.form.get("iSample"),16),
        # qSample=int(request.form.get("qSample"),16),
        # iSample=int(request.form.get("iSample"),16),
        # qSample=int(request.form.get("qSample"),16),
        # iSample=int(request.form.get("iSample"),16),
        # qSample=int(request.form.get("qSample"),16),
        )
    sendpfast(ecpri_packet, pps=speed_value, iface='ens33', loop=1)

    wrpcap("u_packet.pcap", ecpri_packet)
    return render_template('result.html', data=u_plane)
################################u_plane###########
if __name__ == '__main__':
    app.run(debug=True)