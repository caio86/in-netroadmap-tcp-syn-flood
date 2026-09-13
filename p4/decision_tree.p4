/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> PROTO_INT = 253;
const bit<8> PROTO_TCP = 6;

#define MAX_HOPS 10

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_v;
typedef bit<32> ip4Addr_v;

typedef bit<16> flowID_t;
typedef bit<32> int_t;
typedef bit<48> timestamp_t;

typedef bit<31> switchID_v;
typedef bit<9> ingress_port_v;
typedef bit<9> egress_port_v;
typedef bit<9>  egressSpec_v;
typedef bit<48>  ingress_global_timestamp_v;
typedef bit<48>  egress_global_timestamp_v;
typedef bit<32>  enq_timestamp_v;
typedef bit<19> enq_qdepth_v;
typedef bit<32> deq_timedelta_v;
typedef bit<19> deq_qdepth_v;

header ethernet_h {
    macAddr_v dstAddr;
    macAddr_v srcAddr;
    bit<16>   etherType;
}

header ipv4_h {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_v srcAddr;
    ip4Addr_v dstAddr;
}

header tcp_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header nodeCount_h{
    bit<16>  count;
}

header InBandNetworkTelemetry_h {
    switchID_v swid;
    ingress_port_v ingress_port;
    egress_port_v egress_port;
    egressSpec_v egress_spec;
    ingress_global_timestamp_v ingress_global_timestamp;
    egress_global_timestamp_v egress_global_timestamp;
    enq_timestamp_v enq_timestamp;
    enq_qdepth_v enq_qdepth;
    deq_timedelta_v deq_timedelta;
    deq_qdepth_v deq_qdepth;
}

struct ingress_metadata_t {
    bit<16>  count;
}

struct parser_metadata_t {
    bit<16>  remaining;
}

struct metadata {
    ingress_metadata_t   ingress_metadata;
    parser_metadata_t   parser_metadata;
    flowID_t flowID;
    bit<16> window;
    bit<14> action_select1;
    bit<32> frame_size;
    bit<14> action_select2;
    bit<48> ipi;
    bit<14> action_select3;
    bit<8> diffserv;
    bit<14> action_select4;
    bit<3>  result;
}

struct headers {
    ethernet_h         ethernet;
    ipv4_h             ipv4;
    tcp_h              tcp;
    nodeCount_h        nodeCount;
    InBandNetworkTelemetry_h[MAX_HOPS] INT;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            PROTO_TCP: parse_tcp;
            PROTO_INT: parse_count;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_count{
        packet.extract(hdr.nodeCount);
        meta.parser_metadata.remaining = hdr.nodeCount.count;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default: parse_int;
        }
    }

    state parse_int {
        packet.extract(hdr.INT.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining  - 1;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default: parse_int;
        }
    }
}

/*************************************************************************
************ C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
************** I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    register<bit<48>>(0xffff) ipi_register;
    register<bit<48>>(0xffff) lpt_register;

    counter(2, CounterType.packets) resultCounter;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action find_flowID_ipv4() {
        bit<1> base = 0;
        bit<16> max = 0xffff;
        bit<16> hash_result;

        hash(
            hash_result,
            HashAlgorithm.crc16,
            base,
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.ipv4.protocol
            },
            max
        );

        meta.flowID = hash_result;
    }

    action set_actionselect1(bit<14> featurevalue1) {
        meta.action_select1 = featurevalue1;
    }

    table feature1_exact {
        key = {
            meta.window: range ;
        }
        actions = {
            NoAction;
            set_actionselect1;
        }
        size = 1024;
    }
    action set_actionselect2(bit<14> featurevalue2) {
        meta.action_select2 = featurevalue2;
    }

    table feature2_exact {
        key = {
            meta.frame_size: range ;
        }
        actions = {
            NoAction;
            set_actionselect2;
        }
        size = 1024;
    }
    action set_actionselect3(bit<14> featurevalue3) {
        meta.action_select3 = featurevalue3;
    }

    table feature3_exact {
        key = {
            meta.ipi: range ;
        }
        actions = {
            NoAction;
            set_actionselect3;
        }
        size = 1024;
    }
    action set_actionselect4(bit<14> featurevalue4) {
        meta.action_select4 = featurevalue4;
    }

    table feature4_exact {
        key = {
            meta.diffserv: range ;
        }
        actions = {
            NoAction;
            set_actionselect4;
        }
        size = 1024;
    }

    action set_result(bit<3> result) {
        meta.result = result;
    }

    table classify_exact {
        key = {
            meta.action_select1: range ;
            meta.action_select2: range ;
            meta.action_select3: range ;
            meta.action_select4: range ;
        }
        actions = {
            set_result;
            NoAction;
            drop;
        }
    }

    action extract_features() {
        meta.window = hdr.tcp.window;
        meta.frame_size = standard_metadata.packet_length;
        timestamp_t ipi = 0;
        int<48> diff_ts = 0;

        timestamp_t current_time = standard_metadata.ingress_global_timestamp;
        timestamp_t last_packet_time = 0;

        ipi_register.read(ipi, (bit<32>)meta.flowID);
        lpt_register.read(last_packet_time, (bit<32>)meta.flowID);

        if (last_packet_time == 0) {
            last_packet_time = current_time;
        } else {
            /* IPI */
            ipi = current_time - last_packet_time;
            last_packet_time = current_time;
        }

        ipi_register.write((bit<32>)meta.flowID, ipi);
        lpt_register.write((bit<32>)meta.flowID, last_packet_time);

        meta.ipi = ipi;
        meta.diffserv = hdr.ipv4.diffserv;
    }

    action ipv4_forward(macAddr_v dstAddr, egressSpec_v port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        meta.flowID = 0;
        meta.result = 0;
        if (hdr.ipv4.isValid()) {
            if (hdr.tcp.isValid() && !hdr.nodeCount.isValid()) {
                find_flowID_ipv4();
                extract_features();

                feature1_exact.apply();
                feature2_exact.apply();
                feature3_exact.apply();
                feature4_exact.apply();

                classify_exact.apply();
                resultCounter.count((bit<32>)meta.result);
            }

            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
**************** E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action add_swtrace(switchID_v swid) {
        hdr.nodeCount.count = hdr.nodeCount.count + 1;
        hdr.INT.push_front(1);
        hdr.INT[0].setValid();
        hdr.INT[0].swid = swid;
        hdr.INT[0].ingress_port = (ingress_port_v)standard_metadata.ingress_port;
        hdr.INT[0].ingress_global_timestamp = (ingress_global_timestamp_v)standard_metadata.ingress_global_timestamp;
        hdr.INT[0].egress_port = (egress_port_v)standard_metadata.egress_port;
        hdr.INT[0].egress_spec = (egressSpec_v)standard_metadata.egress_spec;
        hdr.INT[0].egress_global_timestamp = (egress_global_timestamp_v)standard_metadata.egress_global_timestamp;
        hdr.INT[0].enq_timestamp = (enq_timestamp_v)standard_metadata.enq_timestamp;
        hdr.INT[0].enq_qdepth = (enq_qdepth_v)standard_metadata.enq_qdepth;
        hdr.INT[0].deq_timedelta = (deq_timedelta_v)standard_metadata.deq_timedelta;
        hdr.INT[0].deq_qdepth = (deq_qdepth_v)standard_metadata.deq_qdepth;

        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 32;
    }

    table swtrace {
        actions = {
            add_swtrace;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
        if (hdr.nodeCount.isValid()) {
            swtrace.apply();
        }
    }
}

/*************************************************************************
************* C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
    update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
*********************** D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.nodeCount);
        packet.emit(hdr.INT);
    }
}

/*************************************************************************
*********************** S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;