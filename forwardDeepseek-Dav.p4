#include <core.p4>
#include <v1model.p4>

/************* HEADER DEFINITIONS *************/
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> ethType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8>  hwAddrLen;
    bit<8>  protoAddrLen;
    bit<16> op;
    bit<48> senderHwAddr;
    bit<32> senderProtoAddr;
    bit<48> targetHwAddr;
    bit<32> targetProtoAddr;
}

/************* STRUCT DEFINITIONS *************/
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    arp_t      arp;
}

struct metadata {
    bit<9> egress_port;
}

/************* PARSER *************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethType) {
            0x0800: parse_ipv4;
            0x0806: parse_arp;
            default: accept;
        }
    }
    
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
    
    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
}

/************* INGRESS PROCESSING *************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    /* Action Definitions */
    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
        meta.egress_port = port;
    }
    
    action broadcast() {
        standard_metadata.mcast_grp = 1;
    }
    
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    /* Checksum calculation */
    action compute_ipv4_checksum() {
        bit<16> checksum = 0;
        hdr.ipv4.hdrChecksum = 0;
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
            checksum,
            HashAlgorithm.csum16
        );
        hdr.ipv4.hdrChecksum = checksum;
    }
    
    /* Table Definitions */
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }
    
    table ethernet_exact {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            forward;
            broadcast;
            drop;
        }
        size = 1024;
        default_action = broadcast();
    }
    
    apply {
        /* Process IPv4 packets first */
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            if (standard_metadata.egress_spec != 0) {
                hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
                compute_ipv4_checksum();
            }
        } else {
            ethernet_exact.apply();
        }
    }
}

/************* EGRESS PROCESSING *************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        // No egress processing required
    }
}

/************* DEPARSER *************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        if (hdr.ipv4.isValid()) {
            packet.emit(hdr.ipv4);
        }
        if (hdr.arp.isValid()) {
            packet.emit(hdr.arp);
        }
    }
}

/************* MAIN PIPELINE *************/
V1Switch(
    MyParser(),
    MyIngress(),
    MyEgress(),
    MyDeparser()
) main;