#include <v1model.p4>

// Ethernet Header
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> ethType;
}

// IPv4 Header
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

// Metadata
struct metadata_t {
    bit<9> egress_port;
}

// Headers
struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

// Parser
parser MyParser(packet_in packet,
                out headers_t headers,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(headers.ethernet);
        transition select(headers.ethernet.ethType) {
            0x0800: parse_ipv4;
            0x0806: accept;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(headers.ipv4);
        transition accept;
    }
}

// Empty Checksum Verification
control MyVerifyChecksum(inout headers_t headers,
                         inout metadata_t meta) {
    apply { }
}

// Actions
action forward(inout metadata_t meta, bit<9> port) {
    meta.egress_port = port;
}

action broadcast(inout standard_metadata_t standard_metadata) {
    standard_metadata.egress_spec = 1; // multicast group 1
}

action drop(inout standard_metadata_t standard_metadata) {
    mark_to_drop(standard_metadata);
}

// Ingress Control
control MyIngress(inout headers_t headers,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    table ipv4_lpm {
        key = {
            headers.ipv4.dstAddr: lpm;
        }
        actions = {
            forward;
            drop;
        }
        size = 1024;
        default_action = drop(standard_metadata);
    }

    table ethernet_exact {
        key = {
            headers.ethernet.dstAddr: exact;
        }
        actions = {
            forward;
            broadcast;
            drop;
        }
        size = 1024;
        default_action = broadcast(standard_metadata);
    }

    apply {
        if (headers.ipv4.isValid()) {
            ipv4_lpm.apply();
        } else {
            ethernet_exact.apply();
        }

        standard_metadata.egress_spec = meta.egress_port;
    }
}

// Egress (empty)
control MyEgress(inout headers_t headers,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

// Checksum Recalculation
control MyComputeChecksum(inout headers_t headers,
                          inout metadata_t meta) {
    apply {
        update_checksum(
            headers.ipv4.isValid(),
            {
                headers.ipv4.version,
                headers.ipv4.ihl,
                headers.ipv4.diffserv,
                headers.ipv4.totalLen,
                headers.ipv4.identification,
                headers.ipv4.flags,
                headers.ipv4.fragOffset,
                headers.ipv4.ttl,
                headers.ipv4.protocol,
                headers.ipv4.srcAddr,
                headers.ipv4.dstAddr
            },
            headers.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

// Deparser
control MyDeparser(packet_out packet,
                   in headers_t headers) {
    apply {
        packet.emit(headers.ethernet);
        if (headers.ipv4.isValid()) {
            packet.emit(headers.ipv4);
        }
    }
}

// Main Program Block
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
