//-----------------------------------------------------------------------------
// P4-16 program for BMv2 (v1model)
//-----------------------------------------------------------------------------

#include <v1model.p4>

//-----------------------------------------------------------------------------
// Header Definitions
//-----------------------------------------------------------------------------

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> ethType;
}

header ipv4_t {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  totalLen;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  fragOffset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdrChecksum;
    bit<32>  srcAddr;
    bit<32>  dstAddr;
}

//-----------------------------------------------------------------------------
// Metadata & Bundle
//-----------------------------------------------------------------------------

struct metadata_t {
    bit<9> egress_port;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

//-----------------------------------------------------------------------------
// Parser
//-----------------------------------------------------------------------------

parser MyParser(
    packet_in           packet,
    out headers_t       hdr,
    inout metadata_t    meta,
    inout standard_metadata_t standard_metadata
) {
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
        transition accept;
    }
}

//-----------------------------------------------------------------------------
// Verify Checksum (no-op)
//-----------------------------------------------------------------------------

control MyVerifyChecksum(
    inout headers_t    hdr,
    inout metadata_t   meta
) {
    apply { }
}

//-----------------------------------------------------------------------------
// Ingress Pipeline
//-----------------------------------------------------------------------------

control MyIngress(
    inout headers_t            hdr,
    inout metadata_t           meta,
    inout standard_metadata_t  standard_metadata
) {
    // Actions
    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action broadcast() {
        standard_metadata.mcast_grp = 1;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    // Tables
    table ethernet_exact {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            forward;
            broadcast;
            drop;
        }
        default_action = broadcast();
        size = 1024;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            forward;
            drop;
        }
        default_action = drop();
        size = 1024;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        } else if (hdr.ethernet.isValid()) {
            ethernet_exact.apply();
        }
    }
}

//-----------------------------------------------------------------------------
// Egress Pipeline
//-----------------------------------------------------------------------------

control MyEgress(
    inout headers_t            hdr,
    inout metadata_t           meta,
    inout standard_metadata_t  standard_metadata
) {
    apply { }
}

//-----------------------------------------------------------------------------
// Compute Checksum
//-----------------------------------------------------------------------------

control MyComputeChecksum(
    inout headers_t  hdr,
    inout metadata_t meta
) {
    apply {
        update_checksum(
            /* always recompute */      true,
            /* fields to include */     {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            /* writeback checksum */    hdr.ipv4.hdrChecksum,
            /* algorithm */             HashAlgorithm.csum16
        );
    }
}

//-----------------------------------------------------------------------------
// Deparser
//-----------------------------------------------------------------------------

control MyDeparser(
    packet_out     packet,
    in headers_t   hdr
) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

//-----------------------------------------------------------------------------
// Switch Instantiation
//-----------------------------------------------------------------------------

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
