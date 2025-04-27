/* 
 * Dual-Mode L2/L3 Network Switch
 * 
 * This P4 program implements a network switch with the following capabilities:
 * - L2 switching based on MAC addresses
 * - L3 filtering based on IPv4 source and destination addresses
 * - Prioritizes L3 filtering over L2 switching
 */

#include <core.p4>
#include <v1model.p4>

// Constants for protocol types
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP = 0x0806;
const bit<32> MAX_TABLE_SIZE = 1024;

//============================
// HEADER DEFINITIONS
//============================

// Ethernet header definition
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

// IPv4 header definition
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

// Metadata structure for internal processing
struct metadata {
    // Used to track whether L3 filtering has been applied
    bool l3_filtering_applied;
}

// Structure of parsed headers
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

//============================
// PARSER IMPLEMENTATION
//============================

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        // Initialize metadata
        meta.l3_filtering_applied = false;
        
        // Start parsing with the ethernet header
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        
        // Select which header to parse next based on the EtherType
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_ARP: accept;     // Accept ARP but don't process further
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

//============================
// CHECKSUM VERIFICATION
//============================

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // Verify IPv4 header checksum
        verify_checksum(
            hdr.ipv4.isValid(),
            {
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
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

//============================
// INGRESS PROCESSING
//============================

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // Action to drop the packet
    action drop() {
        mark_to_drop(standard_metadata);
    }

    // Action for L2 forwarding to a specific port
    action mac_forward(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    // Action for L2 broadcast via multicast group
    action mac_broadcast(bit<16> mcast_grp) {
        standard_metadata.mcast_grp = mcast_grp;
    }

    // Action for L3 forwarding to a specific port
    action ipv4_forward(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
        // Mark L3 filtering as applied
        meta.l3_filtering_applied = true;
    }

    // Table for L2 MAC-based forwarding
    table mac_forwarding {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            mac_forward;
            mac_broadcast;
            drop;
            NoAction;
        }
        size = MAX_TABLE_SIZE;
        default_action = mac_broadcast(1); // Default to broadcast for unknown MAC
    }

    // Table for L3 IPv4-based filtering
    table ipv4_filtering {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = MAX_TABLE_SIZE;
        default_action = ipv4_forward(0); // Default forward to port 0
    }

    apply {
        // Process IPv4 packets for L3 filtering
        if (hdr.ipv4.isValid()) {
            ipv4_filtering.apply();
        }
        
        // Only apply L2 forwarding if L3 filtering wasn't applied
        if (!meta.l3_filtering_applied) {
            mac_forwarding.apply();
        }
    }
}

//============================
// EGRESS PROCESSING
//============================

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    // No specific egress processing needed for this application
    apply { }
}

//============================
// CHECKSUM COMPUTATION
//============================

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // Update IPv4 header checksum if header is valid
        update_checksum(
            hdr.ipv4.isValid(),
            {
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
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

//============================
// DEPARSER
//============================

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // Emit headers in the correct order
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

//============================
// SWITCH IMPLEMENTATION
//============================

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;