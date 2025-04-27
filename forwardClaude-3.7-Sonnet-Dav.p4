/* 
 * Basic Network Switch in P4
 * 
 * This program implements a basic network switch that handles:
 * - Ethernet (L2) packet forwarding
 * - IPv4 (L3) packet forwarding
 * 
 * It uses the v1model architecture and follows a standard pipeline:
 * Parser → Verify Checksum → Ingress → Egress → Compute Checksum → Deparser
 */

#include <core.p4>
#include <v1model.p4>

/* Constants */
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP = 0x0806;
const bit<32> MAX_PORT_COUNT = 512;

/* Header definitions */
// Ethernet header
header ethernet_t {
    bit<48> dstAddr;     // Destination MAC address
    bit<48> srcAddr;     // Source MAC address
    bit<16> etherType;   // Ethertype field
}

// IPv4 header
header ipv4_t {
    bit<4>  version;     // IP version (4 for IPv4)
    bit<4>  ihl;         // Internet header length
    bit<8>  diffserv;    // DSCP + ECN fields
    bit<16> totalLen;    // Total length
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;         // Time to live
    bit<8>  protocol;    // Protocol field
    bit<16> hdrChecksum; // Header checksum
    bit<32> srcAddr;     // Source IP address
    bit<32> dstAddr;     // Destination IP address
}

// Custom metadata structure
struct metadata {
    // We'll keep this empty for now, but you can add custom fields here
    // for passing information between pipeline stages
    bit<1> is_routed;    // Flag to track if packet has been routed (for priority handling)
}

// Structure of parsed headers
struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
}

/*************************************************************************
 *                            PARSER                                     *
 *************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start {
        // Initialize metadata
        meta.is_routed = 0;
        
        // Jump to parsing Ethernet
        transition parse_ethernet;
    }
    
    state parse_ethernet {
        // Extract the Ethernet header
        packet.extract(hdr.ethernet);
        
        // Decide next state based on EtherType
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_ARP: accept;     // Accept ARP packets without additional parsing
            default: accept;           // Accept other types without additional parsing
        }
    }
    
    state parse_ipv4 {
        // Extract the IPv4 header
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

/*************************************************************************
 *                       CHECKSUM VERIFICATION                           *
 *************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // Skip checksum verification on ingress as per requirements
        // In a production environment, you might want to verify checksums
    }
}

/*************************************************************************
 *                           INGRESS PROCESSING                          *
 *************************************************************************/

control MyIngress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    // Action to drop the packet
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    // L2 (Ethernet) forwarding actions
    
    // Forward to a specific port
    action l2_forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    
    // Broadcast packet (for unknown destinations)
    action l2_broadcast() {
        // Use multicast group 1 (this needs to be configured in the control plane)
        standard_metadata.mcast_grp = 1;
    }
    
    // L3 (IPv4) forwarding actions
    
    // Forward IPv4 packet to next hop
    action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        // Set the egress port
        standard_metadata.egress_spec = port;
        
        // Update the Ethernet source address to our address
        // The actual MAC address would be configured by the control plane
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        
        // Update the Ethernet destination address to the next hop's MAC
        hdr.ethernet.dstAddr = dstAddr;
        
        // Decrement TTL
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        
        // Mark packet as routed (for priority handling)
        meta.is_routed = 1;
    }
    
    // L2 switching table
    table mac_forwarding {
        key = {
            hdr.ethernet.dstAddr: exact;  // Exact match on destination MAC
        }
        actions = {
            l2_forward;      // Forward to a specific port
            l2_broadcast;    // Broadcast for unknown destination
            drop;            // Drop the packet
        }
        size = 1024;         // Support up to 1024 MAC addresses
        default_action = l2_broadcast();  // Broadcast if no match (unknown MAC)
    }
    
    // L3 routing table
    table ipv4_routing {
        key = {
            hdr.ipv4.dstAddr: lpm;  // Longest prefix match on destination IP
        }
        actions = {
            ipv4_forward;    // Forward to next hop
            drop;            // Drop the packet
        }
        size = 1024;         // Support up to 1024 routes
        default_action = drop();  // Drop if no matching route
    }
    
    // Main ingress logic
    apply {
        // Only process IPv4 packets with valid headers for routing
        if (hdr.ipv4.isValid() && hdr.ethernet.isValid()) {
            // Try to route at L3 first (priority handling)
            ipv4_routing.apply();
        }
        
        // If packet wasn't routed at L3, try L2 switching
        if (meta.is_routed == 0 && hdr.ethernet.isValid()) {
            mac_forwarding.apply();
        }
    }
}

/*************************************************************************
 *                           EGRESS PROCESSING                           *
 *************************************************************************/

control MyEgress(inout headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    // Keep egress logic simple for this basic switch
    apply { 
        // No specific egress operations needed for our basic switch
    }
}

/*************************************************************************
 *                       CHECKSUM COMPUTATION                            *
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // Recompute IPv4 header checksum for outgoing packets
        // This is needed because we modify the TTL field in ipv4_forward
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

/*************************************************************************
 *                              DEPARSER                                 *
 *************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // Emit headers in the correct order
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
 *                              SWITCH                                   *
 *************************************************************************/

// Instantiate the switch
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;