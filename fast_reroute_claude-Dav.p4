/* 
 * P4 Resilient Networking Switch with Fault Tolerance
 * Based on v1model architecture
 * Implements Ethernet, IPv4, and ARP protocol support with primary/backup path routing
 */

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP = 0x0806;
const bit<8>  PROTOCOL_ICMP = 1;
const bit<8>  PROTOCOL_TCP = 6;
const bit<8>  PROTOCOL_UDP = 17;

/* Maximum number of ports supported by the switch */
const bit<32> MAX_PORTS = 512;

/* Maximum number of routes supported by the switch */
const bit<32> MAX_ROUTES = 1024;

/* Link status values */
const bit<1> LINK_DOWN = 0;
const bit<1> LINK_UP = 1;

/* Special IP address for monitoring (h1->h2 traffic) */
const bit<32> MONITOR_DST_IP = 0x0A000201; // 10.0.2.1

/*************************************************************************
 * HEADER DEFINITIONS
 *************************************************************************/

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ipv4Addr_t;

/* Ethernet header */
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

/* IPv4 header */
header ipv4_t {
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
    ipv4Addr_t srcAddr;
    ipv4Addr_t dstAddr;
}

/* ARP header */
header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8>  hwAddrLen;
    bit<8>  protoAddrLen;
    bit<16> opcode;
    macAddr_t srcMacAddr;
    ipv4Addr_t srcIPAddr;
    macAddr_t dstMacAddr;
    ipv4Addr_t dstIPAddr;
}

/* Headers structure */
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    arp_t      arp;
}

/* Metadata structure for carrying routing information between pipeline stages */
struct metadata {
    /* Routing information */
    bit<1>    use_backup_path;     // Flag to indicate if backup path should be used
    port_t    primary_egress_port; // Primary path egress port
    port_t    backup_egress_port;  // Backup path egress port
    bit<1>    is_local_delivery;   // Flag for packets destined to switch
    bit<1>    has_backup_route;    // Flag to indicate if a backup route exists
    bit<1>    is_monitored_flow;   // Flag for h1->h2 traffic monitoring
}

/*************************************************************************
 * PARSER
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
            TYPE_ARP: parse_arp;
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

/*************************************************************************
 * CHECKSUM VERIFICATION
 *************************************************************************/

control MyVerifyChecksum(inout headers hdr,
                         inout metadata meta) {
    apply {
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
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
 * INGRESS PROCESSING
 *************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* Register for tracking link status (up=1, down=0) */
    register<bit<1>>(MAX_PORTS) link_status;

    /* Register for tracking active egress ports */
    register<bit<32>>(MAX_PORTS) active_egress_ports;

    /* Counter for backup path usage */
    counter(MAX_ROUTES, CounterType.packets) backup_path_counter;

    /* Counter for dropped packets due to missing backup routes */
    counter(1, CounterType.packets) dropped_packets_counter;

    /* Counter for monitoring traffic between h1 and h2 */
    counter(1, CounterType.packets_and_bytes) h1_h2_traffic_counter;

    /* Action to drop a packet */
    action drop() {
        mark_to_drop(standard_metadata);
        dropped_packets_counter.count(0);
    }

    /* IPv4 forwarding action with primary and backup paths */
    action ipv4_forward(macAddr_t dstAddr, port_t primary_port, port_t backup_port) {
        /* Set the source and destination MAC addresses */
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;

        /* Store the primary and backup ports in metadata */
        meta.primary_egress_port = primary_port;
        meta.backup_egress_port = backup_port;
        meta.has_backup_route = 1; // This entry has a backup route

        /* Check if we need to use the backup path */
        bit<1> port_status;
        link_status.read(port_status, (bit<32>)primary_port);

        if (port_status == LINK_DOWN) {
            /* Primary link is down, use backup */
            standard_metadata.egress_spec = backup_port;
            meta.use_backup_path = 1;
            backup_path_counter.count((bit<32>)standard_metadata.egress_spec);
        } else {
            /* Primary link is up, use it */
            standard_metadata.egress_spec = primary_port;
            meta.use_backup_path = 0;
        }

        /* Decrement TTL */
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        /* Record active egress port usage */
        active_egress_ports.write((bit<32>)standard_metadata.egress_spec, 1);
    }

    /* IPv4 forwarding action with only primary path */
    action ipv4_forward_no_backup(macAddr_t dstAddr, port_t primary_port) {
        /* Set the source and destination MAC addresses */
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;

        /* Store the primary port in metadata */
        meta.primary_egress_port = primary_port;
        meta.has_backup_route = 0; // This entry has no backup route

        /* Check if primary link is down */
        bit<1> port_status;
        link_status.read(port_status, (bit<32>)primary_port);

        if (port_status == LINK_DOWN) {
            /* Primary link is down and no backup, drop packet */
            drop();
        } else {
            /* Primary link is up, use it */
            standard_metadata.egress_spec = primary_port;
            meta.use_backup_path = 0;
        }

        /* Decrement TTL */
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        /* Record active egress port usage */
        active_egress_ports.write((bit<32>)standard_metadata.egress_spec, 1);
    }

    /* Action for local delivery to the switch itself */
    action local_delivery() {
        meta.is_local_delivery = 1;
        /* Use CPU port for local delivery */
        standard_metadata.egress_spec = 0;
    }

    /* ARP response action */
    action send_arp_reply(macAddr_t srcMac, ipv4Addr_t srcIP) {
        /* Swap MAC addresses */
        macAddr_t tmpMac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = srcMac;
        hdr.ethernet.dstAddr = tmpMac;

        /* Set ARP operation to REPLY (2) */
        hdr.arp.opcode = 2;

        /* Set MAC addresses in ARP header */
        hdr.arp.dstMacAddr = hdr.arp.srcMacAddr;
        hdr.arp.srcMacAddr = srcMac;

        /* Set IPs in ARP header */
        ipv4Addr_t tmpIP = hdr.arp.srcIPAddr;
        hdr.arp.srcIPAddr = srcIP;
        hdr.arp.dstIPAddr = tmpIP;

        /* Send back to the same port it came from */
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    /* Primary routing table with LPM for IPv4 */
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            ipv4_forward_no_backup;
            local_delivery;
            drop;
        }
        size = MAX_ROUTES;
        default_action = drop();
    }

    /* ARP responder table */
    table arp_responder {
        key = {
            hdr.arp.dstIPAddr: exact;
            hdr.arp.opcode: exact; // 1 for request
        }
        actions = {
            send_arp_reply;
            drop;
        }
        size = 16; // Switch can respond for 16 different IPs
    }

    apply {
        /* Reset metadata */
        meta.use_backup_path = 0;
        meta.is_local_delivery = 0;
        meta.has_backup_route = 0;
        meta.is_monitored_flow = 0;

        if (hdr.ipv4.isValid()) {
            /* Check if this is a monitored flow (h1->h2) */
            if (hdr.ipv4.dstAddr == MONITOR_DST_IP) {
                meta.is_monitored_flow = 1;
                h1_h2_traffic_counter.count(0);
            }

            /* Apply IPv4 routing */
            if (hdr.ipv4.ttl > 1) {
                ipv4_lpm.apply();
            } else {
                drop();
            }
        } else if (hdr.arp.isValid()) {
            /* Process ARP packets */
            arp_responder.apply();
        }
    }
}

/*************************************************************************
 * EGRESS PROCESSING
 *************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        /* Additional processing could be added here */
    }
}

/*************************************************************************
 * CHECKSUM COMPUTATION
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
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
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
 * DEPARSER
 *************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* Emit headers in order */
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.arp);
    }
}

/*************************************************************************
 * SWITCH INSTANCE
 *************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;