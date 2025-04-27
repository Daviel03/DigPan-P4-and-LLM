/*-----------------------------------------------------------------------------
 *  BMv2 / v1model  •  Ethernet + IPv4 L2/L3 switch
 *  (No conditionals in the deparser!)
 *---------------------------------------------------------------------------*/
#include <v1model.p4>

/*--- 1. Header Types -------------------------------------------------------*/
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

/*--- 2. Metadata -----------------------------------------------------------*/
struct metadata_t {
    bit<9> egress_port;
}

/* Bundle */
struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

/*--- 3. Parser -------------------------------------------------------------*/
parser MyParser(packet_in packet,
                out headers_t  hdr,
                inout metadata_t meta,
                inout standard_metadata_t stdmeta)
{
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethType) {
            0x0800: parse_ipv4;   // IPv4
            0x0806: parse_arp;    // ARP (ignored)
            default: accept;
        }
    }

    state parse_ipv4 { packet.extract(hdr.ipv4); transition accept; }
    state parse_arp  { transition accept; }
}

/*--- 4. VerifyChecksum (signature: hdr, meta) ------------------------------*/
control MyVerifyChecksum(inout headers_t hdr,
                         inout metadata_t meta)
{
    apply { }           // nothing to verify in this program
}

/*--- 5. Ingress Pipeline ---------------------------------------------------*/
control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t stdmeta)
{
    /* Actions */
    action forward(bit<9> port) {
        meta.egress_port    = port;
        stdmeta.egress_spec = port;
    }
    action broadcast()           { stdmeta.mcast_grp = 1; }
    action drop()                { mark_to_drop(stdmeta); }

    /* Tables */
    table ethernet_exact {
        key = { hdr.ethernet.dstAddr : exact; }
        actions = { forward; broadcast; drop; }
        size = 1024;
        default_action = broadcast();
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr : lpm; }
        actions = { forward; drop; }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        } else if (hdr.ethernet.isValid()) {
            ethernet_exact.apply();
        }
    }
}

/*--- 6. Egress (empty) -----------------------------------------------------*/
control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t stdmeta)
{
    apply { }
}

/*--- 7. ComputeChecksum (signature: hdr, meta) -----------------------------*/
control MyComputeChecksum(inout headers_t hdr,
                          inout metadata_t meta)
{
    apply {
        update_checksum(
            hdr.ipv4.isValid(),                       // condition
            {                                         // data tuple
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
            hdr.ipv4.hdrChecksum,                     // checksum field
            HashAlgorithm.csum16                      // algorithm
        );
    }
}

/*--- 8. Deparser (NO IF-STATEMENTS) ---------------------------------------*/
control MyDeparser(packet_out packet,
                   in headers_t hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);    // emitted only when header is valid
    }
}

/*--- 9. Switch Package -----------------------------------------------------*/
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
