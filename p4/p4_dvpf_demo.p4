/*
 * Simplified BMv2-compatible P4 program inspired by P4-DVPF.
 *
 * This program implements:
 * 1) IPv4 forwarding
 * 2) Traffic anomaly detection (bucket dominance instead of entropy)
 * 3) Path verification (hijacking detection)
 */

#include <core.p4>     // Core P4 definitions
#include <v1model.p4> // BMv2 architecture (required for simple_switch)

/* =========================
   CONSTANTS
   ========================= */

// Ethernet type for IPv4 packets
const bit<16> TYPE_IPV4 = 0x0800;

// Custom protocol ID used to carry DVPF verification header
const bit<8>  PROTO_DVPF = 253;

// Number of packets in one observation window
const bit<32> WINDOW_SIZE = 128;

// Threshold: if one bucket exceeds this → suspicious
const bit<32> BUCKET_THRESHOLD = 58;


/* =========================
   HEADERS
   ========================= */

// Ethernet header (Layer 2)
header ethernet_t {
    bit<48> dstAddr;   // Destination MAC
    bit<48> srcAddr;   // Source MAC
    bit<16> etherType; // Protocol type
}

// IPv4 header (Layer 3)
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

// Custom DVPF header (for verification and detection)
header dvpf_t {
    bit<32> original_dst;  // Stores original destination IP
    bit<8>  suspicious;    // Flag for suspicious packet
    bit<8>  reserved1;
    bit<16> reserved2;
}


/* =========================
   STRUCTS
   ========================= */

// All packet headers grouped
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    dvpf_t     dvpf;
}

// Metadata used internally in the switch pipeline
struct metadata {
    bit<1>  drop_now;      // Drop flag
    bit<1>  suspicious;    // Suspicious flag
    bit<8>  bucket_idx;    // Hash bucket index
    bit<32> total_pkts;    // Total packets in window
    bit<32> bucket_pkts;   // Packets in current bucket
}


/* =========================
   PARSER
   ========================= */

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        // Initialize metadata values
        meta.drop_now = 0;
        meta.suspicious = 0;
        meta.bucket_idx = 0;
        meta.total_pkts = 0;
        meta.bucket_pkts = 0;

        // Move to Ethernet parsing
        transition parse_ethernet;
    }

    state parse_ethernet {
        // Extract Ethernet header from packet
        packet.extract(hdr.ethernet);

        // Decide next state based on EtherType
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4; // If IPv4 → parse IPv4
            default: accept;       // Otherwise stop parsing
        }
    }

    state parse_ipv4 {
        // Extract IPv4 header
        packet.extract(hdr.ipv4);

        // If custom DVPF protocol → parse it
        transition select(hdr.ipv4.protocol) {
            PROTO_DVPF: parse_dvpf;
            default: accept;
        }
    }

    state parse_dvpf {
        // Extract DVPF header
        packet.extract(hdr.dvpf);

        transition accept;
    }
}


/* =========================
   VERIFY CHECKSUM (unused)
   ========================= */

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { } // No verification performed
}


/* =========================
   REGISTERS (STATEFUL MEMORY)
   ========================= */

// Stores total packets in current window (1 cell only)
register<bit<32>>(1) total_counter_reg;

// Stores packet counts per bucket (64 buckets)
register<bit<32>>(64) bucket_counter_reg;


/* =========================
   INGRESS PIPELINE (MAIN LOGIC)
   ========================= */

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    bit<32> total_local;   // Local copy of total packets
    bit<32> bucket_local;  // Local copy of bucket packets
    bit<32> hash_value;    // Hash output


    // Action: forward packet
    action ipv4_forward(bit<48> dst_mac, bit<9> port) {
        hdr.ethernet.dstAddr = dst_mac;         // Rewrite destination MAC
        standard_metadata.egress_spec = port;   // Set output port
    }

    // Action: drop packet
    action drop() {
        meta.drop_now = 1;
        mark_to_drop(standard_metadata);
    }


    // Forwarding table (LPM)
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm; // Match on destination IP
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    // Policy table (drops suspicious packets)
    table suspicious_policy {
        key = {
            meta.suspicious: exact; // Match if packet is suspicious
        }
        actions = {
            drop;
            NoAction;
        }
        size = 2;
        default_action = NoAction();
    }


    apply {
        // Process only IPv4 packets
        if (hdr.ipv4.isValid()) {

            /* =========================
               HIJACKING DETECTION
               ========================= */

            // If no DVPF header exists → create it
            if (!hdr.dvpf.isValid()) {

                hdr.dvpf.setValid(); // Add header

                // Save original destination
                hdr.dvpf.original_dst = hdr.ipv4.dstAddr;

                // Initialize flags
                hdr.dvpf.suspicious = 0;
                hdr.dvpf.reserved1 = 0;
                hdr.dvpf.reserved2 = 0;

                // Change protocol to indicate DVPF header is present
                hdr.ipv4.protocol = PROTO_DVPF;

            } else {
                // Compare stored destination vs current destination
                if (hdr.dvpf.original_dst != hdr.ipv4.dstAddr) {

                    // If mismatch → mark as suspicious (possible hijacking)
                    meta.suspicious = 1;
                    hdr.dvpf.suspicious = 1;
                }
            }


            /* =========================
               TRAFFIC ANALYSIS (BUCKETS)
               ========================= */

            // Hash destination IP into bucket index
            hash(hash_value, HashAlgorithm.crc16, (bit<32>)0,
                 { hdr.ipv4.dstAddr }, (bit<32>)64);

            meta.bucket_idx = (bit<8>)hash_value;

            // Read total packet count from register
            total_counter_reg.read(total_local, 0);

            // Read bucket-specific count
            bucket_counter_reg.read(bucket_local, (bit<32>)meta.bucket_idx);

            // Increment counts
            total_local = total_local + 1;
            bucket_local = bucket_local + 1;

            // Write updated values back to registers
            total_counter_reg.write(0, total_local);
            bucket_counter_reg.write((bit<32>)meta.bucket_idx, bucket_local);

            // Save in metadata
            meta.total_pkts = total_local;
            meta.bucket_pkts = bucket_local;


            /* =========================
               WINDOW CHECK (ANOMALY DETECTION)
               ========================= */

            if (total_local >= WINDOW_SIZE) {

                // If one bucket dominates → suspicious (similar to entropy drop)
                if (bucket_local >= BUCKET_THRESHOLD) {
                    meta.suspicious = 1;
                    hdr.dvpf.suspicious = 1;
                }

                // Reset counters for next window
                total_counter_reg.write(0, 0);
                bucket_counter_reg.write((bit<32>)meta.bucket_idx, 0);
            }


            /* =========================
               FORWARDING + POLICY
               ========================= */

            // Apply routing table
            ipv4_lpm.apply();

            // If not already dropped → apply security policy
            if (meta.drop_now == 0) {
                suspicious_policy.apply();
            }
        }
    }
}


/* =========================
   EGRESS (EMPTY)
   ========================= */

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}


/* =========================
   CHECKSUM UPDATE
   ========================= */

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // Recalculate IPv4 checksum after modifications
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


/* =========================
   DEPARSE (OUTPUT PACKET)
   ========================= */

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet); // Send Ethernet header
        packet.emit(hdr.ipv4);     // Send IPv4 header
        packet.emit(hdr.dvpf);     // Send custom DVPF header
    }
}


/* =========================
   SWITCH PIPELINE
   ========================= */

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
