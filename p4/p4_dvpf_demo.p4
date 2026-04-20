/*
 * Simplified BMv2-compatible P4 program inspired by P4-DVPF.
 *
 * What this demo does:
 * 1) Basic IPv4 forwarding.
 * 2) "New Stream" approximation:
 *    - hashes destination IP into a small set of buckets
 *    - tracks total packets and per-bucket packets with registers
 *    - if one bucket dominates the current window, marks packet suspicious
 * 3) "Hijacking" approximation:
 *    - carries the original destination in a custom verification header
 *    - if a later hop sees original_dst != current dstAddr, marks suspicious
 *
 * Notes:
 * - This is a teaching/demo implementation, not the exact paper implementation.
 * - It avoids complex entropy/log operations that are impractical in basic P4 targets.
 * - It targets the BMv2 v1model architecture.
 */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8>  PROTO_DVPF = 253;

const bit<32> WINDOW_SIZE = 128;
const bit<32> BUCKET_THRESHOLD = 58;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
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

header dvpf_t {
    bit<32> original_dst;
    bit<8>  suspicious;
    bit<8>  reserved1;
    bit<16> reserved2;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    dvpf_t     dvpf;
}

struct metadata {
    bit<1>  drop_now;
    bit<1>  suspicious;
    bit<8>  bucket_idx;
    bit<32> total_pkts;
    bit<32> bucket_pkts;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        meta.drop_now = 0;
        meta.suspicious = 0;
        meta.bucket_idx = 0;
        meta.total_pkts = 0;
        meta.bucket_pkts = 0;
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
        transition select(hdr.ipv4.protocol) {
            PROTO_DVPF: parse_dvpf;
            default: accept;
        }
    }

    state parse_dvpf {
        packet.extract(hdr.dvpf);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

register<bit<32>>(1) total_counter_reg;
register<bit<32>>(64) bucket_counter_reg;

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    bit<32> total_local;
    bit<32> bucket_local;
    bit<32> hash_value;

    action ipv4_forward(bit<48> dst_mac, bit<9> port) {
        hdr.ethernet.dstAddr = dst_mac;
        standard_metadata.egress_spec = port;
    }

    action drop() {
        meta.drop_now = 1;
        mark_to_drop(standard_metadata);
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

    table suspicious_policy {
        key = {
            meta.suspicious: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 2;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()) {

            if (!hdr.dvpf.isValid()) {
                hdr.dvpf.setValid();
                hdr.dvpf.original_dst = hdr.ipv4.dstAddr;
                hdr.dvpf.suspicious = 0;
                hdr.dvpf.reserved1 = 0;
                hdr.dvpf.reserved2 = 0;
                hdr.ipv4.protocol = PROTO_DVPF;
            } else {
                if (hdr.dvpf.original_dst != hdr.ipv4.dstAddr) {
                    meta.suspicious = 1;
                    hdr.dvpf.suspicious = 1;
                }
            }

            hash(hash_value, HashAlgorithm.crc16, (bit<32>)0,
                 { hdr.ipv4.dstAddr }, (bit<32>)64);
            meta.bucket_idx = (bit<8>)hash_value;

            total_counter_reg.read(total_local, 0);
            bucket_counter_reg.read(bucket_local, (bit<32>)meta.bucket_idx);

            total_local = total_local + 1;
            bucket_local = bucket_local + 1;

            total_counter_reg.write(0, total_local);
            bucket_counter_reg.write((bit<32>)meta.bucket_idx, bucket_local);

            meta.total_pkts = total_local;
            meta.bucket_pkts = bucket_local;

            if (total_local >= WINDOW_SIZE) {
                if (bucket_local >= BUCKET_THRESHOLD) {
                    meta.suspicious = 1;
                    hdr.dvpf.suspicious = 1;
                }

                total_counter_reg.write(0, 0);
                bucket_counter_reg.write((bit<32>)meta.bucket_idx, 0);
            }

            ipv4_lpm.apply();

            if (meta.drop_now == 0) {
    		suspicious_policy.apply();
	     }
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

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
                HashAlgorithm.csum16
            );
      }
 }

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.dvpf);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
