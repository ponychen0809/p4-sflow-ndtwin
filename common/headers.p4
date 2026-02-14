/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2019-present Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks, Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.  Dissemination of
 * this information or reproduction of this material is strictly forbidden unless
 * prior written permission is obtained from Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a written
 * agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

#ifndef _HEADERS_
#define _HEADERS_

#define DATA_BLOCK_LEN 32

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<12> vlan_id_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

typedef bit<16>  pkt_type_t;
const pkt_type_t PKT_TYPE_NORMAL = 1;
const pkt_type_t PKT_TYPE_MIRROR = 2;

header mirror_h {
    bit<16> packet_type;
}

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header vlan_tag_h {
    bit<3> pcp;
    bit<1> cfi;
    vlan_id_t vid;
    bit<16> ether_type;
}

header mpls_h {
    bit<20> label;
    bit<3> exp;
    bit<1> bos;
    bit<8> ttl;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ipv6_h {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    ipv6_addr_t src_addr;
    ipv6_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header icmp_h {
    bit<8> type_;
    bit<8> code;
    bit<16> hdr_checksum;
}

// Address Resolution Protocol -- RFC 6747
header arp_h {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8> hw_addr_len;
    bit<8> proto_addr_len;
    bit<16> opcode;
    // ...
}

// Segment Routing Extension (SRH) -- IETFv7
header ipv6_srh_h {
    bit<8> next_hdr;
    bit<8> hdr_ext_len;
    bit<8> routing_type;
    bit<8> seg_left;
    bit<8> last_entry;
    bit<8> flags;
    bit<16> tag;
}

// VXLAN -- RFC 7348
header vxlan_h {
    bit<8> flags;
    bit<24> reserved;
    bit<24> vni;
    bit<8> reserved2;
}

// Generic Routing Encapsulation (GRE) -- RFC 1701
header gre_h {
    bit<1> C;
    bit<1> R;
    bit<1> K;
    bit<1> S;
    bit<1> s;
    bit<3> recurse;
    bit<5> flags;
    bit<3> version;
    bit<16> proto;
}

struct my_metadata_t {
    bit<32> ingress_port;
    bit<32> egress_port;
    bit<32> pkt_len;
    bit<32> protocol;
    bit<32> src_ip;
    bit<32> dst_ip;
    bit<32> src_port;
    bit<32> dst_port;
    bit<32> tcp_flag;
    bit<32> tos;
    bit<32> ctrl_ts;
    MirrorId_t mirror_session;
    bit<16>  sample_ing_port;
    bit<32>  sampling_rate;
    bit<32>  pkt_count;
    bit<32> sampled_count;
    bit<16> frame_length;
    bit<32> sample_type;
    bit<16> tmp_frame_len;
    bit<32> cpu_ingress_port;
    bit<8>  saved_count;
    bit<16> sample_idx;
    bit<64> in_byte_count;
    bit<64> out_byte_count;
    bit<32> in_ucast_count;
    bit<32> in_multi_count;
    bit<32> in_broad_count;
    bit<32> out_ucast_count;
    bit<32> out_multi_count;
    bit<32> out_broad_count;
    bit<32> ucast_count;
    bit<32> agent_ip;
    bit<32> input_if;
    bit<1024> raw_128_data;
    bit<512> raw_64_data;
    bit<256> raw_32_data;
    bit<32> header_length;
    bit<32> record_length;
    bit<32> sample_length;
    
    bit<16> ip_len;
    bit<16> udp_len;
    bit<1> agent_status;
    bit<1>  recirc;

    
}



header sflow_t {  //28byte
    bit<32> version;
    bit<32> address_type;
    bit<32> agent_addr;
    bit<32> sub_agent_id;
    bit<32> sequence_number;
    bit<32> uptime;
    bit<32> samples;
}

header sflow_flow_t { //40byte
    bit<32> sample_type;
    bit<32> sample_length;
    bit<32> sample_seq_num;
    bit<32> source_id;
    bit<32> sampling_rate;
    bit<32> sample_pool;
    bit<32> drops;
    bit<32> input_if;
    bit<32> output_if;
    bit<32> record_count;
}
header sflow_counter_t { //40byte
    bit<32> sample_type;
    bit<32> sample_length;
    bit<32> sample_seq_num;
    bit<32> source_id;
    bit<32> record_count;    
}

header sflow_eth_record { //152byte
    bit<32> record_type;
    bit<32> record_length;
    bit<32> dot3StatsAlignmentErrors;
    bit<32> dot3StatsFCSErrors;
    bit<32> dot3StatsSingleCollisionFrames;
    bit<32> dot3StatsMultipleCollisionFrames;
    bit<32> dot3StatsSQETestErrors;
    bit<32> dot3StatsDeferredTransmissions;
    bit<32> dot3StatsLateCollisions;
    bit<32> dot3StatsExcessiveCollisions;
    bit<32> dot3StatsInternalMacTxErrors;
    bit<32> dot3StatsCarrierSenseErrors;
    bit<32> dot3StatsFrameTooLongs;
    bit<32> dot3StatsInternalMacRxErrors;
    bit<32> dot3StatsSymbolErrors;
}

header sflow_if_record { //152byte
    bit<32> record_type;
    bit<32> record_length;
    bit<32> ifIndex;
    bit<32> ifType;
    bit<64> ifSpeed;
    bit<32> ifDirection;
    bit<32> ifStatus;
    bit<64> ifInOctets;
    bit<32> ifInUcastPkts;
    bit<32> ifInMulticastPkts;
    bit<32> ifInBroadcastPkts;
    bit<32> ifInDiscards;
    bit<32> ifInErrors;
    bit<32> ifInUnknownProtos;
    bit<64> ifOutOctets;
    bit<32> ifOutUcastPkts;
    bit<32> ifOutMulticastPkts;
    bit<32> ifOutBroadcastPkts;
    bit<32> ifOutDiscards;
    bit<32> ifOutErrors;
    bit<32> ifPromiscuousMode;
}

header sflow_raw_record { //152byte
    bit<32> record_type;
    bit<32> record_length;
    bit<32> header_protocol;
    bit<32> frame_length;
    bit<32> payload_removed;
    bit<32> header_length;
}
header raw_128_t {
    bit<1024> data;   // 128 bytes = 1024 bits
}
header raw_64_t {
    bit<512> data;   
}
header raw_32_t {
    bit<256> data;   
}
header sample_t {
    bit<16>  ingress_port;
    bit<16>  frame_length;
    bit<32>  sampling_rate;
    bit<32>  pkt_count;
    bit<32>  sampled_count;
    
}

header bridge_h {
    bit<32> ingress_port;
    bit<64> in_byte_count;
    bit<64> out_byte_count;
    bit<32> in_ucast_count;
    bit<32> in_multi_count;
    bit<32> in_broad_count;
    bit<32> out_ucast_count;
    bit<32> out_multi_count;
    bit<32> out_broad_count;
    bit<32> agent_ip;
    bit<32> input_if;

}

header fake_eth_t {
    bit<48> fake_dst;
    bit<48> fake_src;
    bit<16> fake_type;
}

struct my_header_t {
    mirror_h        mirror;
    bridge_h        bridge;
    ethernet_h      ethernet;
    ipv4_h          ipv4;
    tcp_h           tcp;
    udp_h           udp;
    sflow_t         sflow_hd;
    sflow_flow_t    sflow_flow;
    sflow_raw_record raw_record;
    sflow_counter_t sflow_counter;
    sflow_eth_record eth_record;
    sflow_if_record  if_record;
    raw_128_t       raw_128;
    raw_64_t        raw_64;
    raw_32_t        raw_32;
    sample_t        sample;
    fake_eth_t      fake_eth;

    
}
struct empty_header_t {}

struct empty_metadata_t {}

#endif /* _HEADERS_ */
