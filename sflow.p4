/* -*- P4_16 -*- */
#include <core.p4>
#include <tna.p4>

#include "common/headers.p4"
#include "common/util.p4"

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/


/* Ingress Parser */
enum bit<3> MIRROR_TYPE_t {
    I2E = 1,
    E2E = 2
};


const bit<32> SAMPLING_RATE = 128;
const bit<9> RECIRC_PORT = 68;
const bit<9> CPU_PORT = 320;
parser MyIngressParser(packet_in pkt,
                out my_header_t hdr,
                out my_metadata_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;
    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        
        transition select(ig_intr_md.ingress_port) {
            RECIRC_PORT :  parse_sample;   // 從 recirc port 進來
            CPU_PORT    :  parse_cpu_packet;
            default     :  parse_ethernet;      // 一般 front-panel port
        }
    }
    state parse_cpu_packet {
        pkt.extract(hdr.bridge);
        meta.cpu_ingress_port = hdr.bridge.ingress_port;
        meta.in_byte_count = hdr.bridge.in_byte_count;
        meta.out_byte_count = hdr.bridge.out_byte_count;
        meta.in_ucast_count = hdr.bridge.in_ucast_count;
        meta.in_multi_count = hdr.bridge.in_multi_count;
        meta.in_broad_count = hdr.bridge.in_broad_count;
        meta.out_ucast_count = hdr.bridge.out_ucast_count;
        meta.out_multi_count = hdr.bridge.out_multi_count;
        meta.out_broad_count = hdr.bridge.out_broad_count;
        meta.agent_ip = hdr.bridge.agent_ip;
        meta.input_if = hdr.bridge.input_if;
        transition parse_ethernet;  
    }
    state parse_sample {
        pkt.extract(hdr.sample);
        meta.sample_idx = (bit<16>)hdr.sample.sample_idx;
        meta.offset = (bit<16>)hdr.sample.offset;
        meta.input_port = (bit<16>)hdr.sample.input_port;
        meta.output_port = (bit<16>)hdr.sample.output_port;
        meta.frame_length = (bit<16>)hdr.sample.frame_length;

        meta.src_ip = (bit<32>)hdr.sample.src_ip ;
        meta.dst_ip = (bit<32>)hdr.sample.dst_ip;
        meta.protocol = (bit<16>)hdr.sample.protocol;
        meta.src_port = (bit<16>)hdr.sample.src_port;
        meta.dst_port = (bit<16>)hdr.sample.dst_port;


        // meta.sampled_count = (bit<32>)hdr.sample.sampled_count;
        
        transition select(hdr.sample.frame_length) {
            // 使用範圍或掩碼（具體取決於編譯器版本，Tofino 支援 range 匹配）
            0 .. 127 : parse_raw_64;
            default  : parse_raw_128; 
        }
    }

    state parse_raw_128 {
        pkt.extract(hdr.raw_128);   
        meta.header_length = 128;
        meta.record_length = 144;
        meta.ip_len = 248;
        meta.udp_len = 228;
        meta.sample_length = 184;
        // meta.raw_128_data = (bit<1024>)hdr.raw_128.data;
        transition accept;
    }
    state parse_raw_64 {
        pkt.extract(hdr.raw_64); // 假設您已定義好 hdr.raw_64
        meta.header_length = 64;
        meta.record_length = 80;
        meta.sample_length = 120;
        meta.ip_len = 184;
        meta.udp_len = 164;
        // meta.raw_64_data = (bit<512>)hdr.raw_64.data;
        // 處理 64 bytes 的邏輯
        transition accept;
    }
    state parse_raw_32 {
        pkt.extract(hdr.raw_32); // 假設您已定義好 hdr.raw_32
        meta.header_length = 32;
        meta.record_length = 48;
        meta.sample_length = 88;
        meta.ip_len = 152;
        meta.udp_len = 132;
        // meta.raw_32_data = (bit<512>)hdr.raw_32.data;
        // 處理 64 bytes 的邏輯
        transition accept;
    }
   

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            IP_PROTOCOLS_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.src_port = (bit<16>)hdr.tcp.src_port;
        meta.dst_port = (bit<16>)hdr.tcp.dst_port;
        meta.tcp_flag = 0;

        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.src_port = (bit<16>)hdr.udp.src_port;
        meta.dst_port = (bit<16>)hdr.udp.dst_port;
        meta.tcp_flag = 0;
        transition accept;
    }
}


/* Ingress Pipeline */
control MyIngress(
                  /* User */
                  inout my_header_t hdr,
                  inout my_metadata_t meta,
                  /* Intrinsic */
                  in ingress_intrinsic_metadata_t ig_intr_md,
                  in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                  inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                  inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    Counter<bit<64>, bit<9>>(512, CounterType_t.BYTES) port_in_bytes;
    Counter<bit<64>, bit<9>>(512, CounterType_t.BYTES) port_out_bytes;

    Counter<bit<64>, bit<9>>(512, CounterType_t.PACKETS) port_in_ucast_pkts;
    Counter<bit<64>, bit<9>>(512, CounterType_t.PACKETS) port_in_multi_pkts;
    Counter<bit<64>, bit<9>>(512, CounterType_t.PACKETS) port_in_broad_pkts;  
    Counter<bit<64>, bit<9>>(512, CounterType_t.PACKETS) port_out_ucast_pkts;
    Counter<bit<64>, bit<9>>(512, CounterType_t.PACKETS) port_out_multi_pkts;
    Counter<bit<64>, bit<9>>(512, CounterType_t.PACKETS) port_out_broad_pkts;

    Register<bit<32>, bit<9>>(512, 0) port_rx_pkts;
    RegisterAction<bit<32>, bit<9>,bit<32>>(port_rx_pkts) 
        inc_pkt = {
            void apply(inout bit<32> v, out bit<32> new_val) {
                if (v == (bit<32>)meta.sampling_rate){
                    v = 0;
                }else{
                    v       = v + 1;
                }
                new_val = v; 
            }
    };
    
    Register<bit<32>, bit<9>>(512, 0) port_sampled_pkts;
    RegisterAction<bit<32>, bit<9>,bit<32>>(port_sampled_pkts) 
        inc_sampled_pkt = {
            void apply(inout bit<32> v, out bit<32> read_val) {
                v       = v + 1;
                read_val = v; 
            }
    };
    Register<bit<32>, bit<9>>(512, 0) port_rx_count;
    RegisterAction<bit<32>, bit<9>,bit<32>>(port_rx_count) 
        inc_port_rx = {
            void apply(inout bit<32> v, out bit<32> read_val) {
                v       = v + 1;
                read_val = v; 
            }
    };

    Register<bit<8>, bit<16>>(512, 0) saved_count;
    RegisterAction<bit<8>, bit<16>,bit<8>>(saved_count) 
        inc_saved_count = {
            void apply(inout bit<8> v, out bit<8> read_val) {
                
                if(v == 4){
                    v = 1;
                }else{
                    v = v + 1;
                }
                read_val = v; 
            }
    };
    
    
    
    // Register<bit<512>, bit<9>>(512, 0) reg_pending_state;
    

    action send_multicast(bit<16> grp_id, bit<16> rid) {
        ig_tm_md.mcast_grp_a = grp_id;
        ig_tm_md.rid = rid;
    }
    action set_out_port(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }
    action set_sampling_rate(bit<32> sampling_rate) {
        meta.sampling_rate=sampling_rate;
    }
    action set_ts(bit<32> ts) {
        meta.ctrl_ts = ts;          
    }
    action set_sampled_count(bit<9> idx) {
        bit<32> sampled_count;
        sampled_count = inc_sampled_pkt.execute(idx);
        meta.sampled_count = sampled_count;
    }

    action set_pkt_count(bit<9> idx) {
        bit<32> pkt_count;
        pkt_count = inc_port_rx.execute(idx);
        meta.pkt_count = pkt_count;
    }

    
    action set_counter_sample_hdr() {
        
        hdr.ethernet.setValid();
        hdr.ipv4.setValid();
        hdr.udp.setValid();     
        
        hdr.ethernet.src_addr = 0x001122334455;
        hdr.ethernet.dst_addr = 0x000acd3b1842;
        hdr.ethernet.ether_type = 0x0800;
        hdr.ipv4.version=4;
        hdr.ipv4.ihl=0x45;
        hdr.ipv4.diffserv     = 0;
        hdr.ipv4.total_len = 232;
        hdr.ipv4.identification = 0; 
        hdr.ipv4.flags        = 2;
        hdr.ipv4.frag_offset  = 0; 
        hdr.ipv4.ttl          = 64;
        hdr.ipv4.protocol     = 17; 
        // hdr.ipv4.src_addr = 0x0a0a0308;
        hdr.ipv4.dst_addr = 0x0a0a0af8;
        
        hdr.udp.src_port = (bit<16>)8888;
        hdr.udp.dst_port = (bit<16>)6343;
        hdr.udp.hdr_length = (bit<16>)212;
        hdr.udp.checksum = 16w0;

        hdr.sflow_hd.setValid();
        hdr.sflow_hd.version = (bit<32>)5;
        hdr.sflow_hd.address_type = (bit<32>)1;
        hdr.sflow_hd.agent_addr = meta.agent_ip;
        hdr.sflow_hd.sub_agent_id = 1;
        hdr.sflow_hd.sequence_number = 1;
        hdr.sflow_hd.uptime = (bit<32>)meta.ctrl_ts;
        hdr.sflow_hd.samples = (bit<32>)1;

        hdr.sflow_counter.setValid();
        hdr.sflow_counter.sample_type = 2;
        hdr.sflow_counter.sample_length = 168;
        hdr.sflow_counter.sample_seq_num = 1;
        hdr.sflow_counter.source_id = meta.input_if;   //待改
        hdr.sflow_counter.record_count = 2;
    }

    action set_sample_hd(bit<32> agent_addr,bit<32> agent_id,bit<32>input_if) {
        hdr.ethernet.src_addr = 0x001122334455;
        hdr.ethernet.dst_addr = 0x000acd3b1842;
        hdr.ethernet.ether_type = 0x0800;
        hdr.ipv4.version=4;
        hdr.ipv4.ihl=0x45;
        hdr.ipv4.diffserv     = 0;
        hdr.ipv4.total_len = meta.ip_len;
        hdr.ipv4.identification = 0; 
        hdr.ipv4.flags        = 2;
        hdr.ipv4.frag_offset  = 0; 
        hdr.ipv4.ttl          = 64;
        hdr.ipv4.protocol     = 17; 
        hdr.ipv4.src_addr = (bit<32>)agent_addr;
        hdr.ipv4.dst_addr = 0x0a0a0af8;
        
        hdr.udp.src_port = (bit<16>)8888;
        hdr.udp.dst_port = (bit<16>)6343;
        hdr.udp.hdr_length = (bit<16>) meta.udp_len;
        hdr.udp.checksum = 16w0;
        
        hdr.sflow_hd.setValid();
        hdr.sflow_hd.version = (bit<32>)5;
        hdr.sflow_hd.address_type = (bit<32>)1;
        hdr.sflow_hd.agent_addr = (bit<32>)agent_addr;
        hdr.sflow_hd.sub_agent_id = (bit<32>)agent_id;
        hdr.sflow_hd.sequence_number = (bit<32>)meta.sampled_count;
        hdr.sflow_hd.uptime = (bit<32>)meta.ctrl_ts;
        hdr.sflow_hd.samples = (bit<32>)1; 

        hdr.sflow_flow.input_if = (bit<32>)25; 
    }


    action set_agent_status(bit<1> status) {
        meta.agent_status = status;
    }


    table ingress_port_forward {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            set_out_port;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    table port_sampling_rate {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            set_sampling_rate;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }
    table set_port_agent {
        key = {
            hdr.sample.input_port : exact;
        }
        actions = {
            set_sample_hd;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    table t_set_ts {
        key = { }                   // ★ 沒有 key → 不用 match，只有 default / 單一 entry
        actions = {
            set_ts;
            NoAction;
        }
        size = 1;
    }
    
    table agent_status {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            set_agent_status;
            NoAction;
        }
        size = 512;
        default_action = NoAction;
    }
    action do_update_count() {
        meta.saved_count = inc_saved_count.execute((bit<16>)meta.sample_ing_port);
        // meta.sample_idx = meta.sample_idx + (bit<16>)meta.saved_count -1;
    }
  
    table t_update_saved_count {
        key = {
            // ig_intr_md.ingress_port : ternary;
        }
        actions = {
            do_update_count;
            // NoAction;
        }
        size = 512;
        default_action = do_update_count; 
    }
//*********** input port ***********//
    Register<bit<16>, bit<16>>(512, 0) sample_input_port;
    RegisterAction<bit<16>, bit<16>,bit<16>>(sample_input_port) 
        set_sample_input_port = {
            void apply(inout bit<16> v, out bit<16> read_val) {
                v       = meta.input_port;
                read_val = v; 
            }
    };

    action do_update_sample_input() {
        set_sample_input_port.execute(meta.sample_idx);
    }
    table t_update_saved_sample_input {
        key = {       }
        actions = {
             do_update_sample_input;
            // NoAction;
        }
        size = 1;
        default_action =  do_update_sample_input; 
    }
//*********** output port ***********//
    Register<bit<16>, bit<16>>(512, 0) sample_output_port;
    RegisterAction<bit<16>, bit<16>,bit<16>>(sample_output_port) 
        set_sample_output_port = {
            void apply(inout bit<16> v, out bit<16> read_val) {
                v       = 0;
                read_val = v; 
            }
    };
    action do_update_sample_output() {
        set_sample_output_port.execute(meta.sample_idx);
    }
    table t_update_saved_sample_output {
        key = {
            
        }
        actions = {
             do_update_sample_output;
            // NoAction;
        }
        size = 1;
        default_action =  do_update_sample_output; 
    }
//*********** frame_len ***********//
    Register<bit<16>, bit<16>>(512, 0) sample_frame_len;
    RegisterAction<bit<16>, bit<16>,bit<16>>(sample_frame_len) 
        set_sample_frame_len = {
            void apply(inout bit<16> v, out bit<16> read_val) {
                v       = 0;
                read_val = v; 
            }
    };
    action do_update_sample_frame_len() {
        set_sample_frame_len.execute(meta.sample_idx);
    }
    table t_update_saved_sample_frame_len {
        key = {
            
        }
        actions = {
             do_update_sample_frame_len;
            // NoAction;
        }
        size = 1;
        default_action =  do_update_sample_frame_len; 
    }
//*********** source_ip ***********//
    Register<bit<32>, bit<16>>(512, 0) sample_source_ip;
    RegisterAction<bit<32>, bit<16>,bit<32>>(sample_source_ip) 
        set_sample_source_ip = {
            void apply(inout bit<32> v, out bit<32> read_val) {
                v       = (bit<32>)hdr.ipv4.src_addr;
                read_val = v; 
            }
    };
    action do_update_sample_source_ip() {
        set_sample_source_ip.execute(meta.sample_idx);
    }
    table t_update_saved_sample_source_ip {
        key = {
            
        }
        actions = {
             do_update_sample_source_ip;
            // NoAction;
        }
        size = 1;
        default_action =  do_update_sample_source_ip; 
    }
//*********** destination_ip ***********//
    Register<bit<32>, bit<16>>(512, 0) sample_destination_ip;
    RegisterAction<bit<32>, bit<16>,bit<32>>(sample_destination_ip) 
        set_sample_destination_ip = {
            void apply(inout bit<32> v, out bit<32> read_val) {
                v       = (bit<32>)hdr.ipv4.dst_addr;
                read_val = v; 
            }
    };
    action do_update_sample_destination_ip() {
        set_sample_destination_ip.execute(meta.sample_idx);
    }
    table t_update_saved_sample_destination_ip {
        key = {
            
        }
        actions = {
             do_update_sample_destination_ip;
            // NoAction;
        }
        size = 1;
        default_action =  do_update_sample_destination_ip; 
    }

    Register<bit<16>, bit<16>>(512, 0) sample_protocol;
    RegisterAction<bit<16>, bit<16>,bit<16>>(sample_protocol) 
        set_sample_protocol = {
            void apply(inout bit<16> v, out bit<16> read_val) {
                v       = (bit<16>)hdr.ipv4.protocol;
                read_val = v; 
            }
    };
    action do_update_sample_protocol() {
        set_sample_protocol.execute(meta.sample_idx);
    }
    table t_update_saved_sample_protocol {
        key = {
            
        }
        actions = {
             do_update_sample_protocol;
            // NoAction;
        }
        size = 1;
        default_action =  do_update_sample_protocol; 
    }

    Register<bit<16>, bit<16>>(512, 0) sample_source_port;
    RegisterAction<bit<16>, bit<16>,bit<16>>(sample_source_port) 
        set_sample_source_port = {
            void apply(inout bit<16> v, out bit<16> read_val) {
                v       = (bit<16>)hdr.udp.src_port;
                read_val = v; 
            }
    };
    action do_update_sample_source_port() {
        set_sample_source_port.execute(meta.sample_idx);
    }
    table t_update_saved_sample_source_port {
        key = {
            
        }
        actions = {
             do_update_sample_source_port;
            // NoAction;
        }
        size = 1;
        default_action =  do_update_sample_source_port; 
    }

    Register<bit<16>, bit<16>>(512, 0) sample_destination_port;
    RegisterAction<bit<16>, bit<16>,bit<16>>(sample_destination_port) 
        set_sample_destination_port = {
            void apply(inout bit<16> v, out bit<16> read_val) {
                v       = (bit<16>)hdr.udp.dst_port;
                read_val = v; 
            }
    };
    action do_update_sample_destination_port() {
        set_sample_destination_port.execute(meta.sample_idx);
    }
    table t_update_saved_sample_destination_port {
        key = {
            
        }
        actions = {
             do_update_sample_destination_port;
            // NoAction;
        }
        size = 1;
        default_action =  do_update_sample_destination_port; 
    }
    apply {
        t_set_ts.apply();  //更新timestamp
        bit<9> idx = (bit<9>)ig_intr_md.ingress_port;
        meta.agent_status = 0;
        agent_status.apply();
        ingress_port_forward.apply();  //根據 ingress port 決定往哪個 egress port 送
        
        if(ig_intr_md.ingress_port == 68){  //從recirc port進來，表示要做成flow sample packet
            hdr.tcp.setInvalid();
            hdr.sflow_counter.setInvalid();
            hdr.ethernet.setValid();
            hdr.ipv4.setValid();
            hdr.udp.setValid();
            ig_dprsr_md.mirror_type  = 0;
            
            // t_update_saved_count.apply();
            if(meta.offset == 8){
                
                sample_input_port.read(meta.sample_idx);
            }else{
                meta.sample_idx = meta.sample_idx + meta.offset;
                t_update_saved_sample_input.apply();
                t_update_saved_sample_output.apply();
                t_update_saved_sample_frame_len.apply();
                t_update_saved_sample_source_ip.apply();
                t_update_saved_sample_destination_ip.apply();
                t_update_saved_sample_protocol.apply();
                t_update_saved_sample_source_port.apply();
                t_update_saved_sample_destination_port.apply();
            }
            
            
            
            
            
        }
        else if(ig_intr_md.ingress_port == 320){ //從CPU port進來，表示要做成counter sample packet
            set_counter_sample_hdr();
            hdr.eth_record.setValid();
            hdr.eth_record.record_type = (bit<32>)2;
            hdr.eth_record.record_length = (bit<32>)52;
            hdr.eth_record.dot3StatsAlignmentErrors = (bit<32>)0;
            hdr.eth_record.dot3StatsFCSErrors = (bit<32>)0;
            hdr.eth_record.dot3StatsSingleCollisionFrames = (bit<32>)0;
            hdr.eth_record.dot3StatsMultipleCollisionFrames = (bit<32>)0;
            hdr.eth_record.dot3StatsSQETestErrors = (bit<32>)0;
            hdr.eth_record.dot3StatsDeferredTransmissions = (bit<32>)0;
            hdr.eth_record.dot3StatsLateCollisions = (bit<32>)0;
            hdr.eth_record.dot3StatsExcessiveCollisions = (bit<32>)0;
            hdr.eth_record.dot3StatsInternalMacTxErrors = (bit<32>)0;
            hdr.eth_record.dot3StatsCarrierSenseErrors = (bit<32>)0;
            hdr.eth_record.dot3StatsFrameTooLongs = (bit<32>)0;
            hdr.eth_record.dot3StatsInternalMacRxErrors = (bit<32>)0;
            hdr.eth_record.dot3StatsSymbolErrors = (bit<32>)0;
            
            hdr.if_record.setValid();
            hdr.if_record.record_type = (bit<32>)1;
            hdr.if_record.record_length = (bit<32>)88;
            hdr.if_record.ifIndex = (bit<32>)meta.input_if;   //代改
            hdr.if_record.ifType = (bit<32>)6;
            hdr.if_record.ifSpeed = (bit<64>)10000000000;
            hdr.if_record.ifDirection = (bit<32>)1;
            hdr.if_record.ifStatus = (bit<32>)1;
            hdr.if_record.ifInOctets = (bit<64>)meta.in_byte_count;
            hdr.if_record.ifInUcastPkts = (bit<32>)meta.in_ucast_count;
            hdr.if_record.ifInMulticastPkts = (bit<32>)meta.in_multi_count;
            hdr.if_record.ifInBroadcastPkts = (bit<32>)meta.in_broad_count;
            hdr.if_record.ifInDiscards = (bit<32>)0;
            hdr.if_record.ifInErrors = (bit<32>)0;
            hdr.if_record.ifOutOctets = (bit<64>)meta.out_byte_count;
            hdr.if_record.ifOutUcastPkts = (bit<32>)meta.out_ucast_count;
            hdr.if_record.ifOutMulticastPkts = (bit<32>)meta.out_multi_count;
            hdr.if_record.ifOutBroadcastPkts = (bit<32>)meta.out_broad_count;;
            hdr.if_record.ifOutDiscards = (bit<32>)0;
            hdr.if_record.ifOutErrors = (bit<32>)0;
            hdr.if_record.ifPromiscuousMode = (bit<32>)1;
            ig_tm_md.ucast_egress_port = 156;
        }        
        else if(meta.agent_status == 1){
            port_sampling_rate.apply();   //根據 ingress port 設定 sampling rate
            port_in_bytes.count(idx);  //
            port_out_bytes.count(ig_tm_md.ucast_egress_port);
            bit<48> dmac = hdr.ethernet.dst_addr;
            bit<32> dmac_hi = (bit<32>)(dmac >> 16);   
            bit<16> dmac_lo = (bit<16>)(dmac);         
            bit<8> dmac0 = (bit<8>)(dmac >> 40);
            if (dmac_hi == 32w0xFFFFFFFF) {
                if (dmac_lo == 16w0xFFFF) {
                    port_in_broad_pkts.count(idx);
                    port_out_broad_pkts.count(ig_tm_md.ucast_egress_port);
                } else if ((dmac0 & 8w1) == 8w1) {
                    port_in_multi_pkts.count(idx);
                    port_out_multi_pkts.count(ig_tm_md.ucast_egress_port);
                } else {
                    port_in_ucast_pkts.count(idx);
                    port_out_ucast_pkts.count(ig_tm_md.ucast_egress_port);
                }
            }else if ((dmac0 & 8w1) == 8w1 ) {
                port_in_multi_pkts.count(idx);
                port_out_multi_pkts.count(ig_tm_md.ucast_egress_port);
            } else {
                port_in_ucast_pkts.count(idx);
                port_out_ucast_pkts.count(ig_tm_md.ucast_egress_port);
            }
            
            
            bit<32> pkt_count;
            pkt_count = inc_pkt.execute(idx);
            
            set_pkt_count(idx);
            if(pkt_count==0){   //送往recirc port
                
                t_update_saved_count.apply();
                meta.offset = (bit<16>)meta.saved_count - 1;
                // meta.sample_idx = ((bit<16>)meta.sample_ing_port << 2) + (bit<16>)meta.saved_count - 1;
                meta.sample_idx = ((bit<16>)meta.sample_ing_port<<2);
                // t_update_saved_sample_input.apply();
                // t_update_saved_sample_output.apply();
                // t_update_saved_sample_frame_len.apply();
                // t_update_saved_sample_source_ip.apply();
                // t_update_saved_sample_destination_ip.apply();
                // t_update_saved_sample_protocol.apply();
                // t_update_saved_sample_source_port.apply();
                // t_update_saved_sample_destination_port.apply();
                set_sampled_count(idx);
                ig_dprsr_md.mirror_type = MIRROR_TYPE_t.I2E;
                meta.mirror_session = (bit<10>)26;
                meta.sample_ing_port = (bit<16>)ig_intr_md.ingress_port;
                meta.frame_length = (bit<16>)hdr.ipv4.total_len;
            }

        }
        
        
    }
}

/* Ingress Deparser*/

control MyIngressDeparser(packet_out pkt,
                            /* User */
                            inout my_header_t hdr,
                            in my_metadata_t meta,
                            /* Intrinsic */
                            in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    /* Resource Definitions */
    Checksum() ipv4_checksum;
    Checksum() udp_checksum;
    Mirror() mirror;
    Resubmit() resubmit;
    apply {
        
        if(hdr.ipv4.isValid()){
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        }

        if (ig_dprsr_md.mirror_type == MIRROR_TYPE_t.I2E) {
            mirror.emit<sample_t>(meta.mirror_session, {
                (bit<16>)meta.sample_idx,
                (bit<16>)meta.offset,
                (bit<16>)meta.input_port,
                (bit<16>)meta.output_port,
                (bit<16>)meta.frame_length,
                (bit<32>)meta.src_ip,
                (bit<32>)meta.dst_ip,
                (bit<16>)meta.protocol,
                (bit<16>)meta.src_port,
                (bit<16>)meta.dst_port
            });
        }
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);

        pkt.emit(hdr.sflow_hd);
        pkt.emit(hdr.sflow_flow);
        pkt.emit(hdr.raw_record);
        pkt.emit(hdr.raw_128);
        pkt.emit(hdr.raw_64);
        pkt.emit(hdr.raw_32);
        pkt.emit(hdr.sflow_counter);
        pkt.emit(hdr.eth_record);
        pkt.emit(hdr.if_record);
   
    }
}

/* Egress pipeline */

parser MyEgressParser(
        packet_in pkt,
        out my_header_t hdr,
        out my_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;
    
    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition accept;
    }

    state parse_bridge {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

control MyEgress(
        inout my_header_t hdr,
        inout my_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

    action drop() {
        eg_intr_dprs_md.drop_ctl = 0b1;
    }

    apply {
        // eg_intr_md.egress_port=39;
    //     if (eg_intr_dprs_md.mirror_type !=0){
    //         hdr.sample.setValid();
    //         hdr.ethernet.src_addr = 0xaaaaaaaaaaaa;
    //     }else{
    //         hdr.sample.setInvalid();
    //     }
    }
}

control MyEgressDeparser(
        packet_out pkt,
        inout my_header_t hdr,
        in my_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md) {

    apply {
        // pkt.emit(hdr.sample);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}




Pipeline(
    MyIngressParser(), MyIngress(), MyIngressDeparser(),
    MyEgressParser(), MyEgress(), MyEgressDeparser()
) pipe;

Switch(pipe) main;
