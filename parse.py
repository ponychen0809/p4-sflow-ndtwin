import socket
import struct

def parse_sflow(data):
    try:
        # --- 解析第一部分：sFlow Header (由你的第一張圖定義) ---
        # 每個欄位都是 4 byte (32-bit unsigned int)，對應 struct 格式 'I'
        # 總共 7 個欄位 = 28 bytes
        header_data = data[:28]
        if len(header_data) < 28:
            return

        sflow_version, agent_addr_type, agent_addr, sub_agent_id, \
        seq_num, sys_uptime, samples_count = struct.unpack('!7I', header_data)

        print("-" * 50)
        print(f"[sFlow Header]")
        print(f"Version: {sflow_version} | Agent Addr: {agent_addr} | Samples: {samples_count}")
        print(f"Sequence: {seq_num} | Uptime: {sys_uptime}")

        # --- 解析第二部分：Sample Data (由你的第二張圖定義) ---
        # 注意：sFlow 實際結構會因 type 而異，這裡嚴格依照你提供的 Table 偏移量解析
        # 偏移量從 28 byte 開始
        sample_payload = data[28:]
        
        # 根據你的圖表定義格式：
        # 4b, 4b, 2b, 2b, 4b, 4b, 2b, 2b, 4b, 4b, (ip_flag/offset 混合2b), 2b, 2b, 2b
        # 格式符號：I=4byte, H=2byte
        # '!IIHHIIHHIIHHHH' 總長度為 4+4+2+2+4+4+2+2+4+4+2+2+2+2 = 38 bytes
        if len(sample_payload) >= 38:
            s_type, s_len, in_port, out_port, s_rate, eth_type, \
            frame_len, proto, src_ip, dst_ip, ip_mix, tcp_flag, \
            src_port, dst_port = struct.unpack('!IIHHIIHHIIHHHH', sample_payload[:38])

            # 處理 16-bit 的 ip_flag (3 bit) 與 ip_offset (13 bit)
            ip_flag = ip_mix >> 13
            ip_offset = ip_mix & 0x1FFF

            print(f"\n[Sample Details]")
            print(f"Type: {s_type} | Length: {s_len}")
            print(f"In/Out Port: {in_port}/{out_port} | Rate: {s_rate}")
            print(f"Proto: {proto} | EthType: {eth_type}")
            print(f"Src IP: {src_ip} -> Dst IP: {dst_ip}")
            print(f"IP Flag: {ip_flag} | IP Offset: {ip_offset}")
            print(f"TCP Flag: {tcp_flag}")
            print(f"Port: {src_port} -> {dst_port}")

    except Exception as e:
        print(f"解析錯誤: {e}")

def start_server():
    # 建立 UDP Socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # 綁定所有網卡的 Port 6343
    server_address = ('0.0.0.0', 6343)
    sock.bind(server_address)
    
    print(f"正在監聽 {server_address} 的 sFlow 封包...")

    while True:
        data, address = sock.recvfrom(65535) # 接收最大 UDP 封包
        parse_sflow(data)

if __name__ == "__main__":
    start_server()