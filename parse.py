import socket
import struct
import ipaddress

def parse_sflow_payload(payload):
    """ 解析 UDP 之後的 sFlow 內容 (即你提供的兩個表格結構) """
    try:
        # 1. 解析 Header (28 bytes)
        if len(payload) < 28: return
        header = struct.unpack('!7I', payload[:28])
        
        print(f"\n{'='*60}")
        print(f"  [sFlow Header] Ver: {header[0]} | Samples: {header[6]} | Seq: {header[4]}")
        print(f"  Agent IP: {ipaddress.IPv4Address(header[2])}")
        print(f"{'-'*60}")

        # 2. 解析 Sample Data (從偏移量 28 開始，長度 38 bytes)
        sample_data = payload[28:66]
        if len(sample_data) < 38: return

        fields = struct.unpack('!IIHHIIHHIIHHHH', sample_data)
        
        # 位元運算處理 IP Flag (3bit) 與 Offset (13bit)
        ip_mix = fields[10]
        ip_flag = ip_mix >> 13
        ip_offset = ip_mix & 0x1FFF

        print(f"  In/Out Port: {fields[2]}/{fields[3]} | Rate: {fields[4]}")
        print(f"  Source:      {ipaddress.IPv4Address(fields[8])}:{fields[12]}")
        print(f"  Destination: {ipaddress.IPv4Address(fields[9])}:{fields[13]}")
        print(f"  EthType: {hex(fields[5])} | Proto: {fields[7]}")
        print(f"  IP Flag: {bin(ip_flag)} | Offset: {ip_offset} | TCP Flag: {hex(fields[11])}")
        print(f"{'='*60}")
    except Exception as e:
        print(f"解析內容出錯: {e}")

def start_raw_sniffing(interface):
    # 使用 AF_PACKET 建立原始通訊端，監聽所有乙太網路類型 (ETH_P_ALL)
    # ETH_P_ALL = 0x0003
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((interface, 0))
    
    print(f"正在以 Raw 模式監聽網卡: {interface} (過濾 UDP Port 6343)...")

    while True:
        # 接收完整封包 (包含 Ethernet Header)
        packet, addr = sock.recvfrom(65535)
        
        # 1. 拆解 Ethernet Header (前 14 bytes)
        eth_header = packet[:14]
        eth_type = struct.unpack('!H', eth_header[12:14])[0]
        
        if eth_type == 0x0800: # 確保是 IPv4 (0x0800)
            # 2. 拆解 IP Header (通常是 20 bytes)
            ip_header = packet[14:34]
            ip_data = struct.unpack('!BBH HH BB H 4s 4s', ip_header)
            protocol = ip_data[6] # 第 7 個欄位是 Protocol
            
            if protocol == 17: # 17 代表 UDP
                # 3. 拆解 UDP Header (8 bytes)
                # IP Header 長度可能不固定，但基本為 20 byte，所以 UDP 從 14 + 20 = 34 開始
                udp_header = packet[34:42]
                src_port, dst_port, udp_len, udp_chk = struct.unpack('!HHHH', udp_header)
                
                if dst_port == 6343:
                    # 4. 提取 Payload (14 bytes Eth + 20 bytes IP + 8 bytes UDP = 42 bytes offset)
                    sflow_payload = packet[42:]
                    parse_sflow_payload(sflow_payload)

if __name__ == "__main__":
    # 執行時請確保使用 sudo python3 ...
    try:
        start_raw_sniffing("enp2s0")
    except KeyboardInterrupt:
        print("\n停止監聽。")