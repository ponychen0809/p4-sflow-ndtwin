import socket
import struct
import ipaddress

def parse_sflow_payload(payload):
    try:
        # 1. 解析 sFlow Header (28 bytes)
        if len(payload) < 28: return
        
        # !7I 代表 7 個 4-byte unsigned int
        header = struct.unpack('!7I', payload[:28])
        version = header[0]
        agent_ip = ipaddress.IPv4Address(header[2])
        samples_count = header[6]

        print(f"\n{'='*70}")
        print(f" [sFlow v{version}] Agent: {agent_ip} | Samples Count: {samples_count}")
        print(f"{'='*70}")

        # 2. 迴圈解析每個 Sample (每個長度 38 bytes)
        # 根據你的描述，Sample 直接跟在 Header (offset 28) 後面
        current_offset = 28
        sample_size = 38 # 根據你的表格計算: 4+4+2+2+4+4+2+2+4+4+2+2+2 = 38 (含 flag/offset 混合位元)

        for i in range(samples_count):
            # 確保剩下的資料夠長
            if len(payload) < current_offset + sample_size:
                break
            
            sample_data = payload[current_offset : current_offset + sample_size]
            
            # 格式字串解釋:
            # ! : Big-endian
            # I I : sample_type (4), sample_length (4)
            # H H : input_port (2), output_port (2)
            # I I : sampling_rate (4), Ethernet_type (4)
            # H H : frame_length (2), protocol (2)
            # I I : source_ip (4), destination_ip (4)
            # H   : ip_flag(3bit) + ip_offset(13bit) (共 2 bytes)
            # H   : tcp_flag (2)
            # H H : source_port (2), destination_port (2)
            f = struct.unpack('!IIHHIIHHIIHHHH', sample_data)

            # 位元運算處理 IP Flag & Offset
            ip_mix = f[10]
            ip_flag = ip_mix >> 13
            ip_offset = ip_mix & 0x1FFF

            print(f"  # Sample {i+1}")
            print(f"    Ports: In[{f[2]}] Out[{f[3]}] | Proto: {f[7]} | EthType: {hex(f[5])}")
            print(f"    Source:      {ipaddress.IPv4Address(f[8])}:{f[12]}")
            print(f"    Destination: {ipaddress.IPv4Address(f[9])}:{f[13]}")
            print(f"    IP Flag: {bin(ip_flag)} | Offset: {ip_offset} | TCP Flag: {hex(f[11])}")
            print(f"    {'-'*30}")

            # 移動到下一個 Sample 的起點
            current_offset += sample_size

    except Exception as e:
        print(f"解析出錯: {e}")

def start_sniffing(interface):
    # 使用 Raw Socket 監聽所有 IP 封包
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((interface, 0))
    
    print(f"正在監聽網卡 {interface} 並解析 sFlow...")

    while True:
        packet, addr = sock.recvfrom(65535)
        
        # Ethernet Header = 14 bytes
        # IP Header = 20 bytes (假設無 Option)
        # UDP Header = 8 bytes
        # 總共跳過 42 bytes 來到 sFlow Payload
        
        # 簡單過濾：確定是 UDP (17) 且 Dst Port 是 6343
        try:
            # IP Header 的 Protocol 在第 23 個 byte (14+9)
            if packet[23] == 17: 
                # UDP Dst Port 在第 36, 37 byte (14+20+2)
                dst_port = struct.unpack('!H', packet[36:38])[0]
                if dst_port == 6343:
                    parse_sflow_payload(packet[42:])
        except:
            continue

if __name__ == "__main__":
    # 請確保執行時使用 sudo python3
    start_sniffing("enp2s0")