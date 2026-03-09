import socket
import struct
import ipaddress

def parse_sflow_payload(payload):
    try:
        # 1. 解析 sFlow Header (28 bytes)
        if len(payload) < 28: return
        header = struct.unpack('!7I', payload[:28])
        samples_count = header[6]

        print(f"\n{'='*70}")
        print(f" [sFlow v{header[0]}] Agent: {ipaddress.IPv4Address(header[2])} | Samples: {samples_count}")
        print(f"{'='*70}")

        # 2. 迴圈解析 Samples
        current_offset = 28
        # 根據報錯提示，每個 Sample 在記憶體中佔用 40 bytes (38數據 + 2填充)
        sample_size = 40 

        for i in range(samples_count):
            if len(payload) < current_offset + sample_size:
                break
            
            sample_data = payload[current_offset : current_offset + sample_size]
            
            # 格式修正：最後加上 2x 用來吸收掉補位的 2 bytes，總長度剛好 40
            # 格式：I(4)I(4)H(2)H(2)I(4)I(4)H(2)H(2)I(4)I(4)H(2)H(2)H(2)H(2) + 2x = 40
            f = struct.unpack('!IIHHIIHHIIHHHH2x', sample_data)

            # 解析 IP Flag (3bit) 與 Offset (13bit)
            ip_mix = f[10]
            ip_flag = ip_mix >> 13
            ip_offset = ip_mix & 0x1FFF

            print(f"  # Sample {i+1}")
            print(f"    Ports: In[{f[2]}] Out[{f[3]}] | Proto: {f[7]} | Eth: {hex(f[5])}")
            print(f"    Source:      {ipaddress.IPv4Address(f[8])}:{f[12]}")
            print(f"    Destination: {ipaddress.IPv4Address(f[9])}:{f[13]}")
            print(f"    Flag: {bin(ip_flag)} | Offset: {ip_offset} | TCP: {hex(f[11])}")
            print(f"    {'-'*40}")

            current_offset += sample_size

    except Exception as e:
        print(f"解析過程中斷: {e}")

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