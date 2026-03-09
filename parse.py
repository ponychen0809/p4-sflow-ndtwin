import socket
import struct
import ipaddress


def parse_sflow_payload(payload):
    try:
        # 1. 解析你 P4 寫入的 sFlow Header (28 bytes)
        if len(payload) < 28: return
        header = struct.unpack('!7I', payload[:28])
        samples_count = header[6]

        print(f"\n{'='*70}")
        print(f" [P4 sFlow Header] Agent: {ipaddress.IPv4Address(header[2])} | Samples: {samples_count}")
        print(f"{'='*70}")

        # 2. 迴圈解析每個 Sample
        current_offset = 28
        sample_size = 40  # 10 個 32-bit 欄位 = 40 bytes

        for i in range(samples_count):
            if len(payload) < current_offset + sample_size:
                break
            
            sample_data = payload[current_offset : current_offset + sample_size]
            
            # 因為你在 P4 全都是寫入 32-bit 暫存器，我們直接讀取 10 個 4-byte 整數
            # 格式: !10I (10 個 unsigned int)
            fields = struct.unpack('!10I', sample_data)

            # 根據你的 P4 assign 順序還原欄位
            s_type = fields[0]
            s_len  = fields[1]
            
            # packed_ports = (input_port << 16) | output_port
            in_port  = fields[2] >> 16
            out_port = fields[2] & 0xFFFF
            
            s_rate   = fields[3]
            eth_type = fields[4]
            
            # frame_length_protocol = (frame_length << 16) | protocol
            frame_len = fields[5] >> 16
            proto     = fields[5] & 0xFFFF
            
            src_ip   = ipaddress.IPv4Address(fields[6])
            dst_ip   = ipaddress.IPv4Address(fields[7])
            
            # l4_ports = (src_port << 16) | dst_port
            src_port = fields[9] >> 16
            dst_port = fields[9] & 0xFFFF
            
            # ip_flag_offset_tcp_flag = (ip_flags_offset << 16) | tcp_flag
            ip_flags_offset = fields[8] >> 16
            tcp_flag        = fields[8] & 0xFFFF
            
            # 再進一步將 ip_flags_offset 拆分為 flag (3 bit) 與 offset (13 bit)
            ip_flag = ip_flags_offset >> 13
            ip_offset = ip_flags_offset & 0x1FFF

            # 印出結果
            print(f"  # Sample {i+1} (Type: {s_type}, Len: {s_len})")
            print(f"    Ports: In[{in_port}] Out[{out_port}] | Proto: {proto} | FrameLen: {frame_len}")
            print(f"    Source:      {src_ip}:{src_port}")
            print(f"    Destination: {dst_ip}:{dst_port}")
            print(f"    IP Flag: {bin(ip_flag)} | Offset: {ip_offset} | TCP Flag: {hex(tcp_flag)}")
            print(f"    {'-'*40}")

            current_offset += sample_size

    except Exception as e:
        print(f"解析錯誤: {e}")

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