import socket
import struct
import ipaddress

def parse_sflow(data):
    try:
        # --- Header (28 bytes) ---
        header_data = data[:28]
        if len(header_data) < 28: return
        
        # !7I: 7個 4-byte unsigned int
        s_ver, a_type, a_addr, sub_id, seq, uptime, count = struct.unpack('!7I', header_data)

        print(f"\n{'='*60}")
        print(f"  [sFlow Header] Version: {s_ver} | Samples: {count} | Seq: {seq}")
        print(f"  Agent: {ipaddress.IPv4Address(a_addr)} | Uptime: {uptime}ms")
        print(f"{'-'*60}")

        # --- Sample Data (從 28 byte 開始，長度 38 bytes) ---
        sample_payload = data[28:66]
        if len(sample_payload) < 38: return

        # 依照你的表格定義格式解析
        # !IIHHIIHHIIHHHH -> 4,4,2,2,4,4,2,2,4,4,2,2,2,2
        (s_type, s_len, in_p, out_p, s_rate, eth_t, f_len, proto, 
         src_ip, dst_ip, ip_mix, tcp_f, src_p, dst_p) = struct.unpack('!IIHHIIHHIIHHHH', sample_payload)

        # 位元運算處理 IP Flag (3bit) 與 Offset (13bit)
        ip_flag = ip_mix >> 13
        ip_offset = ip_mix & 0x1FFF

        # 格式化輸出
        print(f"  Type: {s_type} | In/Out Port: {in_p}/{out_p} | Rate: {s_rate}")
        print(f"  EthType: {hex(eth_t)} | Proto: {proto} | FrameLen: {f_len}")
        print(f"  Source:      {ipaddress.IPv4Address(src_ip)} : {src_p}")
        print(f"  Destination: {ipaddress.IPv4Address(dst_ip)} : {dst_p}")
        print(f"  IP Flag: {bin(ip_flag)} | Offset: {ip_offset} | TCP Flag: {hex(tcp_f)}")
        print(f"{'='*60}")

    except Exception as e:
        print(f"解析失敗: {e}")

def start_server(interface_name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # 核心步驟：將 Socket 綁定到特定網卡
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface_name.encode())
        print(f"成功綁定網卡: {interface_name}")
    except PermissionError:
        print("錯誤：綁定網卡需要 root 權限 (請使用 sudo)")
        return
    except OSError as e:
        print(f"錯誤：無法綁定網卡 {interface_name}，請檢查名稱是否正確。({e})")
        return

    sock.bind(('0.0.0.0', 6343))
    print(f"正在監聽 UDP Port 6343...")

    while True:
        data, addr = sock.recvfrom(65535)
        parse_sflow(data)

if __name__ == "__main__":
    # 在這裡指定你的網卡名稱
    start_server("enp2s0")