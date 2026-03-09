import socket
import struct
import ipaddress

def parse_sflow_payload(payload):
    try:
        # 1. 解析 sFlow Header (28 bytes)
        if len(payload) < 28: return
        header = struct.unpack('!7I', payload[:28])
        
        print(f"\n{'='*60}")
        print(f"  [sFlow Header] Ver: {header[0]} | Samples: {header[6]} | Seq: {header[4]}")
        print(f"  Agent IP: {ipaddress.IPv4Address(header[2])}")
        print(f"{'-'*60}")

        # 2. 處理 Sample 數據
        # 實務上 sFlow 每個 Sample 前面會有 8 bytes 的類型與長度描述
        # 我們跳過這些描述，直接從你圖表對應的欄位開始抓取
        # 嘗試從第 28 或 36 byte 開始抓取數據
        current_offset = 28
        
        # 檢查剩餘長度，如果你原本預期 38-40 bytes 的欄位，我們調低門檻確保不噴錯
        remaining_data = payload[current_offset:]
        
        # 根據報錯調整：如果你的結構剛好差了幾位元組，我們先印出長度來檢查
        if len(remaining_data) < 38:
            print(f"  [Info] Sample 資料長度不足 ({len(remaining_data)} bytes)，可能包含不同的 Sample Type")
            return

        # 嘗試動態解析 (針對你提供的 38 bytes 格式)
        try:
            fields = struct.unpack('!IIHHIIHHIIHHHH', remaining_data[:38])
            
            ip_mix = fields[10]
            ip_flag = ip_mix >> 13
            ip_offset = ip_mix & 0x1FFF

            print(f"  In/Out Port: {fields[2]}/{fields[3]} | Rate: {fields[4]}")
            print(f"  Source:      {ipaddress.IPv4Address(fields[8])}:{fields[12]}")
            print(f"  Destination: {ipaddress.IPv4Address(fields[9])}:{fields[13]}")
            print(f"  EthType: {hex(fields[5])} | Proto: {fields[7]}")
            print(f"  IP Flag: {bin(ip_flag)} | Offset: {ip_offset} | TCP Flag: {hex(fields[11])}")
        except struct.error:
            # 如果 38 bytes 還是失敗，印出 Raw Hex 方便偵錯
            print(f"  [Raw Data Hex]: {remaining_data[:20].hex()}")
            
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