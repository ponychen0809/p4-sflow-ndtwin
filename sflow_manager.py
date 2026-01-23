#!/usr/bin/env python3
import os
import sys
import json
import time
import threading
import struct
import socket
import bfrt_grpc.client as gc
from bfruntime_client_base_tests import BfRuntimeTest

from ptf.testutils import send_packet
from scapy.all import Ether, IP, UDP


# ------------------------------------------------------------
# Keep using input() style, but make it safe for Python 2.7
# (Python2 built-in input() will eval and can throw SyntaxError)
# ------------------------------------------------------------
def input(prompt=""):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    line = sys.stdin.readline()
    if not line:
        return ""
    return line.rstrip("\n")


def _to_int(v):
    """Convert '0x..' string or int to int."""
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        vv = v.strip().lower()
        if vv.startswith("0x"):
            return int(vv, 16)
        return int(vv)
    raise ValueError("Unsupported int value: {}".format(repr(v)))


class SimpleSwitchTest(BfRuntimeTest):
    def setUp(self):
        self.client_id = 0
        self.p4_name = "sflow"
        self.dev = 0
        self.dev_tgt = gc.Target(self.dev, pipe_id=0xFFFF)

        # ---- load config ----
        script_dir = os.path.dirname(os.path.abspath(__file__))
        cfg_path = os.environ.get("SWITCH_CFG", os.path.join(script_dir, "config.json"))

        with open(cfg_path, "r") as f:
            self.cfg = json.load(f)

        print("[CFG] loaded: {}".format(cfg_path))

        # 建 BFRT 連線
        BfRuntimeTest.setUp(self, self.client_id, self.p4_name)
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)

        # system tables
        self.port_table = self.bfrt_info.table_get("$PORT")
        self.pre_node_tbl = self.bfrt_info.table_get("$pre.node")
        self.pre_mgid_tbl = self.bfrt_info.table_get("$pre.mgid")
        self.mirror_cfg_tbl = self.bfrt_info.table_get("$mirror.cfg")

        # p4 tables
        self.ing_tbl = self.bfrt_info.table_get("MyIngress.ingress_port_forward")
        self.port_sampling_tbl = self.bfrt_info.table_get("MyIngress.port_sampling_rate")
        self.port_agent_tbl = self.bfrt_info.table_get("MyIngress.set_port_agent")
        self.ts_tbl = self.bfrt_info.table_get("MyIngress.t_set_ts")
        self.agent_status = self.bfrt_info.table_get("MyIngress.agent_status")

        # ---- NEW: counter + if_stats table (do not change other logic) ----
        self.port_in_ucast_pkts_tbl  = self.bfrt_info.table_get("MyIngress.port_in_ucast_pkts")
        self.port_in_multi_pkts_tbl  = self.bfrt_info.table_get("MyIngress.port_in_multi_pkts")
        self.port_in_broad_pkts_tbl  = self.bfrt_info.table_get("MyIngress.port_in_broad_pkts")
        self.port_out_ucast_pkts_tbl  = self.bfrt_info.table_get("MyIngress.port_out_ucast_pkts")
        self.port_out_multi_pkts_tbl  = self.bfrt_info.table_get("MyIngress.port_out_multi_pkts")
        self.port_out_broad_pkts_tbl  = self.bfrt_info.table_get("MyIngress.port_out_broad_pkts")
        self.port_in_bytes_tbl = self.bfrt_info.table_get("MyIngress.port_in_bytes")
        self.port_out_bytes_tbl = self.bfrt_info.table_get("MyIngress.port_out_bytes")
        
        self.start_time = None
        self.cleanUp()

    def runTest(self):
        self.start_time = time.time()
        self.up_ports_from_cfg()
        self.up_recirc_ports_from_cfg()
        self.apply_forwarding_from_cfg()
        self.apply_agent_status_from_cfg()
        self.apply_sampling_from_cfg()
        self.apply_port_agent_from_cfg()
        self.apply_mirror_cfg_from_cfg()
        self.apply_pre_from_cfg()
        self.apply_timestamp_from_cfg()

        # threads
        t1 = threading.Thread(target=self.send_pkt_every_second)
        t1.daemon = True
        t1.start()

        # 只有 timestamp.enable=true 才跑更新 thread
        if bool(self.cfg.get("timestamp", {}).get("enable", True)):
            t2 = threading.Thread(target=self.update_ts_every_second)
            t2.daemon = True
            t2.start()

        while True:
            time.sleep(1)


    def read_port_in_ucast_pkts(self, counter_index):
        k = self.port_in_ucast_pkts_tbl.make_key([
            gc.KeyTuple("$COUNTER_INDEX", int(counter_index))
        ])

        try:
            it = self.port_in_ucast_pkts_tbl.entry_get(self.dev_tgt, [k], {"from_hw": True})
            for data, key in it:
                d = data.to_dict()

                val = d.get("$COUNTER_SPEC_PKTS", 0)

                # Some BFRT versions may return nested dict for counter spec
                if isinstance(val, dict):
                    # try common keys
                    if "packets" in val:
                        return int(val.get("packets", 0))
                    if "pkts" in val:
                        return int(val.get("pkts", 0))
                    if "$COUNTER_SPEC_PKTS" in val:
                        return int(val.get("$COUNTER_SPEC_PKTS", 0))
                    # fallback: first numeric value
                    for _, vv in val.items():
                        if isinstance(vv, (int, long)):
                            return int(vv)

                return int(val)
            return 0
        except Exception as e:
            print("[counter] entry_get Error: {}".format(e))
            return 0
    
    def read_port_in_multi_pkts(self, counter_index):
        k = self.port_in_multi_pkts_tbl.make_key([
            gc.KeyTuple("$COUNTER_INDEX", int(counter_index))
        ])

        try:
            it = self.port_in_multi_pkts_tbl.entry_get(self.dev_tgt, [k], {"from_hw": True})
            for data, key in it:
                d = data.to_dict()

                val = d.get("$COUNTER_SPEC_PKTS", 0)

                # Some BFRT versions may return nested dict for counter spec
                if isinstance(val, dict):
                    # try common keys
                    if "packets" in val:
                        return int(val.get("packets", 0))
                    if "pkts" in val:
                        return int(val.get("pkts", 0))
                    if "$COUNTER_SPEC_PKTS" in val:
                        return int(val.get("$COUNTER_SPEC_PKTS", 0))
                    # fallback: first numeric value
                    for _, vv in val.items():
                        if isinstance(vv, (int, long)):
                            return int(vv)

                return int(val)
            return 0
        except Exception as e:
            print("[counter] entry_get Error: {}".format(e))
            return 0
        
    def read_port_in_broad_pkts(self, counter_index):
        k = self.port_in_broad_pkts_tbl.make_key([
            gc.KeyTuple("$COUNTER_INDEX", int(counter_index))
        ])

        try:
            it = self.port_in_broad_pkts_tbl.entry_get(self.dev_tgt, [k], {"from_hw": True})
            for data, key in it:
                d = data.to_dict()

                val = d.get("$COUNTER_SPEC_PKTS", 0)

                # Some BFRT versions may return nested dict for counter spec
                if isinstance(val, dict):
                    # try common keys
                    if "packets" in val:
                        return int(val.get("packets", 0))
                    if "pkts" in val:
                        return int(val.get("pkts", 0))
                    if "$COUNTER_SPEC_PKTS" in val:
                        return int(val.get("$COUNTER_SPEC_PKTS", 0))
                    # fallback: first numeric value
                    for _, vv in val.items():
                        if isinstance(vv, (int, long)):
                            return int(vv)

                return int(val)
            return 0
        except Exception as e:
            print("[counter] entry_get Error: {}".format(e))
            return 0
    
    def read_port_out_ucast_pkts(self, counter_index):
        k = self.port_out_ucast_pkts_tbl.make_key([
            gc.KeyTuple("$COUNTER_INDEX", int(counter_index))
        ])

        try:
            it = self.port_out_ucast_pkts_tbl.entry_get(self.dev_tgt, [k], {"from_hw": True})
            for data, key in it:
                d = data.to_dict()

                val = d.get("$COUNTER_SPEC_PKTS", 0)

                # Some BFRT versions may return nested dict for counter spec
                if isinstance(val, dict):
                    # try common keys
                    if "packets" in val:
                        return int(val.get("packets", 0))
                    if "pkts" in val:
                        return int(val.get("pkts", 0))
                    if "$COUNTER_SPEC_PKTS" in val:
                        return int(val.get("$COUNTER_SPEC_PKTS", 0))
                    # fallback: first numeric value
                    for _, vv in val.items():
                        if isinstance(vv, (int, long)):
                            return int(vv)

                return int(val)
            return 0
        except Exception as e:
            print("[counter] entry_get Error: {}".format(e))
            return 0
    
    def read_port_out_multi_pkts(self, counter_index):
        k = self.port_out_multi_pkts_tbl.make_key([
            gc.KeyTuple("$COUNTER_INDEX", int(counter_index))
        ])

        try:
            it = self.port_out_multi_pkts_tbl.entry_get(self.dev_tgt, [k], {"from_hw": True})
            for data, key in it:
                d = data.to_dict()

                val = d.get("$COUNTER_SPEC_PKTS", 0)

                # Some BFRT versions may return nested dict for counter spec
                if isinstance(val, dict):
                    # try common keys
                    if "packets" in val:
                        return int(val.get("packets", 0))
                    if "pkts" in val:
                        return int(val.get("pkts", 0))
                    if "$COUNTER_SPEC_PKTS" in val:
                        return int(val.get("$COUNTER_SPEC_PKTS", 0))
                    # fallback: first numeric value
                    for _, vv in val.items():
                        if isinstance(vv, (int, long)):
                            return int(vv)

                return int(val)
            return 0
        except Exception as e:
            print("[counter] entry_get Error: {}".format(e))
            return 0
        
    def read_port_out_broad_pkts(self, counter_index):
        k = self.port_out_broad_pkts_tbl.make_key([
            gc.KeyTuple("$COUNTER_INDEX", int(counter_index))
        ])

        try:
            it = self.port_out_broad_pkts_tbl.entry_get(self.dev_tgt, [k], {"from_hw": True})
            for data, key in it:
                d = data.to_dict()

                val = d.get("$COUNTER_SPEC_PKTS", 0)

                # Some BFRT versions may return nested dict for counter spec
                if isinstance(val, dict):
                    # try common keys
                    if "packets" in val:
                        return int(val.get("packets", 0))
                    if "pkts" in val:
                        return int(val.get("pkts", 0))
                    if "$COUNTER_SPEC_PKTS" in val:
                        return int(val.get("$COUNTER_SPEC_PKTS", 0))
                    # fallback: first numeric value
                    for _, vv in val.items():
                        if isinstance(vv, (int, long)):
                            return int(vv)

                return int(val)
            return 0
        except Exception as e:
            print("[counter] entry_get Error: {}".format(e))
            return 0
        
    def read_port_in_bytes(self, counter_index):
        k = self.port_in_bytes_tbl.make_key([
            gc.KeyTuple("$COUNTER_INDEX", int(counter_index))
        ])

        try:
            it = self.port_in_bytes_tbl.entry_get(self.dev_tgt, [k], {"from_hw": True})
            for data, key in it:
                d = data.to_dict()

                val = d.get("$COUNTER_SPEC_BYTES", 0)

                # Some BFRT versions may return nested dict for counter spec
                if isinstance(val, dict):
                    # try common keys
                    if "bytes" in val:
                        return int(val.get("bytes", 0))
                    if "$COUNTER_SPEC_BYTES" in val:
                        return int(val.get("$COUNTER_SPEC_BYTES", 0))
                    # fallback: first numeric value
                    for _, vv in val.items():
                        if isinstance(vv, (int, long)):
                            return int(vv)

                return int(val)
            return 0
        except Exception as e:
            print("[counter] entry_get Error: {}".format(e))
            return 0

    def read_port_out_bytes(self, counter_index):
        k = self.port_out_bytes_tbl.make_key([
            gc.KeyTuple("$COUNTER_INDEX", int(counter_index))
        ])

        try:
            it = self.port_out_bytes_tbl.entry_get(self.dev_tgt, [k], {"from_hw": True})
            for data, key in it:
                d = data.to_dict()

                val = d.get("$COUNTER_SPEC_BYTES", 0)

                # Some BFRT versions may return nested dict for counter spec
                if isinstance(val, dict):
                    # try common keys
                    if "bytes" in val:
                        return int(val.get("bytes", 0))
                    if "$COUNTER_SPEC_BYTES" in val:
                        return int(val.get("$COUNTER_SPEC_BYTES", 0))
                    # fallback: first numeric value
                    for _, vv in val.items():
                        if isinstance(vv, (int, long)):
                            return int(vv)

                return int(val)
            return 0
        except Exception as e:
            print("[counter] entry_get Error: {}".format(e))
            return 0
    # ----------------------------
    # apply: ports
    # ----------------------------
    def up_ports_from_cfg(self):
        p = self.cfg.get("ports", {})
        ports = p.get("dev_ports", [])
        ports = sorted(ports)
        if not ports:
            print("[ports] skip (no dev_ports)")
            return

        speed = p.get("speed", "BF_SPEED_10G")
        fec = p.get("fec", "BF_FEC_TYP_NONE")
        autoneg = p.get("autoneg", "PM_AN_FORCE_DISABLE")
        enable = bool(p.get("enable", True))

        try:
            keys = [
                self.port_table.make_key([gc.KeyTuple("$DEV_PORT", int(dp))])
                for dp in ports
            ]

            data = self.port_table.make_data([
                gc.DataTuple("$SPEED", str_val=str(speed)),
                gc.DataTuple("$FEC", str_val=str(fec)),
                gc.DataTuple("$AUTO_NEGOTIATION", str_val=str(autoneg)),
                gc.DataTuple("$PORT_ENABLE", bool_val=enable)
            ])

            self.port_table.entry_add(self.dev_tgt, keys, [data] * len(keys))
            for i in ports:
                print("[ports] port{} UP".format(i))
            # print("[ports] added+enabled: {} (speed={}, fec={}, enable={})".format(
            #     ports, speed, fec, enable
            # ))
        except Exception as e:
            print("[ports] Error: {}".format(e))
    # ----------------------------
    # apply: recirc ports
    # ----------------------------
    def up_recirc_ports_from_cfg(self):
        p = self.cfg.get("recirc_port", {})
        ports = p.get("dev_ports", [])
        ports = sorted(ports)
        if not ports:
            print("[ports] skip (no dev_ports)")
            return

        speed = p.get("speed", "BF_SPEED_100G")
        fec = p.get("fec", "BF_FEC_TYP_NONE")
        autoneg = p.get("autoneg", "PM_AN_FORCE_DISABLE")
        enable = bool(p.get("enable", True))

        try:
            keys = [
                self.port_table.make_key([gc.KeyTuple("$DEV_PORT", int(dp))])
                for dp in ports
            ]

            data = self.port_table.make_data([
                gc.DataTuple("$SPEED", str_val=str(speed)),
                gc.DataTuple("$FEC", str_val=str(fec)),
                gc.DataTuple("$AUTO_NEGOTIATION", str_val=str(autoneg)),
                gc.DataTuple("$PORT_ENABLE", bool_val=enable)
            ])

            self.port_table.entry_add(self.dev_tgt, keys, [data] * len(keys))
            for i in ports:
                print("[recirc_ports] recirc port{} UP".format(i))
            # print("[ports] added+enabled: {} (speed={}, fec={}, enable={})".format(
            #     ports, speed, fec, enable
            # ))
        except Exception as e:
            print("[recirc_ports] Error: {}".format(e))

    # ----------------------------
    # apply: forwarding
    # ----------------------------
    def apply_forwarding_from_cfg(self):
        rules = self.cfg.get("ports_config", [])
        if not rules:
            print("[forwarding] skip (no rules)")
            return

        keys = []
        datas = []
        port_map = {}
        for r in rules:
            in_p = int(r["ingress_port"])
            out_p = int(r["egress_port"])
            port_map[in_p] = out_p
            keys.append(self.ing_tbl.make_key([gc.KeyTuple("ig_intr_md.ingress_port", in_p)]))
            datas.append(self.ing_tbl.make_data([gc.DataTuple("port", out_p)], "MyIngress.set_out_port"))

        try:
            self.ing_tbl.entry_add(self.dev_tgt, keys, datas)
            print("[forwarding] rules written: {}".format(len(rules)))
            for key in sorted(port_map.keys()):
                print("[forwarding] Ingress port: {} -> Egress port: {}".format(key, port_map[key]))
        except Exception as e:
            print("[forwarding] Error: {}".format(e))

    # ----------------------------
    # apply: sampling rate
    # ----------------------------
    def apply_sampling_from_cfg(self):
        rules = self.cfg.get("ports_config", [])
        if not rules:
            print("[sampling] skip (no rules)")
            return

        keys = []
        datas = []
        port_map={}
        for r in rules:
            in_p = int(r["ingress_port"])
            rate = int(r["rate"]) - 1
            port_map[in_p] = rate
            keys.append(self.port_sampling_tbl.make_key([gc.KeyTuple("ig_intr_md.ingress_port", in_p)]))
            datas.append(self.port_sampling_tbl.make_data(
                [gc.DataTuple("sampling_rate", rate)],
                "MyIngress.set_sampling_rate"
            ))

        try:
            self.port_sampling_tbl.entry_add(self.dev_tgt, keys, datas)
            print("[sampling] rules written: {}".format(len(rules)))
            for key in sorted(port_map.keys()):
                print("[sampling] Ingress port: {} : Sampling Rate  = {}".format(key, port_map[key]+1))
        except Exception as e:
            print("[sampling] Error: {}".format(e))
    # ----------------------------
    # apply: agent_status
    # ----------------------------
    def apply_agent_status_from_cfg(self):
        rules = self.cfg.get("ports_config", [])
        if not rules:
            print("[agent_status] skip (no rules)")
            return

        keys = []
        datas = []
        port_map = {}
        for r in rules:
            in_p = int(r["ingress_port"])
            status = int(r["status"])
            if(status == 1):
                port_map[in_p] = "UP"
            else:
                 port_map[in_p] = "Down"

            keys.append(self.agent_status.make_key([gc.KeyTuple("ig_intr_md.ingress_port", in_p)]))
            datas.append(self.agent_status.make_data(
                [gc.DataTuple("status", status)],
                "MyIngress.set_agent_status"
            ))

        try:
            self.agent_status.entry_add(self.dev_tgt, keys, datas)
            print("[agent_status] rules written: {}".format(len(rules)))
            for key in sorted(port_map.keys()):
                print("[agent_status] Ingress port: {} : Agent status = {}".format(key, port_map[key]))
        except Exception as e:
            print("[agent_status] Error: {}".format(e))

    # ----------------------------
    # apply: port agent (based on hdr.sample.ingress_port)
    # ----------------------------
    def apply_port_agent_from_cfg(self):
        rules = self.cfg.get("ports_config", [])
        if not rules:
            print("[port_agent] skip (no rules)")
            return

        keys = []
        datas = []
        port_map={}
        for r in rules:
            in_p = int(r["ingress_port"])
            addr = _to_int(r["agent_addr"])
            agent_id = int(r["agent_id"])
            input_if = int(r["input_if"])
            port_map[in_p] = {
                "addr" : addr,
                "id" : agent_id,
                "input_if" : input_if
            }
            keys.append(self.port_agent_tbl.make_key([gc.KeyTuple("hdr.sample.ingress_port", in_p)]))
            datas.append(self.port_agent_tbl.make_data(
                [
                    gc.DataTuple("agent_addr", addr),
                    gc.DataTuple("agent_id", agent_id),
                    gc.DataTuple("input_if", input_if)
                ],
                "MyIngress.set_sample_hd"
            ))

        try:
            self.port_agent_tbl.entry_add(self.dev_tgt, keys, datas)
            print("[port_agent] rules written: {}".format(len(rules)))
            for key in sorted(port_map.keys()):
                print("[port_agent] Ingress port: {} -> agent_addr: {}, agent_id: {}, input_if:{}".format(key, port_map[key]["addr"],port_map[key]["id"],port_map[key]["input_if"]))
        except Exception as e:
            print("[port_agent] Error: {}".format(e))

    # ----------------------------
    # apply: mirror cfg (use your '$normal' style)
    # ----------------------------
    def apply_mirror_cfg_from_cfg(self):
        rules = self.cfg.get("mirror_cfg", [])
        if not rules:
            print("[mirror_cfg] skip (no rules)")
            return

        for r in rules:
            sid = r.get("sid")
            try:
                self.mirror_cfg_tbl.entry_add(
                    self.dev_tgt,
                    [self.mirror_cfg_tbl.make_key([
                        gc.KeyTuple("$sid", int(r["sid"]))
                    ])],
                    [self.mirror_cfg_tbl.make_data([
                        gc.DataTuple("$direction", str_val=str(r.get("direction", "INGRESS"))),
                        gc.DataTuple("$session_enable", bool_val=bool(r.get("session_enable", True))),
                        gc.DataTuple("$ucast_egress_port", int(r.get("ucast_egress_port", 0))),
                        gc.DataTuple("$ucast_egress_port_valid", bool_val=bool(r.get("ucast_egress_port_valid", True))),
                        gc.DataTuple("$max_pkt_len", int(r.get("max_pkt_len", 0)))
                    ], "$normal")]
                )
                print("[mirror_cfg] written: sid={} dir={} ucast={}".format(
                    r.get("sid"), r.get("direction"), r.get("ucast_egress_port")
                ))
            except Exception as e:
                print("[mirror_cfg] Error (sid={}): {}".format(sid, e))

    # ----------------------------
    # apply: PRE (optional)
    # ----------------------------
    def apply_pre_from_cfg(self):
        pre = self.cfg.get("pre", None)
        if not pre:
            print("[pre] skip (no config)")
            return

        node_id = int(pre.get("node_id", 1))
        mgid = int(pre.get("mgid", 1))
        rid = int(pre.get("rid", 1))
        dev_ports = [int(x) for x in pre.get("dev_ports", [])]

        if not dev_ports:
            print("[pre] skip (no dev_ports)")
            return

        # $pre.node
        try:
            self.pre_node_tbl.entry_add(
                self.dev_tgt,
                [self.pre_node_tbl.make_key([gc.KeyTuple("$MULTICAST_NODE_ID", node_id)])],
                [self.pre_node_tbl.make_data([
                    gc.DataTuple("$MULTICAST_RID", rid),
                    gc.DataTuple("$MULTICAST_LAG_ID", int_arr_val=[]),
                    gc.DataTuple("$DEV_PORT", int_arr_val=dev_ports)
                ])]
            )
            print("[pre.node] written: node_id={}, dev_ports={}".format(node_id, dev_ports))
        except Exception as e:
            print("[pre.node] Error: {}".format(e))

        # $pre.mgid
        try:
            self.pre_mgid_tbl.entry_add(
                self.dev_tgt,
                [self.pre_mgid_tbl.make_key([gc.KeyTuple("$MGID", mgid)])],
                [self.pre_mgid_tbl.make_data([
                    gc.DataTuple("$MULTICAST_NODE_ID", int_arr_val=[node_id]),
                    gc.DataTuple("$MULTICAST_NODE_L1_XID_VALID", bool_arr_val=[False]),
                    gc.DataTuple("$MULTICAST_NODE_L1_XID", int_arr_val=[0])
                ])]
            )
            print("[pre.mgid] written: mgid={} -> node_id={}".format(mgid, node_id))
        except Exception as e:
            print("[pre.mgid] Error: {}".format(e))

    # ----------------------------
    # apply: timestamp default entry
    # ----------------------------
    def apply_timestamp_from_cfg(self):
        ts_cfg = self.cfg.get("timestamp", {"enable": True, "init": 0})
        if not bool(ts_cfg.get("enable", True)):
            print("[timestamp] disabled by config")
            return

        init_ts = int(ts_cfg.get("init", 0))
        try:
            ts_data = self.ts_tbl.make_data([gc.DataTuple("ts", init_ts)], "MyIngress.set_ts")
            self.ts_tbl.default_entry_set(self.dev_tgt, ts_data)
            print("[timestamp] default init={}".format(init_ts))
        except Exception as e:
            print("[timestamp] Error: {}".format(e))

    # ----------------------------
    # threads
    # ----------------------------
    def send_pkt_every_second(self):
        count = 0
        # 1. 先從 config 讀取 agent_status 陣列，如果讀不到則給空陣列 []
        agent_status_list = self.cfg.get("ports_config", [])

        # 2. 使用 List Comprehension (列表推導式) 篩選出 status 為 1 的 ingress_port
        index_list = [
            item["ingress_port"] 
            for item in agent_status_list 
            if item.get("status") == 1
        ]

        # (選配) 印出來確認一下抓到了哪些 index
        print("Selected indices based on status=1: {}".format(index_list))
        input("按 Enter 後開始每秒送封包到 PTF port 320...\n")

        # 你要查的 counter index array
        # 你可以在 config.json 放:
        # "counter_indexes": [140,141,142]
        
        # index_list = self.cfg.get("counter_indexes", [188,189])

        while True:
            count += 1
            rules = self.cfg.get("ports_config", [])
            port_to_addr = {r["ingress_port"]: r["agent_addr"] for r in rules}
            port_to_input_if = {r["ingress_port"]: r["input_if"] for r in rules}
            # forward_rules = self.cfg.get("ports_config", [])

            ingress_to_egress = {r["ingress_port"]: r["egress_port"] for r in rules}            

            # 每秒送出 len(index_list) 個封包
            for idx in index_list:
                addr = port_to_addr[idx]
                input_if = port_to_input_if[idx]
                ip = socket.inet_ntoa(struct.pack("!I", int(addr, 16)))
                pkt = (
                    Ether(dst="00:0a:cd:3b:18:42", src="00:11:22:33:44:55") /
                    IP(src=ip, dst="10.10.10.248") /
                    UDP(sport=1234, dport=6343) /
                    "test"   # Python2: 用 str 就好，避免 b""
                )
                try:
                    in_byte  = self.read_port_in_bytes(idx)
                    out_byte = self.read_port_out_bytes(idx)
                    in_ucast = self.read_port_in_ucast_pkts(idx)
                    in_multi = self.read_port_in_multi_pkts(idx)
                    in_broad = self.read_port_in_broad_pkts(idx)
                    out_ucast = self.read_port_out_ucast_pkts(idx)
                    out_multi = self.read_port_out_multi_pkts(idx)
                    out_broad = self.read_port_out_broad_pkts(idx)
                    print("[counter] index={} in_pkts={} in_bytes={} out_pkts={} out_bytes={}".format(idx, in_ucast, in_byte,out_ucast,out_byte))

                    # 4B idx + 4B pkts + 4B bytes (network order)
                    prefix = struct.pack("!I", int(idx)) + struct.pack("!Q", int(in_byte)) + struct.pack("!Q", int(out_byte))
                    prefix = prefix + struct.pack("!I", int(in_ucast)) + struct.pack("!I", int(in_multi)) + struct.pack("!I", int(in_broad))
                    prefix = prefix + struct.pack("!I", int(out_ucast)) + struct.pack("!I", int(out_multi)) + struct.pack("!I", int(out_broad))
                    prefix = prefix + socket.inet_aton(ip) + struct.pack("!I", int(input_if))
                    # Python2: str(pkt) 是 raw bytes；不要用 bytes(pkt)
                    raw_pkt = prefix + bytes(pkt)

                    print("{}, send_packet() to port 320 (idx={})".format(count, idx))
                    send_packet(self, 320, raw_pkt)

                except Exception as e:
                    print("[counter] read/send Error (idx={}): {}".format(idx, e))

            time.sleep(1)

    def update_ts_every_second(self):
        print("[timestamp] start update thread")
        while True:
            elapsed_sec = int(time.time() - self.start_time)
            try:
                ts_data = self.ts_tbl.make_data([gc.DataTuple("ts", elapsed_sec)], "MyIngress.set_ts")
                self.ts_tbl.default_entry_set(self.dev_tgt, ts_data)
            except Exception as e:
                print("[timestamp] update Error: {}".format(e))
            time.sleep(1)

    def cleanUp(self):
        pass

    def tearDown(self):
        self.cleanUp()
        BfRuntimeTest.tearDown(self)
