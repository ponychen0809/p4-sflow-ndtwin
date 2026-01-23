# p4-sflow-ndtwin

## compile
```
make build
```
## Config 設定
#### 開啟port
```
"ports": {
    "speed": "BF_SPEED_10G",
    "fec": "BF_FEC_TYP_NONE",
    "autoneg": "PM_AN_FORCE_DISABLE",
    "enable": true,
    "dev_ports": [156,157,158,159,160,161,162,163,164,165,166,167,168,169,
                  170,171,172,173,174,175,176,177,178,179,180,181,182,183,
                  184,185,186,187,188, 189,190,191,184]
  },
```
* 所有有接線的 port 都要把 port number 加到 dev_ports 的 array 中，用來開啟 port。
#### 設定 port agent 
```
"ports_config": [
    { "ingress_port": 188, "agent_id": 9, "status": 1, "egress_port": 189, "rate": 1000, "agent_addr": "0x0a0a0a18", "input_if" : 25},
    { "ingress_port": 189, "agent_id": 5, "status": 1, "egress_port": 188, "rate": 1000, "agent_addr": "0x0a0a0a14", "input_if" : 25},
    { "ingress_port": 190, "agent_id": 9, "status": 1, "egress_port": 191, "rate": 1000, "agent_addr": "0x0a0a0a18", "input_if" : 26},
    { "ingress_port": 191, "agent_id": 6, "status": 1, "egress_port": 190, "rate": 1000, "agent_addr": "0x0a0a0a15", "input_if" : 25},
  ],
```
* ingress_port：線接到哪個 port number。
* agent_id：取代的agent id。
* status：1 = up ，0 = down。
* egress_port：從這個 ingress port進來的 packet 要從個 port 送出。
* rate：sampling rate。
* agent_addr：取代的agent address。
* input_if：取代交換機的哪個 port。

**取代的 agent 就是 egress port 連到哪個 switch，哪個port，就是取代這個 port 的 agent， 因為是 ingress sampling**
## Run
* Terminal 1 run bfrt
```
make bfrt
```
* Terminal 2 run BfRuntime (gRPC)
```
make test
```

## BFRT (Terminal 1) 相關指令
* 查看各 port 狀態
```
bfshell> ucli
bf-sde> pm
bf-sde.pm> show 

//也可用打help查看相關指令
```
