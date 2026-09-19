# Review addresses and paths before importing.
# VelaDNS replaces the existing DNS container at 172.16.0.100.

/interface/veth/add name=veth-veladns address=172.16.0.100/16 gateway=172.16.0.1
/interface/bridge/port/add bridge=br-container interface=veth-veladns

/container/envs/add list=veladns key=AUTO_FORWARD value=172.16.0.101
/container/envs/add list=veladns key=LOG_LEVEL value=warn

/container/mounts/add list=veladns src=/container/veladns/data dst=/data

/container/add name=veladns \
  remote-image=ghcr.io/hyird/veladns:latest \
  interface=veth-veladns \
  root-dir=/container/veladns/root \
  envlists=veladns \
  mountlists=veladns \
  start-on-boot=yes \
  logging=yes

# Start the container only after the image extraction has completed.
# /container/start [find where name=veladns]
# /ip/dns/set servers=172.16.0.100 allow-remote-requests=yes
# Prometheus metrics: http://172.16.0.100:5308/metrics
# Restrict access to port 5308 to trusted monitoring hosts.

# Defense in depth: never expose the RouterOS recursive resolver on WAN.
/ip/firewall/filter/add chain=input in-interface-list=WAN protocol=udp dst-port=53 action=drop comment="veladns: block public UDP DNS"
/ip/firewall/filter/add chain=input in-interface-list=WAN protocol=tcp dst-port=53 action=drop comment="veladns: block public TCP DNS"
