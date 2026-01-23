sudo ip address add 10.10.2.1/24 dev enp6s0
echo reload
sudo $SDE_INSTALL/bin/bf_kdrv_mod_unload
sudo $SDE_INSTALL/bin/bf_kpkt_mod_load $SDE_INSTALL

echo PCIE:
CPU_PCIE=`basename /sys/module/bf_kpkt/drivers/pci\:bf/*/net/*`
sudo ip link set ${CPU_PCIE} up
echo ${CPU_PCIE}

echo ETHER:
sudo modprobe ixgbe
for x in /sys/module/ixgbe/drivers/pci\:ixgbe/*/net/*; do
    basename ${x};
    sudo ip link set `basename ${x}` up
done
sudo ip address add 10.10.2.2/24 dev enp4s0f0
sudo ip address add 10.10.2.3/24 dev enp4s0f1