sudo ip addr add 192.168.57.16/24 dev toto0
sudo ifconfig toto0 up
sudo sysctl net.ipv4.ip_forward=1
sudo route del -net 192.168.57.0 netmask 255.255.255.0 dev toto0
sudo route add -net 192.168.57.15 netmask 255.255.255.255 dev toto0
sudo route add -net 192.168.56.0 netmask 255.255.255.0 dev toto0
sudo route add -net 192.168.58.0 netmask 255.255.255.0 dev toto0
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -t nat -A POSTROUTING -j MASQUERADE -o eth17