#!/bin/bash

sudo dnf repolist
sudo dnf config-manager --set-enabled extras
sudo dnf install -y firewalld
sudo systemctl start firewalld

ports=(9090 9300 443 80 22)

for port in "${ports[@]}"; do
   sudo firewall-cmd --zone=public --add-port=${port}/tcp --permanent
done

sudo firewall-cmd --reload

