#!/bin/sh

#Generic Dependencies
sudo apt update
sudo apt install -y build-essential
sudo apt install -y gcc make python-minimal libssl-dev git python-pip wget unzip

#Install Seccure
sudo apt-get install -y libgmp-dev build-essential python-dev python-pip libmpfr-dev libmpc-dev
pip install seccure

#Install Ryu
pip install ryu

#Install pcap
sudo apt install -y libpcap-dev

#Selenium Dependencies
#Install Chrome

wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install -y ./google-chrome-stable_current_amd64.deb

#Install Chrome Driver
version="`wget -qO- https://chromedriver.storage.googleapis.com/LATEST_RELEASE`"
echo ${version}
baseUrl="https://chromedriver.storage.googleapis.com"
compUrl="${baseUrl}/${version}"
comStr="wget -N  ${compUrl}/chromedriver_linux64.zip"
${comStr}

unzip ./chromedriver_linux64.zip -d /tmp/
sudo mv -f /tmp/chromedriver /usr/local/bin/
sudo chmod +x /usr/local/bin/chromedriver

pip install scapy selenium

#Install scapy, selenium smtplib and imap modules
pip install scapy easyimap

#Finally Let's build actual code.

#Build Client
cd main
cd ./client/c
make
#Build proxy
cd ../../
cd ./proxy/
make center
make single_conn
cd ../
#
