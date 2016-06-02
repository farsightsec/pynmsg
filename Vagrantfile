#e -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"
VAGRANTFILE_LOCAL = 'Vagrantfile.local'

# https://www.farsightsecurity.com/Technical/SIE_Software_Installation_Debian/

$script = <<SCRIPT
sudo wget -O /etc/apt/trusted.gpg.d/debian-farsightsec.gpg https://dl.farsightsecurity.com/debian/archive.pubkey
echo "deb http://dl.farsightsecurity.com/debian wheezy-farsightsec main" | sudo tee /etc/apt/sources.list.d/debian-farsightsec.list
sudo add-apt-repository ppa:fkrull/deadsnakes-python2.7
sudo apt-get update
sudo apt-get install -y libffi-dev libssl-dev python-pip python-dev git htop virtualenvwrapper python2.7 python-virtualenv python-support build-essential libnmsg-dev python-nmsg libpcap-dev axa-tools libaxa-dev nmsgtool nmsg-msg-module-sie-dev libwdns-dev nmsg-msg-module-sie python-nmsg python-wdns pkg-config
sudo pip install requests --upgrade
sudo pip install pip --upgrade
sudo pip install vex cython
SCRIPT


Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = 'ubuntu/trusty64'
  config.vm.provision "shell", inline: $script
  
  config.vm.provider :virtualbox do |vb|
    vb.customize ["modifyvm", :id, "--cpus", "2", "--ioapic", "on", "--memory", "512" ]
  end

  if File.file?(VAGRANTFILE_LOCAL)
    external = File.read VAGRANTFILE_LOCAL
    eval external
  end
end
