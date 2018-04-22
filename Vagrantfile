# curl -L https://github.com/docker/compose/releases/download/1.17.0/docker-compose-`uname -s`-`uname -m` -o /usr/bin/docker-compose
Vagrant.configure("2") do |config|
  common_config = ->(config) do
    config.vm.hostname="vagrant"
    config.vm.box_check_update = false
    config.vbguest.auto_update = false

    config.vm.synced_folder ".", "/mnt/vagrant"
    config.vm.synced_folder "/home/tle/playground/gantry-thai", "/mnt/gantry"

    config.vm.provider "virtualbox" do |v|
      v.customize ["modifyvm", :id, "--cpuexecutioncap", "100"]
      v.customize ["modifyvm", :id, "--memory", "1024"]
    end    
  end

  forward_port = ->(guest, host = guest) do
    config.vm.network :forwarded_port,
      guest: guest,
      host: host,
      auto_correct: true
  end

  fix_tty = ->(config) do
    config.vm.provision "fix-no-tty", type: "shell" do |s|
      s.privileged = false
      s.inline = "sudo sed -i '/tty/!s/mesg n/tty -s \\&\\& mesg n/' /root/.profile"
    end
  end

  install_programs = ->(config) do
    config.vm.provision "shell", inline: <<-SHELL
      curl -sL https://deb.nodesource.com/setup_6.x | sudo -E bash -
      apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv EA312927
      echo "deb http://repo.mongodb.org/apt/ubuntu trusty/mongodb-org/3.2 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-3.2.list

      apt-get update
      apt-get install --no-install-recommends --no-install-suggests -y nodejs mongodb-org nginx tree build-essential apt-rdepends
      npm i -g yarn

      apt-get install --no-install-recommends --no-install-suggests -y apt-transport-https ca-certificates curl software-properties-common
      curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
      apt-key fingerprint 0EBFCD88 | grep docker@docker.com || exit 1
      add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
      apt-get update
      apt-get install --no-install-recommends --no-install-suggests -y docker-ce
      docker --version
    SHELL
  end

  prepare = ->(config) do
    config.vm.provision "shell", inline: <<-SHELL
      cd / && tar -c --exclude=mnt --exclude=sys --exclude=proc --exclude=dev --exclude=var/lib/docker . | docker import - vmimage
      docker pull ubuntu:14.04
    SHELL
  end

  install_devbox = ->(config) do
    config.vm.provision "shell", privileged: false, inline: <<-SHELL
      cd /mnt/vagrant && yarn install
    SHELL
  end

  config.vm.define "devbox" do |devbox|
    devbox.vm.box = "ubuntu/trusty64"
    common_config[devbox]
    forward_port[8081]
    forward_port[3001]

    fix_tty[devbox]
    install_programs[devbox]
    prepare[devbox]
    install_devbox[devbox]
  end

  config.vm.define "ddagent" do |ddagent|
    ddagent.vm.box = "thailekha/ddagent"
    common_config[ddagent]
    forward_port[8081]
    forward_port[3001]
  end
end