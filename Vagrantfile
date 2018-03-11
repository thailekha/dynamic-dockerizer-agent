# curl -L https://github.com/docker/compose/releases/download/1.17.0/docker-compose-`uname -s`-`uname -m` -o /usr/bin/docker-compose
Vagrant.configure("2") do |config|
  common_config = ->(config) do
    config.vm.hostname="vagrant"
    config.vm.box = "ubuntu/trusty64"
    config.vm.box_check_update = false
    config.vbguest.auto_update = false

    config.vm.synced_folder ".", "/mnt/vagrant"

    config.vm.provider "virtualbox" do |v|
      v.customize ["modifyvm", :id, "--cpuexecutioncap", "100"]
      v.customize ["modifyvm", :id, "--memory", "512"]
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

  install_docker = ->(config) do
    config.vm.provision "shell", inline: <<-SHELL
      apt-get update && sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common
      curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
      apt-key fingerprint 0EBFCD88 | grep docker@docker.com || exit 1
      add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
      apt-get update
      apt-get install -y docker-ce
      docker --version

      curl -L https://github.com/docker/compose/releases/download/1.18.0/docker-compose-`uname -s`-`uname -m` -o /usr/bin/docker-compose
      chmod +x /usr/bin/docker-compose
      docker-compose --version
    SHELL
  end

  pull_docker_images = ->(config) do
    config.vm.provision "shell", inline: <<-SHELL
      docker pull ubuntu:14.04
    SHELL
  end

  install_mongo = ->(config) do
    config.vm.provision "shell", inline: <<-SHELL
      apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv EA312927
      echo "deb http://repo.mongodb.org/apt/ubuntu trusty/mongodb-org/3.2 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-3.2.list
      apt-get -y update
      apt-get -y install mongodb-org
    SHELL
  end

  install_common = ->(config) do
    config.vm.provision "shell", inline: <<-SHELL
      apt-get -y install git dpkg-repack tree build-essential apt-rdepends
    SHELL
  end

  install_nginx = ->(config) do
    config.vm.provision "shell", inline: <<-SHELL
      apt-get -y install nginx
    SHELL
  end

  install_node = ->(config) do
    config.vm.provision "shell", inline: <<-SHELL
      curl -sL https://deb.nodesource.com/setup_8.x | sudo -E bash -
      apt-get install -y nodejs
      npm i -g yarn
    SHELL
  end

  install_rails_dev = ->(config) do
    config.vm.provision "shell", inline: <<-SHELL
      apt-add-repository -y ppa:brightbox/ruby-ng
      apt-get -y update
      apt-get -y install ruby2.4 ruby2.4-dev
      update-alternatives --set ruby /usr/bin/ruby2.4
      update-alternatives --set gem /usr/bin/gem2.4
      gem update --system -N
      gem install bundler -N
      apt-get -y install sqlite3 libsqlite3-dev
      apt-get -y install memcached memcached
      apt-get -y install redis-server
    SHELL
  end
  
  ecs_nginx = ->(config) do
    config.vm.provision "shell", inline: <<-SHELL
      cd /mnt/vagrant/ecs-auth-microservice && cp ./nginx/nginx.conf /etc/nginx/nginx.conf
    SHELL
  end

  install_ecs = ->(config) do
    config.vm.provision "shell", privileged: false, inline: <<-SHELL
      cd /mnt/vagrant/ecs-auth-microservice/app && yarn install
    SHELL
  end

  # install_gantry = ->(config) do
  #   config.vm.provision "shell", privileged: false, inline: <<-SHELL
  #     cd /mnt/vagrant/gantry && yarn install
  #   SHELL
  # end

  install_gantry = ->(config) do
    config.vm.provision "shell", privileged: false, inline: <<-SHELL
      cd ~ && git clone https://github.com/StephenCoady/gantry.git && cd gantry && yarn install
    SHELL
  end

  install_devbox = ->(config) do
    config.vm.provision "shell", privileged: false, inline: <<-SHELL
      cd /mnt/vagrant && yarn install
    SHELL
  end

  config.vm.define "devbox" do |devbox|
    common_config[devbox]
    forward_port[8081]
    forward_port[3001]

    fix_tty[devbox]
    install_docker[devbox]
    pull_docker_images[devbox]
    install_mongo[devbox]
    install_common[devbox]
    install_nginx[devbox]
    install_node[devbox]
  end

  config.vm.define "before" do |before|
    common_config[before]
    # # forward_port[49153]     # vm2docker agent
    #forward_port[8777, 18777]
    forward_port[8888, 9000]

    fix_tty[before]
    install_docker[before]
    pull_docker_images[before]
    install_mongo[before]
    install_common[before]
    install_nginx[before]
    install_node[before]
    ecs_nginx[before]
    install_ecs[before]
  end

  config.vm.define "after" do |after|
    common_config[after]
    #forward_port[8777, 28777]
    forward_port[8888, 9001]

    fix_tty[after]
    install_docker[after]
    pull_docker_images[after]
    install_mongo[after]
    install_common[after]
    install_nginx[after]
    install_node[after]
    ecs_nginx[after]
    install_ecs[after]
  end

  config.vm.define "gantry" do |gantry|
    common_config[gantry]

    fix_tty[gantry]
    install_docker[gantry]
    pull_docker_images[gantry]
    install_common[gantry]
    install_node[gantry]
    install_gantry[gantry]
  end

  config.vm.define "test_dcompose" do |test_dcompose|
    common_config[test_dcompose]

    fix_tty[test_dcompose]
    install_docker[test_dcompose]
    install_common[test_dcompose]
    install_node[test_dcompose]
    install_ecs[test_dcompose]
  end
end