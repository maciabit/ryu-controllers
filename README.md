# Virtual machine setup

- Install required packages
  ```
  sudo apt update
  sudo apt upgrade
  sudo apt install openvswitch-switch
  sudo apt install net-tools
  sudo apt install git
  sudo apt install python3-pip python3-dev build-essential curl
  sudo pip3 install --upgrade pip
  sudo apt install python3-eventlet python3-routes python3-webob python3-paramiko
  ```

- Install mininet
  ```
  git clone https://github.com/mininet/mininet
  cd mininet
  git checkout -b mininet-2.3.0
  cd ..
  sudo mininet/util/install.sh -a
  ```

- Install Ryu
  ```
  git clone https://github.com/faucetsdn/ryu.git
  cd ryu
  sudo python3 ./setup.py install
  sudo pip3 install -r tools/pip-requires
  ```
