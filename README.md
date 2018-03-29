# nginx-mtcp
nginx-1.10.3移植到用户态协议栈mTCP

使用说明

## 物理环境部署

### 直连方式

1.接口直连

    以万兆网卡为例，用光纤线将需要通信的两台物理服务器的网卡接口进行正确直连，

2.IP设置

    IP地址的设置旨在将通信接口设为同一网段，例如可以将mTCP应用和client端所在网段设为10.0.1.0/24。首先需要手动设置作为client端的服务器上直连接口的IP和掩码，而mTCP应用所在服务器上的接口IP是在DPDK部署的时候设置的。

3.ARP设置

    由于mTCP目前尚不支持自动获取ARP，所以需要手动添加。首先在client端的服务器上添加ARP，用到的命令为arp，如#arp -s <IP address> <mac address>，mTCP应用所在服务器的ARP会在相应的arp.conf文件中添加。

### 交换机连接方式(待更新)

## 服务器端软件环境部署

### DPDK编译部署

以dpdk-16.11为例，这里使用dpdk自带脚本

(1)运行dpdk-setup.sh

    # ./dpdk-16.11/tools/dpdk-setup.sh

(2)按如下选项操作

    a) 输入 13， 编译源码包
    b) 输入 16， 安装igb_uio
    c) 输入 20， 预留大内存页
    d) 输入 22， 绑定网卡
    e) 输入 33， 退出dpdk-setup.sh

(3)设置绑定网卡的IP，例如绑定了两个网卡，IP分别设为10.0.0.4和10.0.1.4，命令如下

    # ./dpdk-16.11/tools/setup_iface_single_process.sh 4

(4)进入dpdk/,创建软连接

    # cd dpdk/
    # ln -s <path_to_dpdk_16_11_directory>/x86_64-native-linuxapp-gcc/lib lib
    # ln -s <path_to_dpdk_16_11_directory>/x86_64-native-linuxapp-gcc/include include

### mTCP编译部署 

(1)编译mTCP库

    # ./configure --with-dpdk-lib=$<path_to_mtcp_release>/dpdk
    # make

(2)检查mTCP编译是否成功

    a) mtcp/lib/ 目录下生成了libmtcp.a 
    b) mtcp/include/ 目录下生成了头文件
    c) apps/example/ 目录下生成了示例程序的二进制文件

## 软件运行方法 

### 编译服务器软件

(1)移植开发的Nginx源码文件放在mTCP源码中的apps/ 目录下

(2)进入Nginx目录，编译安装服务器软件

    a)# ./configure --prefix=$<path_to_mtcp_release>/apps/nginx-xxx/install-dir --with-mtcp<path to mtcp release>/
    b)# make
    c)# make install

### 进入安装目录，添加配置文件

(1)添加mTCP配置文件

    # cp $<path_to_mtcp_release>/config/sample-mtcp.conf mtcp.conf
    （若采用多进程模式，还需要添加mtcp_master.conf和mtcp_slave.conf）

(2)添加路由和ARP配置

    a)# mkdir config && cd config
    b)# cp $<path_to_mtcp_release>/config/sample-route.conf route.conf
    c)# cp $<path_to_mtcp_release>/config/sample-arp.conf arp.conf
    d)根据需要，分别编辑route.conf和arp.conf

(3)修改nginx配置

    a)# cd conf/
    b)编辑配置文件nginx.conf

  注意：
       以上三步操作可以直接运行自己写的shell脚本setting.sh完成(nginx-xxx/config-tmp/ 目录下是自己根据nginx运行要求，给出的配置文件和软件运行脚本的样例)

### 运行服务器软件

1.单进程mtcp-nginx的运行方法

  进入安装目录install-dir/，根据需要，调整mtcp.conf和conf/nginx.conf,运行可执行二进制文件，如

     # ./sbin/nginx -n 4
     1) -n: 使用的cpu数目，与 mtcp.conf 中 num_cores 选项要一致

2.multi-process模式的运行方法

  进入安装目录install-dir/，根据需要，调整mtcp_master.conf、mtcp_slave.cong以及conf/nginx.conf的配置参数,运行可执行二进制文件sbin/nginx，如

     # ./sbin/nginx -n 4 -r 0 
       for i in {1..3}
       do 
           ./sbin/nginx -n 4 -r $i
       done
    1) -n: 使用的cpu数目，与 mtcp.conf 中 num_cores 选项要一致
    2）-r: 当前进程运行的cpu核

  注意：

    1) 由于启动一个进程后，终端被占据，会影响后续进程启动，所以建议启动进程时放在后台运行，并将后台运行时产生的大量输出重定向到某个文件中，下面是自己写的一个多进程启动的简单脚本：
           #!/bin/bash
           #
           ./sbin/nginx -n 4 -r 0 >out.file 2>&1 &
           for i in {1..3}
           do
               sleep 15s
               ./sbin/nginx -n 4 -r $i >out$i.file 2>&1 &
           done
    2) 同时kill所有进程，可以使用命令：
       # kill -9 $(pidof nginx)

可以在client端向目的地址（即上述步骤配置的接口IP）发送http请求，查看请求结果
