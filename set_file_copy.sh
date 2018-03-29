#!/bin/bash

mkdir -p install-dir/config
cp config-tmp/mtcp.conf install-dir/
cp config-tmp/mtcp-multiprocess.conf install-dir/
cp config-tmp/nginx-start.sh install-dir/
cp config-tmp/route.conf install-dir/config/
cp config-tmp/arp.conf install-dir/config/

rm -f install-dir/conf/nginx.conf
cp config-tmp/nginx.conf install-dir/conf/

