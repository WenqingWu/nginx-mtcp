#!/bin/bash

./sbin/nginx -n 4 -r 0 >out.file 2>&1 &

for i in {1..3}
do
   sleep 15s
   ./sbin/nginx -n 4 -r $i >out$i.file 2>&1 &
done

