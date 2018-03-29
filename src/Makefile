
default:	build

clean:
	rm -rf Makefile objs

build:
	$(MAKE) -f objs/Makefile

install:
	$(MAKE) -f objs/Makefile install

modules:
	$(MAKE) -f objs/Makefile modules

upgrade:
	/root/work/mtcp-master/apps/nginx-1.10-self/install-dir/sbin/nginx -t

	kill -USR2 `cat /root/work/mtcp-master/apps/nginx-1.10-self/install-dir/logs/nginx.pid`
	sleep 1
	test -f /root/work/mtcp-master/apps/nginx-1.10-self/install-dir/logs/nginx.pid.oldbin

	kill -QUIT `cat /root/work/mtcp-master/apps/nginx-1.10-self/install-dir/logs/nginx.pid.oldbin`
