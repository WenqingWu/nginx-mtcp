
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
	/home/wenqing/work/mtcp-new/apps/nginx-1.10.3/install-dir/sbin/nginx -t

	kill -USR2 `cat /home/wenqing/work/mtcp-new/apps/nginx-1.10.3/install-dir/logs/nginx.pid`
	sleep 1
	test -f /home/wenqing/work/mtcp-new/apps/nginx-1.10.3/install-dir/logs/nginx.pid.oldbin

	kill -QUIT `cat /home/wenqing/work/mtcp-new/apps/nginx-1.10.3/install-dir/logs/nginx.pid.oldbin`
