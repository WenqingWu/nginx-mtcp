
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
/*****************FLAG******************/
#include <assert.h>
#include <numa.h>
#include <unistd.h>
#define MAX_FILE_NAME 1024


#if (NGX_HAVE_CPUSET_SETAFFINITY)

void
ngx_setaffinity(ngx_cpuset_t *cpu_affinity, ngx_log_t *log)
{
    ngx_uint_t  i;

    for (i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, cpu_affinity)) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                          "cpuset_setaffinity(): using cpu #%ui", i);
        }
    }

    if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
                           sizeof(cpuset_t), cpu_affinity) == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "cpuset_setaffinity() failed");
    }
}

#elif (NGX_HAVE_SCHED_SETAFFINITY)

void
ngx_setaffinity(ngx_cpuset_t *cpu_affinity, ngx_log_t *log)
{
    ngx_uint_t  i;

    for (i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, cpu_affinity)) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                          "sched_setaffinity(): using cpu #%ui", i);
        }
    }

    if (sched_setaffinity(0, sizeof(cpu_set_t), cpu_affinity) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "sched_setaffinity() failed");
    }
}
/*****************FLAG******************/
int
mtcp_ngx_setaffinity(ngx_cpuset_t *cpu_affinity, ngx_log_t *log, int cpu)
{
	ngx_uint_t  i;
	
	int ret;
	struct bitmask *bmask;
/*	FILE *fp;
	char sysfname[MAX_FILE_NAME];
	int phy_id;
*/
    for (i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, cpu_affinity)) {
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                          "sched_setaffinity(): using cpu #%ui", i);
        }
    }
	ret = sched_setaffinity(0, sizeof(cpu_set_t), cpu_affinity);
	if(ret == -1) {
		ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "sched_setaffinity() failed");
	}
	if (numa_max_node() == 0)
		return ret;
	bmask = numa_bitmask_alloc(16);
	assert(bmask);
/*

	snprintf(sysfname, MAX_FILE_NAME - 1, 
		"/sys/devices/system/cpu/cpu%d/topology/physical_package_id", cpu);
	
	fp = fopen(sysfname, "r");
	if(!fp) {
		ngx_log_error(NGX_LOG_NOTICE, log, 0,
                          "open file cpu%d/topology/physical_package_id failed", cpu);
		return -1;
	}
*/
	numa_bitmask_setbit(bmask, cpu % 2);
	numa_set_membind(bmask);
	numa_bitmask_free(bmask);

	return ret;
}

#endif

int 
core_affinitize(int core)
{
	cpu_set_t *cmask;
	struct bitmask *bmask;
	//size_t n;
	int ret;

	//n = sysconf(_SC_NPROCESSORS_ONLN);

	if (core < 0 || core >= (int)core_limit) {
		printf("cpu index error, core affinitize failed.\n");
		return -1;
	}

	cmask = CPU_ALLOC(core_limit);
	if (cmask == NULL) {
		printf("core affinitize failed.\n");
		return -1;
	}

	CPU_ZERO_S(core_limit, cmask);
	CPU_SET_S(core, core_limit, cmask);

	ret = sched_setaffinity(0, core_limit, cmask);

	CPU_FREE(cmask);

	if (numa_max_node() == 0)
		return ret;

	bmask = numa_bitmask_alloc(16);
	assert(bmask);

	numa_bitmask_setbit(bmask, core % 2);
	numa_set_membind(bmask);
	numa_bitmask_free(bmask);

	return ret;
}
