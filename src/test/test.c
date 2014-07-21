/*
 * DPRIO (deferred set priority) test.
 *
 * Copyright (c) 2014 Sergey Oboguev
 *
 * User-level DPRIO test code is dual-licensed under GPL2 and
 * "use as you want" license described below. The user of this code is
 * free to choose whether to use user-level DPRIO test under GPL2
 * or under "use as you want" license.
 *
 * "Use as you want" license terms are:
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this source file (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software
 * is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/*
 * Tests legend:
 *
 * 	setnow		test dprio_setnow(..., DPRIO_FORCE)
 *
 * 	invalid_ku	test dprio with invalid ku area pointer
 *
 *	voluntary	test priority change via dprio when voluntary
 *			preemption is attempted
 *
 *	random-slow     test priority change via dprio by changing work threads
 *			priority at random and then first waiting for
 *			involuntary preemption, and if it does not happen
 *			within a short time interval, then via voluntary
 *			preemption
 *
 *	random-fast     test priority change via dprio by changing work threads
 *			priority at random in a tight cycle
 *
 *	updown2		work threads execute repetitve pattern to change
 *			priority up and then down to the original level
 *
 *	updown4a	work threads execute repetitve pattern to change
 *			priority up, up again, down, down again to the
 *			original level
 *
 *	updown4b	similar to updown4a, but mutual relationship of
 *			priority levels is different
 *
 *	imm-updown2	similar to regular updownxxx, but uses
 *	imm-updown4a	regular sched_setattr(2) instead of dprio
 *      imm-updown4b
 *
 * Running DPRIO tests requires the use of RT priority.
 * If you do not want to run the test as root and do not want to elevate
 * rlimits, you can grant CAP_SYS_NICE to the test executable instead:
 *
 *	sudo setcap cap_sys_nice+eip test
 *
 */

#define _GNU_SOURCE
// #define __USE_GNU
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sched.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/time.h>
#include <sys/syscall.h>
// #include <linux/time.h>
#include "../userlib/dprio.h"

#ifndef CLOCK_MONOTONIC_RAW
  #define CLOCK_MONOTONIC_RAW	4
#endif

typedef int bool;

#ifndef true
  #define true 1
#endif

#ifndef false
  #define false 0
#endif

#ifndef PR_SET_DEFERRED_SETPRIO
 #define PR_SET_DEFERRED_SETPRIO	43
#endif

#define NSEC_PER_SEC	(1000ul * 1000ul * 1000ul)
#define NSEC_PER_MSEC	(1000ul * 1000ul)

#define CHECK(cond)  do { if (! (cond))  goto cleanup; } while (0)
#define streq(s1, s2)  (0 == strcmp((s1), (s2)))

static inline pid_t gettid(void)
{
	return syscall(SYS_gettid);
}

typedef struct __thread_context
{
	int nt;
}
thread_context_t;

#define TEST_RUN_TIME_SEC 100

static thread_context_t *create_thread_context(void);
static void destroy_thread_context(thread_context_t *ctx);
static void test_setnow(void);
static void test_invalid_ku(void);
static void test_voluntary(void);
static void test_random_slow(void);
static void test_random_fast(void);
static void test_updown(int test_id);
static void *thread_main_random_slow(void *arg);
static void *thread_main_random_fast(void *arg);
static void *thread_main_updown(void *arg);
static int onerror(int error, int err_pl, unsigned long err_errctx,
		   int new_pl, unsigned long new_errctx,
		   int recoverable);
static bool sched_attr_cmp(const struct sched_attr *a1,
			   const struct sched_attr *a2);
static bool equal_sched(const struct sched_attr *a1,
			const struct sched_attr *a2);
static void updown_snap_stat(void);
static bool init_smp_info(void);
static bool barrier(pthread_barrier_t* barrier);
static void create_threads(void* (*proc)(void *arg));
static void show_cpu_range(int nr, int nc1, int nc2);
static void reap_threads(void);
static void prio_set(int pl);
static void fatal_errno(const char *msg, int errcode);
static void fatal(const char *msg);
static void fatal_msg(const char *msg);
static void out_of_memory(void);
static thread_context_t *create_thread_context(void);
static void destroy_thread_context(thread_context_t *ctx);
static void *xmalloc(size_t size);
static void sleep_msec(int ms);
static void usage(void);
static void print_separator(void);

static int ncpus = 0;
static int reserved_cpus;
static int nthreads;
static cpu_set_t smp_all_cpu_set;
static cpu_set_t test_cpu_set;
static dprio_threadgroup_t tg = NULL;
static dprio_perthread_set_t pset = NULL;
static int minpl, maxpl;
static struct sched_attr *plsched;
static volatile bool abort_flag = false;
static pthread_barrier_t barrier_ntp1;
static int random_fd;
static int locked = false;
static int test_selector = 0;
const static clockid_t clk_id = CLOCK_MONOTONIC;
const static test_random_slow_sec = TEST_RUN_TIME_SEC;
const static test_random_fast_sec = TEST_RUN_TIME_SEC;
const static test_updown_sec = TEST_RUN_TIME_SEC;
static pthread_t* threads = NULL;
static int updown_down;
static int updown_up1, updown_up2, updown_up3;
static int s_test_id;

static struct __random_slow_stat {
	unsigned long total_up;
	unsigned long total_down;
	unsigned long total_eq;
	unsigned long voluntary_up;
	unsigned long voluntary_down;
	unsigned long voluntary_eq;
	unsigned long involuntary_up;
	unsigned long involuntary_down;
	unsigned long involuntary_eq;
	unsigned long immediate_up;
	unsigned long immediate_down;
	unsigned long immediate_eq;
} random_slow_stat __attribute__ ((aligned (8)));

static struct __random_fast_stat {
	unsigned long total;
} random_fast_stat __attribute__ ((aligned (8)));

static struct __updown_stat {
	unsigned long total;
	unsigned long rt;
	unsigned long nonrt;
} updown_stat __attribute__ ((aligned (8)));

enum {
	TEST_SETNOW = 1,
	TEST_INVALID_KU,
	TEST_VOLUNTARY,
	TEST_RANDOM_SLOW,
	TEST_RANDOM_FAST,
	TEST_UPDOWN2,
	TEST_UPDOWN4A,
	TEST_UPDOWN4B,
	TEST_IMM_UPDOWN2,
	TEST_IMM_UPDOWN4A,
	TEST_IMM_UPDOWN4B
};

static bool is_imm(int test_id)
{
	switch (test_id) {
	case TEST_IMM_UPDOWN2:
	case TEST_IMM_UPDOWN4A:
	case TEST_IMM_UPDOWN4B:
		return true;

	default:
		return false;
	}
}

int main(int argc, char **argv)
{
	int nt, nc, nclr, pl, rt_min_rr, rt_min_fifo, plbad;
	struct sched_attr* sa;

	if (argc == 1)
		test_selector = 0;
	else if (argc == 2 && streq(argv[1], "help"))
		usage();
	else if (argc == 2 && streq(argv[1], "setnow"))
		test_selector = TEST_SETNOW;
	else if (argc == 2 && streq(argv[1], "invalid_ku"))
		test_selector = TEST_INVALID_KU;
	else if (argc == 2 && streq(argv[1], "voluntary"))
		test_selector = TEST_VOLUNTARY;
	else if (argc == 2 && streq(argv[1], "random-slow"))
		test_selector = TEST_RANDOM_SLOW;
	else if (argc == 2 && streq(argv[1], "random-fast"))
		test_selector = TEST_RANDOM_FAST;
	else if (argc == 2 && streq(argv[1], "updown2"))
		test_selector = TEST_UPDOWN2;
	else if (argc == 2 && streq(argv[1], "updown4a"))
		test_selector = TEST_UPDOWN4A;
	else if (argc == 2 && streq(argv[1], "updown4b"))
		test_selector = TEST_UPDOWN4B;
	else if (argc == 2 && streq(argv[1], "imm-updown2"))
		test_selector = TEST_IMM_UPDOWN2;
	else if (argc == 2 && streq(argv[1], "imm-updown4a"))
		test_selector = TEST_IMM_UPDOWN4A;
	else if (argc == 2 && streq(argv[1], "imm-updown4b"))
		test_selector = TEST_IMM_UPDOWN4B;
	else
		usage();

	random_fd = open("/dev/urandom", O_RDONLY);
	if (random_fd == -1)
		fatal("Unable to open /dev/urandom");

	rt_min_rr = sched_get_priority_min(SCHED_RR);
	if (rt_min_rr < 0)
		fatal("sched_get_priority_min");
	rt_min_fifo = sched_get_priority_min(SCHED_FIFO);
	if (rt_min_fifo < 0)
		fatal("sched_get_priority_min");
	if (rt_min_rr != rt_min_fifo)
		fatal_msg("priority_min(RR) != priority_min(FIFO)");

	/*
	 * Build an array of priorities used during the testing.
	 * Priorities are selected from this array at random at
	 * every test cycle.
	 *
	 *	10 x IDLE
	 *	10 x FIFO
	 *	10 x RR
	 *	10 x BATCH
	 *	10 x NORMAL
	 */
	plsched = xmalloc(sizeof(struct sched_attr) * 50);
	minpl = pl = 0;

	for (nt = 0;  nt < 10;  nt++, pl++) {
		sa = plsched + pl;
		memset(sa, 0, sizeof(*sa));
		sa->size = sizeof(*sa);
		sa->sched_policy = SCHED_IDLE;
		/* just in case */
		sa->sched_nice = 20;
	}

	for (nt = 0;  nt < 10;  nt++, pl++) {
		sa = plsched + pl;
		memset(sa, 0, sizeof(*sa));
		sa->size = sizeof(*sa);
		sa->sched_policy = SCHED_BATCH;
		/* 19 ... 10 */
		sa->sched_nice = 19 - nt;
	}

	for (nt = 0;  nt < 10;  nt++, pl++) {
		sa = plsched + pl;
		memset(sa, 0, sizeof(*sa));
		sa->size = sizeof(*sa);
		sa->sched_policy = SCHED_NORMAL;
		/* 5 ... -4 */
		sa->sched_nice = 5 - nt;
		if (nt == 5)  updown_down = pl;
	}

	for (nt = 0;  nt < 10;  nt++, pl++) {
		sa = plsched + pl;
		memset(sa, 0, sizeof(*sa));
		sa->size = sizeof(*sa);
		sa->sched_policy = SCHED_RR;
		/* 1 ... 10 */
		sa->sched_priority = rt_min_rr + nt;
		if (nt == 0)  updown_up1 = pl;
		if (nt == 2)  updown_up2 = pl;
		if (nt == 4)  updown_up3 = pl;
	}

	for (nt = 0;  nt < 10;  nt++, pl++) {
		sa = plsched + pl;
		memset(sa, 0, sizeof(*sa));
		sa->size = sizeof(*sa);
		sa->sched_policy = SCHED_FIFO;
		/* 11 ... 20 */
		sa->sched_priority = rt_min_fifo + 10 + nt;
	}

	maxpl = pl - 1;

	if (! init_smp_info()) {
		fprintf(stderr, "Unable to collect CPU data\n");
		exit(1);
	}

	/* number of CPUs to use */
	if (ncpus >= 8)
		reserved_cpus = 2;
	else if (ncpus != 1)
		reserved_cpus = 1;
	else
		reserved_cpus = 0;
	nthreads = (ncpus - reserved_cpus) * 2;

	/* build affinity mask excising reserved_cpus */
	test_cpu_set = smp_all_cpu_set;
	nclr = 0;
	for (nc = 0;  nc < CPU_SETSIZE;  nc++) {
		if (CPU_ISSET(nc, &test_cpu_set)) {
			CPU_CLR(nc, &test_cpu_set);
			if (++nclr == reserved_cpus)
				break;
		}
	}

	/* verify pl level definitions are sane */
	if (!dprio_validate_pl(minpl, maxpl, plsched, &plbad)) {
		fprintf(stderr, "Logical priority level definitions are "
			"not sane at pl %d\n", plbad);
		exit(1);
	}

	/* allocate thread group descriptor */
	tg = dprio_alloc_threadgroup(minpl, maxpl, plsched, onerror);
	if (tg == NULL)
		fatal_msg("Unable to allocate thread group data");

	/* allocate perthread context structures set */
	pset = dprio_alloc_perthread_set(nthreads, NULL, 0,
					 DPRIO_ALLOC_TRY_MLOCK, &locked);
	if (pset == NULL)
		fatal_msg("Unable to allocate thread contexts set");

	if (test_selector == 0 || test_selector == TEST_SETNOW) {
		print_separator();
		printf("Testing dprio_setnow ...\n\n");
		test_setnow();
	}

	if (test_selector == 0 || test_selector == TEST_INVALID_KU) {
		print_separator();
		printf("Testing with invalid ku area pointer ...\n\n");
		test_invalid_ku();
	}

	if (test_selector == 0 || test_selector == TEST_VOLUNTARY) {
		print_separator();
		printf("Testing voluntary preemption ...\n\n");
		test_voluntary();
	}

	if (test_selector == 0 || test_selector == TEST_RANDOM_SLOW) {
		print_separator();
		printf("Testing random-slow priority change (%d seconds) ...\n",
		       test_random_slow_sec);
		test_random_slow();
		printf("\n");
	}

	if (test_selector == 0 || test_selector == TEST_RANDOM_FAST) {
		print_separator();
		printf("Testing random-fast priority change (%d seconds) ...\n",
		       test_random_fast_sec);
		test_random_fast();
		printf("\n");
	}

	if (test_selector == 0 || test_selector == TEST_UPDOWN2) {
		print_separator();
		printf("Testing updown-2 priority change (%d seconds) ...\n",
		       test_updown_sec);
		test_updown(TEST_UPDOWN2);
		printf("\n");
	}

	if (test_selector == 0 || test_selector == TEST_UPDOWN4A) {
		print_separator();
		printf("Testing updown-4a priority change (%d seconds) ...\n",
		       test_updown_sec);
		test_updown(TEST_UPDOWN4A);
		printf("\n");
	}

	if (test_selector == 0 || test_selector == TEST_UPDOWN4B) {
		print_separator();
		printf("Testing updown-4b priority change (%d seconds) ...\n",
		       test_updown_sec);
		test_updown(TEST_UPDOWN4B);
		printf("\n");
	}

	/*
	 * Do not run imm tests by default, they are not for DPRIO testing,
	 * but rather for comparison only. Run them only if explicitly
	 * requested.
	 */
	if (test_selector == TEST_IMM_UPDOWN2) {
		print_separator();
		printf("Testing immediate updown-2 priority change (%d seconds) ...\n",
		       test_updown_sec);
		test_updown(TEST_IMM_UPDOWN2);
		printf("\n");
	}

	if (test_selector == TEST_IMM_UPDOWN4A) {
		print_separator();
		printf("Testing immediate updown-4a priority change (%d seconds) ...\n",
		       test_updown_sec);
		test_updown(TEST_IMM_UPDOWN4A);
		printf("\n");
	}

	if (test_selector == TEST_IMM_UPDOWN4B) {
		print_separator();
		printf("Testing immediate updown-4b priority change (%d seconds) ...\n",
		       test_updown_sec);
		test_updown(TEST_IMM_UPDOWN4B);
		printf("\n");
	}

	/* deallocate perthread context structures set */
	dprio_free_perthread_set(pset);

	/* deallocate thread group descriptor */
	dprio_free_threadgroup(tg);

	return 0;
}

static void print_separator(void)
{
	printf("------------------------------------------------------------\n");
}

static void usage(void)
{
	fprintf(stderr, "usage: test [help | setnow | invalid_ku | voluntary |"
		        " random-slow | random-fast |\n");
	fprintf(stderr, "             updown2 | updown4a | updown4b |\n");
	fprintf(stderr, "             imm-updown2 | imm-updown4a | imm-updown4b ]\n");
	exit(1);
}

/*
 * Test dprio_setnow
 */
static void test_setnow(void)
{
	dprio_perthread_t dctx;
	struct sched_attr attr;
	struct sched_attr svattr;
	int pl;

	/* save pre-test priority */
	if (sched_getattr(0, &svattr, sizeof(svattr), 0))
		fatal("sched_getattr");

	/* initialize DPRIO thread context */
	dctx = dprio_get_perthread(pset, 0);
	if (dctx == NULL)
		fatal_msg("Unable to allocate thread context");

	if (dprio_init_thread(dctx, tg))
		fatal("Unable to initialize thread for DPRIO");

	/* set all the priorities in plsched array */
	for (pl = minpl;  pl <= maxpl;  pl++) {
		if (dprio_setnow(pl, DPRIO_FORCE))
			fatal("dprio_setnow");
		if (sched_getattr(0, &attr, sizeof(attr), 0))
			fatal("sched_getattr");
		if (! equal_sched(plsched + pl - minpl, &attr))
			fatal_msg("dprio_setnow malfunction");
	}

	/* uninitialize DPRIO thread context */
	dprio_uninit_thread();

	/* restore pre-test priority */
       if (sched_setattr(0, &svattr, 0))
	       fatal("sched_setattr");
}

/*
 * Test with purposefully invalid ku address.
 */
static void test_invalid_ku(void)
{
	u64 kuarea = 8;
	struct sched_attr *pp[1];

	pp[0] = &plsched[0];

	if (prctl(PR_SET_DEFERRED_SETPRIO, kuarea, &pp, 1, 0))
		perror("Expected error when prctl(PR_SET_DEFERRED_SETPRIO) with invalid ku address");
	else
		fatal_msg("prctl(PR_SET_DEFERRED_SETPRIO) with invalid ku address did not fail");

	if (prctl(PR_SET_DEFERRED_SETPRIO, &kuarea, &pp, 1, 0))
		fatal("prctl(PR_SET_DEFERRED_SETPRIO) with invalid ku address");
	sleep_msec(30);
	sleep_msec(30);
	sleep_msec(30);
	if (prctl(PR_SET_DEFERRED_SETPRIO, 0, 0, 0, 0))
		fatal("prctl(PR_SET_DEFERRED_SETPRIO) with invalid ku address");
}

static void test_voluntary(void)
{
	dprio_perthread_t dctx;
	struct sched_attr attr;
	struct sched_attr svattr;
	const int sleep_ms = 30;
	int pl;

	/* save pre-test priority */
	if (sched_getattr(0, &svattr, sizeof(svattr), 0))
		fatal("sched_getattr");

	/* initialize DPRIO thread context */
	dctx = dprio_get_perthread(pset, 0);
	if (dctx == NULL)
		fatal_msg("Unable to allocate thread context");

	if (dprio_init_thread(dctx, tg))
		fatal("Unable to initialize thread for DPRIO");

	/* set all the priorities in plsched array */
	for (pl = minpl;  pl <= maxpl;  pl++) {
		dprio_set(pl, 0);
		sleep_msec(sleep_ms);
		if (sched_getattr(0, &attr, sizeof(attr), 0))
			fatal("sched_getattr");
		if (! equal_sched(plsched + pl - minpl, &attr))
			fatal_msg("dprio_set malfunction");
	}

	/* then go through all the priorities in reverse order */
	for (pl = maxpl;  pl >= minpl;  pl--) {
		dprio_set(pl, 0);
		sleep_msec(sleep_ms);
		if (sched_getattr(0, &attr, sizeof(attr), 0))
			fatal("sched_getattr");
		if (! equal_sched(plsched + pl - minpl, &attr))
			fatal_msg("dprio_set malfunction");
	}

	/* uninitialize DPRIO thread context */
	dprio_uninit_thread();

	/* restore pre-test priority */
       if (sched_setattr(0, &svattr, 0))
	       fatal("sched_setattr");
}

static void test_random_slow(void)
{
	struct __random_slow_stat *rss = &random_slow_stat;
	unsigned long ul;

	memset(rss, 0, sizeof random_slow_stat);
	memset(&dprio_stat, 0, sizeof dprio_stat);

	create_threads(thread_main_random_slow);
	sleep(test_random_slow_sec);
	abort_flag = true;
	reap_threads();

	printf("Total requests up: %lu\n", rss->total_up);
	printf("Total requests down: %lu\n", rss->total_down);
	printf("Total requests eq: %lu\n", rss->total_eq);
	printf("\n");

	printf("Involuntary up: %lu (%g%%)\n",
	       rss->involuntary_up,
	       100.0 * (double) rss->involuntary_up / (double) rss->total_up);
	printf("Involuntary down: %lu (%g%%)\n",
	       rss->involuntary_down,
	       100.0 * (double) rss->involuntary_down / (double) rss->total_down);
	printf("Involuntary eq: %lu (%g%%)\n",
	       rss->involuntary_eq,
	       100.0 * (double) rss->involuntary_eq / (double) rss->total_eq);
	printf("\n");

	printf("Voluntary up: %lu (%g%%)\n",
	       rss->voluntary_up,
	       100.0 * (double) rss->voluntary_up / (double) rss->total_up);
	printf("Voluntary down: %lu (%g%%)\n",
	       rss->voluntary_down,
	       100.0 * (double) rss->voluntary_down / (double) rss->total_down);
	printf("Voluntary eq: %lu (%g%%)\n",
	       rss->voluntary_eq,
	       100.0 * (double) rss->voluntary_eq / (double) rss->total_eq);
	printf("\n");

	printf("Nearly-immediate up: %lu (%g%%)\n",
	       rss->immediate_up,
	       100.0 * (double) rss->immediate_up / (double) rss->total_up);
	printf("Nearly-immediate down: %lu (%g%%)\n",
	       rss->immediate_down,
	       100.0 * (double) rss->immediate_down / (double) rss->total_down);
	printf("Nearly-immediate eq: %lu (%g%%)\n",
	       rss->immediate_eq,
	       100.0 * (double) rss->immediate_eq / (double) rss->total_eq);
	printf("\n");

	ul = rss->total_up - rss->voluntary_up -
	     rss->involuntary_up - rss->immediate_up;
	printf("Unhandled up: %lu (%g%%)\n",
	       ul,
	       100.0 * (double) ul / (double) rss->total_up);
	ul = rss->total_down - rss->voluntary_down -
	     rss->involuntary_down - rss->immediate_down;
	printf("Unhandled down: %lu (%g%%)\n",
	       ul,
	       100.0 * (double) ul / (double) rss->total_down);
	ul = rss->total_eq - rss->voluntary_eq -
	     rss->involuntary_eq - rss->immediate_eq;
	printf("Unhandled eq: %ld (%g%%)\n",
	       (long) ul,
	       100.0 * (double) (long) ul / (double) rss->total_eq);
	printf("\n");

	printf("dprio_setnow: %lu\n", dprio_stat.dprio_setnow);
	printf("dprio_set: %lu\n", dprio_stat.dprio_set);
	printf("actual setprio: %lu (%g%% of dprio_set and setnow)\n",
	       dprio_stat.actual_setprio,
	       100.0 * (double) dprio_stat.actual_setprio /
	       (double) (dprio_stat.dprio_set + dprio_stat.dprio_setnow));
	printf("actual setprio out of dprio_setnow: %lu (%g%% of dprio_set)\n",
	       dprio_stat.actual_setprio,
	       100.0 * (double) (dprio_stat.actual_setprio - dprio_stat.dprio_setnow) /
	       (double) dprio_stat.dprio_set);
}

static void*
thread_main_random_slow(void* arg)
{
	thread_context_t* ctx = (thread_context_t*) arg;
	dprio_perthread_t dctx;
	struct __random_slow_stat *rss = &random_slow_stat;
	struct timespec ts1, ts2;
	const int spin_ms = 30;
	const int sleep_ms = 30;
	struct sched_attr svattr;
	struct sched_attr attr;
	struct sched_attr prev_attr;
	int pl = -1, newpl;
	int seed;

	/* save pre-test priority */
	if (sched_getattr(0, &svattr, sizeof(svattr), 0))
		fatal("sched_getattr");

	/* limit the thread to CPUs specified in test_cpu_set */
	if (sched_setaffinity(0, sizeof(cpu_set_t), &test_cpu_set))
		fatal("sched_setaffinity");

	/* set up random number generation */
	if (read(random_fd, &seed, sizeof seed) != sizeof seed)
		fatal_msg("Unable to read /dev/random");
	seed = seed ^ gettid();
	seed = seed ^ ctx->nt;

	/* initialize thread context for DPRIO */
	dctx = dprio_get_perthread(pset, ctx->nt);
	if (dctx == NULL)
		fatal_msg("Unable to allocate thread context");

	if (dprio_init_thread(dctx, tg))
		fatal("Unable to initialize thread for DPRIO");

	/* once all threads are initialized, begin testing */
	barrier(&barrier_ntp1);

	for (;;) {
		if (abort_flag)
			break;

		/* select next desired priority at random */
		newpl = minpl + (rand_r(&seed) % (maxpl - minpl + 1));

		if (newpl == pl)
			continue;

		switch (sched_attr_cmp(plsched + newpl,
				       pl >= 0 ? plsched + pl : &svattr))
		{
		case 1:
			__sync_fetch_and_add(&rss->total_up, 1);
			break;
		case -1:
			__sync_fetch_and_add(&rss->total_down, 1);
			break;
		case 0:
			__sync_fetch_and_add(&rss->total_eq, 1);
			break;
		}

		pl = newpl;

		if (sched_getattr(0, &prev_attr, sizeof(prev_attr), 0))
			fatal("sched_getattr");

		dprio_set(pl, 0);

		/* changed priority? */
		if (sched_getattr(0, &attr, sizeof(attr), 0))
			fatal("sched_getattr");

		if (equal_sched(plsched + pl - minpl, &attr)) {
			switch (sched_attr_cmp(&attr, &prev_attr)) {
			case 1:
				__sync_fetch_and_add(&rss->immediate_up, 1);
				break;
			case -1:
				__sync_fetch_and_add(&rss->immediate_down, 1);
				break;
			case 0:
				__sync_fetch_and_add(&rss->immediate_eq, 1);
				break;
			}

			continue;
		}

		/* record starting time for the pass */
		if (clock_gettime(clk_id, &ts1))
			fatal("clock_gettime");

		/*
		 * Loop until notice priority change
		 * or spin_ms timeout expires
		 */
		for (;;) {
			/* changed priority? */
			if (sched_getattr(0, &attr, sizeof(attr), 0))
				fatal("sched_getattr");

			if (equal_sched(plsched + pl - minpl, &attr)) {
				switch (sched_attr_cmp(&attr, &prev_attr)) {
				case 1:
					__sync_fetch_and_add(&rss->involuntary_up, 1);
					break;
				case -1:
					__sync_fetch_and_add(&rss->involuntary_down, 1);
					break;
				case 0:
					__sync_fetch_and_add(&rss->involuntary_eq, 1);
					break;
				}

				break;
			}

			/*
			 * has been running over a scheduling time slice
			 * and still not preempted?
			 */
			if (clock_gettime(clk_id, &ts2))
				fatal("clock_gettime");

			long dt = NSEC_PER_SEC * (long) (ts2.tv_sec - ts1.tv_sec) +
				  (ts2.tv_nsec - ts1.tv_nsec);

			if (dt > spin_ms * NSEC_PER_MSEC) {
				/* goto into voluntary sleep */
				sleep_msec(sleep_ms);

				if (sched_getattr(0, &attr, sizeof(attr), 0))
					fatal("sched_getattr");

				if (equal_sched(plsched + pl - minpl, &attr)) {
					switch (sched_attr_cmp(&attr, &prev_attr)) {
					case 1:
						__sync_fetch_and_add(&rss->voluntary_up, 1);
						break;
					case -1:
						__sync_fetch_and_add(&rss->voluntary_down, 1);
						break;
					case 0:
						__sync_fetch_and_add(&rss->voluntary_eq, 1);
						break;
					}
				}

				break;
			}
		}
	}

	/* uninitialize DPRIO thread context */
	dprio_uninit_thread();

	pthread_exit(NULL);
	return NULL;
}

static void test_random_fast(void)
{
	memset(&random_fast_stat, 0, sizeof random_fast_stat);
	memset(&dprio_stat, 0, sizeof dprio_stat);

	create_threads(thread_main_random_fast);
	sleep(test_random_fast_sec);
	abort_flag = true;
	reap_threads();

	printf("random-fast cycles: %lu\n", random_fast_stat.total);
	printf("\n");

	printf("dprio_setnow: %lu\n", dprio_stat.dprio_setnow);
	printf("dprio_set: %lu\n", dprio_stat.dprio_set);
	printf("actual setprio: %lu (%g%% per up-down cycle)\n",
	       dprio_stat.actual_setprio,
	       100.0 * (double) dprio_stat.actual_setprio /
	       (double) random_fast_stat.total);
}

static void*
thread_main_random_fast(void* arg)
{
	thread_context_t* ctx = (thread_context_t*) arg;
	dprio_perthread_t dctx;
	int pl = -1, newpl;
	int seed;

	/* limit the thread to CPUs specified in test_cpu_set */
	if (sched_setaffinity(0, sizeof(cpu_set_t), &test_cpu_set))
		fatal("sched_setaffinity");

	/* set up random number generation */
	if (read(random_fd, &seed, sizeof seed) != sizeof seed)
		fatal_msg("Unable to read /dev/random");
	seed = seed ^ gettid();
	seed = seed ^ ctx->nt;

	/* initialize thread context for DPRIO */
	dctx = dprio_get_perthread(pset, ctx->nt);
	if (dctx == NULL)
		fatal_msg("Unable to allocate thread context");

	if (dprio_init_thread(dctx, tg))
		fatal("Unable to initialize thread for DPRIO");

	/* once all threads are initialized, begin testing */
	barrier(&barrier_ntp1);

	for (;;) {
		if (abort_flag)
			break;

		/* select next desired priority at random */
		newpl = minpl + (rand_r(&seed) % (maxpl - minpl + 1));
		pl = newpl;

		dprio_set(pl, 0);
		__sync_fetch_and_add(&random_fast_stat.total, 1);
	}

	/* uninitialize DPRIO thread context */
	dprio_uninit_thread();

	pthread_exit(NULL);
	return NULL;
}

static void test_updown(int test_id)
{
	unsigned long ul;

	s_test_id = test_id;

	memset(&updown_stat, 0, sizeof updown_stat);
	memset(&dprio_stat, 0, sizeof dprio_stat);

	create_threads(thread_main_updown);
	sleep(test_updown_sec);
	abort_flag = true;
	reap_threads();

	printf("updown cycles: %lu\n", updown_stat.total);
	printf("\n");

	if (updown_stat.rt || updown_stat.nonrt) {
		unsigned long total = updown_stat.rt + updown_stat.nonrt;
		printf("os-level rt: %lu (%g%%)\n",
		       updown_stat.rt,
		       100.0 * (double) updown_stat.rt /
		       (double) total);
		printf("os-level non-rt: %lu (%g%%)\n",
		       updown_stat.nonrt,
		       100.0 * (double) updown_stat.nonrt /
		       (double) total);
		printf("\n");
	}

	if (is_imm(test_id))
		return;

	printf("dprio_setnow: %lu\n", dprio_stat.dprio_setnow);
	printf("dprio_set: %lu\n", dprio_stat.dprio_set);
	printf("actual setprio: %lu (%g%% per up-down cycle)\n",
	       dprio_stat.actual_setprio,
	       100.0 * (double) dprio_stat.actual_setprio /
	       (double) updown_stat.total);
}

static void*
thread_main_updown(void* arg)
{
	thread_context_t* ctx = (thread_context_t*) arg;
	dprio_perthread_t dctx;

	/* limit the thread to CPUs specified in test_cpu_set */
	if (sched_setaffinity(0, sizeof(cpu_set_t), &test_cpu_set))
		fatal("sched_setaffinity");

	/* initialize thread context for DPRIO */
	if (!is_imm(s_test_id)) {
		dctx = dprio_get_perthread(pset, ctx->nt);
		if (dctx == NULL)
			fatal_msg("Unable to allocate thread context");

		if (dprio_init_thread(dctx, tg))
			fatal("Unable to initialize thread for DPRIO");
	}

	/* once all threads are initialized, begin testing */
	barrier(&barrier_ntp1);

	if (!is_imm(s_test_id))
		dprio_setnow(updown_down, DPRIO_FORCE);
	else
		prio_set(updown_down);

	for (;;) {
		if (abort_flag)
			break;

		switch (s_test_id) {
		case TEST_UPDOWN2:
			dprio_set(updown_up1, 0);	updown_snap_stat();
			dprio_set(updown_down, 0);	updown_snap_stat();
			break;

		case TEST_UPDOWN4A:
			dprio_set(updown_up1, 0);	updown_snap_stat();
			dprio_set(updown_up3, 0);	updown_snap_stat();
			dprio_set(updown_up2, 0);	updown_snap_stat();
			dprio_set(updown_down, 0);	updown_snap_stat();
			break;

		case TEST_UPDOWN4B:
			dprio_set(updown_up2, 0);	updown_snap_stat();
			dprio_set(updown_up3, 0);	updown_snap_stat();
			dprio_set(updown_up1, 0);	updown_snap_stat();
			dprio_set(updown_down, 0);	updown_snap_stat();
			break;

		case TEST_IMM_UPDOWN2:
			prio_set(updown_up1);		updown_snap_stat();
			prio_set(updown_down);		updown_snap_stat();
			break;

		case TEST_IMM_UPDOWN4A:
			prio_set(updown_up1);		updown_snap_stat();
			prio_set(updown_up3);		updown_snap_stat();
			prio_set(updown_up2);		updown_snap_stat();
			prio_set(updown_down);		updown_snap_stat();
			break;

		case TEST_IMM_UPDOWN4B:
			prio_set(updown_up2);		updown_snap_stat();
			prio_set(updown_up3);		updown_snap_stat();
			prio_set(updown_up1);		updown_snap_stat();
			prio_set(updown_down);		updown_snap_stat();
			break;
		}
		__sync_fetch_and_add(&updown_stat.total, 1);
	}

	/* uninitialize DPRIO thread context */
	if (!is_imm(s_test_id))
		dprio_uninit_thread();

	pthread_exit(NULL);
	return NULL;
}

static void updown_snap_stat(void)
{
	struct sched_attr attr;
	static const bool do_updown_snap_stat = true;

	if (do_updown_snap_stat) {
		if (sched_getattr(0, &attr, sizeof(attr), 0))
			fatal("sched_getattr");

		switch (attr.sched_policy) {
		case SCHED_IDLE:
		case SCHED_BATCH:
		case SCHED_NORMAL:
			__sync_fetch_and_add(&updown_stat.nonrt, 1);
			break;

		default:
			__sync_fetch_and_add(&updown_stat.rt, 1);
			break;
		}
	}
}

static int onerror(int error, int err_pl, unsigned long err_errctx,
		   int new_pl, unsigned long new_errctx,
		   int recoverable)
{
	if (recoverable) {
		fprintf(stderr, "DPRIO recoverable error: %s\n", strerror(error));
		return true;
	} else {
		fatal_errno("DPRIO irrecoverable error", error);
	}
}

static void create_threads(void* (*proc)(void *arg))
{
	int nt, error, nc, nc1, nr = 0;

	abort_flag = false;

	if (error = pthread_barrier_init(& barrier_ntp1, NULL, nthreads + 1))
		fatal_errno("pthread_barrier_init", error);

	printf("Using %d threads on %d CPUs (",
	       nthreads, ncpus - reserved_cpus);

	nc1 = -1;
	if (CPU_ISSET(0, &test_cpu_set))
		nc1 = 0;

	for (nc = 1;  nc < CPU_SETSIZE;  nc++) {
		if (CPU_ISSET(nc, &test_cpu_set)) {
			if (nc1 == -1)
				nc1 = nc;
		} else {
			if (nc1 != -1) {
				show_cpu_range(nr++, nc1, nc - 1);
				nc1 = -1;
			}
		}
	}

	if (nc1 != -1)
		show_cpu_range(nr++, nc1, CPU_SETSIZE - 1);


	printf("), k/u context is %s\n",
	       locked ? "locked in memory" : "not locked in memory");

	threads = xmalloc(sizeof(pthread_t) * nthreads);
	for (nt = 0;  nt < nthreads;  nt++) {
		thread_context_t *ctx = create_thread_context();
		ctx->nt = nt;
		if (error = pthread_create(&threads[nt], NULL, proc, ctx))
			fatal_errno("pthread_create", error);
	}

	barrier(&barrier_ntp1);
}

static void show_cpu_range(int nr, int nc1, int nc2)
{
	if (nr != 0)
		printf(", ");
	if (nc1 == nc2)
		printf("%d", nc1);
	else
		printf("%d-%d", nc1, nc2);
}

static void reap_threads(void)
{
	int nt, error;

	for (nt = 0;  nt < nthreads;  nt++) {
		if (error = pthread_join(threads[nt], NULL))
			fatal_errno("pthread_join", error);
	}

	if (error = pthread_barrier_destroy(& barrier_ntp1))
		fatal_errno("pthread_barrier_destroy", error);

	free(threads);
	threads = NULL;
}

static bool equal_sched(const struct sched_attr *a1,
			const struct sched_attr *a2)
{
	if (a1->sched_policy != a2->sched_policy)
		return false;

	switch (a1->sched_policy) {
	case SCHED_NORMAL:
	case SCHED_BATCH:
		return a1->sched_nice == a2->sched_nice;

	case SCHED_FIFO:
	case SCHED_RR:
		return a1->sched_priority == a2->sched_priority;

	case SCHED_DEADLINE:
		return 	a1->sched_runtime == a2->sched_runtime &&
			a1->sched_deadline == a2->sched_deadline &&
			a1->sched_period == a2->sched_period;

	case SCHED_IDLE:
		return true;

	default:
		return false;
	}
}

static void prio_set(int pl)
{
	if (sched_setattr(0, plsched + pl - minpl, 0))
		fatal("sched_setattr");
}

static int signof(int v)
{
	if (v == 0)
		return 0;
	else if (v > 0)
		return 1;
	else
		return -1;
}

static bool sched_attr_cmp(const struct sched_attr *a1,
			   const struct sched_attr *a2)
{
	/*
	 * Limited to NORMAL, BATCH, FIFO, RR and IDLE
	 */
	switch (a1->sched_policy) {
	case SCHED_NORMAL:
	case SCHED_BATCH:
		if (a2->sched_policy == SCHED_IDLE)
			return 1;
		if (a2->sched_policy == SCHED_FIFO || a2->sched_policy == SCHED_RR)
			return -1;
		return signof((int) a2->sched_nice - (int) a1->sched_nice);

	case SCHED_FIFO:
	case SCHED_RR:
		if (a2->sched_policy == SCHED_NORMAL ||
		    a2->sched_policy == SCHED_BATCH ||
		    a2->sched_policy == SCHED_IDLE)
			return 1;
		return signof((int) a1->sched_priority - (int) a2->sched_priority);

	case SCHED_IDLE:
		if (a2->sched_policy == SCHED_IDLE)
			return 1;
		return -1;

	default:
		/* should not happen */
		fatal_msg("sched_attr_cmp bug check");
		return 0;
	}
}

static void strip_trailing_blanks(char *s)
{
	if (*s) {
		char *p = s + strlen(s) - 1;
		while (p >= s && (*p == ' ' || *p == '\t')) *p-- = '\0';
	}
}

/*
 * Gather host system multiprocessor configuration.
 */
static bool init_smp_info(void)
{
	/*
	 * /proc/cpuinfo displays information only for online CPUs, this is just what we want
	 */
	FILE	*fd          = fopen("/proc/cpuinfo", "r");
	bool	done         = false;
	char	buffer[1024];
	char	*xp;
	char	*key;
	char	*value;
	int	cpu_id;

	CPU_ZERO(&smp_all_cpu_set);

	CHECK(fd);

	ncpus = 0;

	while (fgets(buffer, sizeof(buffer), fd)) {
		buffer[sizeof(buffer) - 1] = '\0';
		if (xp = strchr(buffer, '\n')) *xp = '\0';
		if (xp = strchr(buffer, '\r')) *xp = '\0';
		if (buffer[0] == '\0')
			continue;
		key = buffer;
		xp = strchr(buffer, ':');
		if (!xp)
			continue;
		*xp++ = 0;
		value = xp;
		while (*value == ' ' || *value == 't')  value++;
		strip_trailing_blanks(key);
		strip_trailing_blanks(value);

		if (streq(key, "processor")) {
			ncpus++;
			cpu_id = -1;
			CHECK(1 == sscanf(value, "%d", &cpu_id));
			CHECK(cpu_id >= 0);
			CPU_SET(cpu_id, &smp_all_cpu_set);
		}
	}

	CHECK(!ferror(fd));

	done = true;

cleanup:

	if (fd) fclose(fd);

	return done;
}

/***************************************************************************
*                         Utility routines     			  	   *
***************************************************************************/

static bool barrier(pthread_barrier_t* barrier)
{
	int error = pthread_barrier_wait(barrier);

	if (error == PTHREAD_BARRIER_SERIAL_THREAD)
		return true;

	if (error != 0)
		fatal_errno("pthread_barrier_wait", error);

	return false;
}

static void
fatal_errno(const char* msg, int errcode)
{
	fprintf(stderr, "\nerror: %s: %s\n", msg, strerror(errcode));
	exit(1);
}

static void
fatal(const char* msg)
{
	fatal_errno(msg, errno);
}

static void
fatal_msg(const char* msg)
{
	fprintf(stderr, "\nerror: %s\n", msg);
	exit(1);
}

static void
out_of_memory(void)
{
	fatal_msg("Out of memory");
}

static thread_context_t*
create_thread_context(void)
{
	thread_context_t* ctx = (thread_context_t*) malloc(sizeof(thread_context_t));
	if (ctx == NULL)
		out_of_memory();
	return ctx;
}

static void
destroy_thread_context(thread_context_t* ctx)
{
	if (ctx != NULL)
		free(ctx);
}

static void*
xmalloc(size_t size)
{
	void* p = malloc(size);
	if (p == NULL)
		out_of_memory();
	return p;
}

static void sleep_msec(int ms)
{
	struct timespec tss;
	int rc;

	/* goto into voluntary sleep */
	tss.tv_sec = 0;
	tss.tv_nsec = ms * NSEC_PER_MSEC;
	do {
		rc = clock_nanosleep(clk_id, 0, &tss, &tss);
	} while (errno == EINTR);

	if (rc)
		fatal_errno("clock_nanosleep", rc);
}

