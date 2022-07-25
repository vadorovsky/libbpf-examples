#include <bpf/libbpf.h>

#include <signal.h>
#include <unistd.h>
#include "tc.skel.h"

static volatile sig_atomic_t stop;

/* Signal handler */
void sig_int(int signo)
{
	stop = 1;
}

void help(char *prog)
{
	fprintf(stderr, "Usage: %s [-i ifindex]\n", prog);
}

int main(int argc, char **argv)
{
	signal(SIGINT, sig_int);

	int opt, ifindex;
	while ((opt = getopt(argc, argv, "hi:")) != -1) {
		switch (opt) {
		case 'h':
			help(argv[0]);
			exit(0);
		case 'i':
			ifindex = atoi(optarg);
			break;
		default:
			help(argv[0]);
			exit(1);
		}
	}

	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
			    .attach_point = BPF_TC_INGRESS);

	struct tc_bpf *skel;
	int err, fd;

	skel = tc_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open skeleton\n");
		return 1;
	}
	printf("opened skeleton\n");

	skel->bss->ifindex = ifindex;

	err = tc_bpf__load(skel);
	if (err != 0) {
		fprintf(stderr, "failed to load skeleton\n");
		return 1;
	}
	printf("loaded skeleton\n");

	fd = bpf_program__fd(skel->progs.tc_bytes);

	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1,
			    .prog_fd = fd);

	err = bpf_tc_attach(&hook, &opts);
	if (err != 0) {
		fprintf(stderr, "failed to attach\n");
		// goto out_hook;
		goto out_skel;
	}
	printf("attached tc\n");

	while (!stop) {
		fprintf(stderr, ".");
		sleep(1);
	}

	bpf_tc_detach(&hook, &opts);
	printf("detached tc\n");
// out_hook:
// 	bpf_tc_hook_destroy(&hook);
// 	printf("destroyed hook\n");
out_skel:
	tc_bpf__destroy(skel);
	printf("destroyed skeleton\n");

	return 0;
}