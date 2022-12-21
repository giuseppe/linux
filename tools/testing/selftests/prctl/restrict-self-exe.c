// SPDX-License-Identifier: GPL-2.0
/*
 * Tests for prctl(PR_GET_HIDE_SELF_EXE, ...) / prctl(PR_SET_HIDE_SELF_EXE, ...)
 *
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/prctl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PR_SET_HIDE_SELF_EXE
# define PR_SET_HIDE_SELF_EXE		67
# define PR_GET_HIDE_SELF_EXE		68
#endif

int main(void)
{
	char path[PATH_MAX];
	struct dirent *ent;
	int status;
	pid_t pid;
	DIR *dir;
	int ret;

	ret = open("/proc/self/exe", O_RDONLY);
	if (ret < 0) {
		perror("open /proc/self/exe");
		exit(EXIT_FAILURE);
	}
	close(ret);

	ret = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
	if (ret != 0) {
		perror("prctl(PR_SET_DUMPABLE, SUID_DUMP_DISABLE)");
		exit(EXIT_FAILURE);
	}

	ret = prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
	if (ret != 0) {
		perror("prctl(PR_SET_DUMPABLE, SUID_DUMP_USER)");
		exit(EXIT_FAILURE);
	}

	ret = prctl(PR_GET_HIDE_SELF_EXE, 0, 0, 0, 0);
	if (ret != 0) {
		perror("prctl(PR_GET_HIDE_SELF_EXE)");
		exit(EXIT_FAILURE);
	}

	ret = prctl(PR_SET_HIDE_SELF_EXE, 1, 0, 0, 0);
	if (ret != 0) {
		perror("prctl(PR_SET_HIDE_SELF_EXE)");
		exit(EXIT_FAILURE);
	}

	ret = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
	if (ret != 1) {
		perror("prctl(PR_GET_DUMPABLE)");
		exit(EXIT_FAILURE);
	}

	ret = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
	if (ret != 0) {
		perror("prctl(PR_SET_DUMPABLE, SUID_DUMP_DISABLE)");
		exit(EXIT_FAILURE);
	}

	/* It is not permitted anymore.  */
	ret = prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
	if (ret == 0) {
		perror("prctl(PR_SET_DUMPABLE, SUID_DUMP_USER)");
		exit(EXIT_FAILURE);
	}
	/* It can only be disabled.  */
	ret = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
	if (ret != 0) {
		perror("prctl(PR_SET_DUMPABLE, SUID_DUMP_DISABLE)");
		exit(EXIT_FAILURE);
	}

	/* check it doesn't fail a second time.  */
	ret = prctl(PR_SET_HIDE_SELF_EXE, 1, 0, 0, 0);
	if (ret != 0) {
		perror("prctl(PR_SET_HIDE_SELF_EXE)");
		exit(EXIT_FAILURE);
	}

	ret = prctl(PR_GET_HIDE_SELF_EXE, 0, 0, 0, 0);
	if (ret != 1) {
		perror("prctl(PR_GET_HIDE_SELF_EXE)");
		exit(EXIT_FAILURE);
	}

	ret = open("/proc/self/exe", O_RDONLY);
	if (ret >= 0 || errno != EPERM) {
		perror("open /proc/self/exe succeeded");
		exit(EXIT_FAILURE);
	}

	ret = execl("/proc/self/exe", "/proc/self/exe", NULL);
	if (ret >= 0 || errno != EPERM) {
		perror("execl /proc/self/exe succeeded or wrong error");
		exit(EXIT_FAILURE);
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(EXIT_FAILURE);
	}
	if (pid == 0) {
		/* It cannot be unset after a fork().  */
		ret = prctl(PR_SET_HIDE_SELF_EXE, 0, 0, 0, 0);
		if (ret == 0) {
			perror("prctl(PR_SET_HIDE_SELF_EXE)");
			exit(EXIT_FAILURE);
		}

		/* The getter still return the correct value.  */
		ret = prctl(PR_GET_HIDE_SELF_EXE, 0, 0, 0, 0);
		if (ret != 1) {
			perror("prctl(PR_GET_HIDE_SELF_EXE)");
			exit(EXIT_FAILURE);
		}

		/* It must be unreachable after fork().  */
		ret = open("/proc/self/exe", O_RDONLY);
		if (ret >= 0 || errno != EPERM) {
			perror("open /proc/self/exe succeeded or wrong error");
			exit(EXIT_FAILURE);
		}

		ret = execl("/proc/self/exe", "/proc/self/exe", NULL);
		if (ret >= 0 || errno != EPERM) {
			perror("execl /proc/self/exe succeeded wrong error");
			exit(EXIT_FAILURE);
		}

		dir = opendir("/proc/self/map_files");
		if (dir == NULL) {
			perror("opendir /proc/self/map_files");
			exit(EXIT_FAILURE);
		}

		while ((ent = readdir(dir)) != NULL) {
			if (ent->d_name[0] == '.')
				continue;

			sprintf(path, "/proc/self/map_files/%s", ent->d_name);
			ret = open(path, O_RDONLY);
			if (ret >= 0 || errno != EPERM) {
				perror("open /proc/self/map_files file succeeded or wrong error");
				exit(EXIT_FAILURE);
			}
		}
		closedir(dir);

		/* It can be set again.  */
		ret = prctl(PR_SET_HIDE_SELF_EXE, 1, 0, 0, 0);
		if (ret != 0) {
			perror("prctl(PR_SET_HIDE_SELF_EXE)");
			exit(EXIT_FAILURE);
		}

		/* PR_SET_DUMPABLE must not be permitted.  */
		ret = prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
		if (ret == 0) {
			perror("prctl(PR_SET_DUMPABLE, SUID_DUMP_USER)");
			exit(EXIT_FAILURE);
		}

		/* HIDE_SELF_EXE is cleared after execve.  */
		ret = system("cat /proc/self/exe > /dev/null");
		exit(ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
	}
	if (waitpid(pid, &status, 0) != pid) {
		perror("waitpid");
		exit(EXIT_FAILURE);
	}
	if (status != 0) {
		perror("child failed");
		exit(EXIT_FAILURE);
	}
	exit(EXIT_SUCCESS);
}
