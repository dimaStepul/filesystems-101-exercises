#include <solution.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <ctype.h>

#define BUFFER_SIZE 1024

int is_pid(const char *name)
{
	while (*name)
	{
		if (!isdigit(*name))
		{
			return 0;
		}
		name++;
	}
	return 1;
}


void lsof(void)
{
	char path_buf[BUFFER_SIZE];
	char file_path[BUFFER_SIZE];
	char link_target[BUFFER_SIZE];

	DIR *proc_ptr = opendir("/proc");
	if (!proc_ptr)
	{
		report_error("/proc", ENOMEM);
		return;	
	}

	struct dirent *pid_dirent;
	while ((pid_dirent = readdir(proc_ptr)))
	{
		if (!is_pid(pid_dirent->d_name))
		{
			continue;
		}

		pid_t pid = atol(pid_dirent->d_name);
		snprintf(path_buf, sizeof(path_buf), "/proc/%d/fd", pid);

		DIR *fd_ptr = opendir(path_buf);
		if (!fd_ptr)
		{
			report_error(path_buf, errno);
			continue;
		}

		struct dirent *fd_entry;
		while ((fd_entry = readdir(fd_ptr)))
		{
			if (strcmp(fd_entry->d_name, ".") == 0 || strcmp(fd_entry->d_name, "..") == 0)
			{
				continue;
			}
			snprintf(file_path, sizeof(file_path), "/proc/%d/fd/%s", pid, fd_entry->d_name);

			ssize_t link_len = readlink(file_path, link_target, sizeof(link_target) - 1);
			if (link_len < 0)
			{
				report_error(file_path, errno);
				continue;
			}
			link_target[link_len] = '\0';

			report_file(link_target);
		}

		closedir(fd_ptr);
	}

	closedir(proc_ptr);
}
