#include <solution.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#define BUFFER_SIZE 16384
#define PATH_LENGTH 256
#define PROC_DIRECTORY "/proc"

	ssize_t get_executable_path(pid_t pid, char *exe_buf)
{
	char path_buf[PATH_LENGTH];
	snprintf(path_buf, sizeof(path_buf), "/proc/%d/exe", pid);
	ssize_t exe_len = readlink(path_buf, exe_buf, PATH_LENGTH);
	if (exe_len == -1)
	{
		report_error(path_buf, errno);
		return -1;
	}
	exe_buf[exe_len] = '\0';
	return exe_len;
}

ssize_t read_file_content(const char *path, char *buffer, size_t buffer_size)
{
	FILE *file = fopen(path, "r");
	if (!file)
	{
		if (errno == EACCES)
			return -1;
		report_error(path, errno);
		return -1;
	}
	ssize_t bytes_read = fread(buffer, 1, buffer_size - 1, file);
	if (bytes_read == -1)
	{
		report_error(path, errno);
	}
	buffer[bytes_read] = '\0';
	fclose(file);
	return bytes_read;
}

int parse_strings(char *input, char **output, size_t max_output_size)
{
	size_t count = 0;
	char *ptr = input;
	while (*ptr && count < max_output_size - 1)
	{
		output[count++] = ptr;
		ptr += strlen(ptr) + 1;
	}
	output[count] = NULL;
	return count;
}

int count_null_terminated_strings(const char *buffer, size_t size)
{
	size_t count = 0;
	for (size_t i = 0; i < size; i++)
	{
		if (buffer[i] == '\0')
		{
			count++;
		}
	}
	return count;
}

void ps(void)
{
	DIR *proc_dir = opendir(PROC_DIRECTORY);
	if (!proc_dir)
	{
		report_error(PROC_DIRECTORY, ENOENT);
		return;
	}

	struct dirent *cur_dir;
	while ((cur_dir = readdir(proc_dir)))
	{
		if (!isdigit(cur_dir->d_name[0]))
		{
			continue;
		}

		char exe_buf[PATH_LENGTH];
		char *argv_read = malloc(BUFFER_SIZE + 1);
		char *envp_read = malloc(BUFFER_SIZE + 1);
		char **argv_buf = NULL;
		char **envp_buf = NULL;

		if (!argv_read || !envp_read)
		{
			report_error(PROC_DIRECTORY, ENOMEM);
			exit(EXIT_FAILURE);
		}

		pid_t pid = atol(cur_dir->d_name);
		if (get_executable_path(pid, exe_buf) == -1)
		{
			free(argv_read);
			free(envp_read);
			continue;
		}
		snprintf(exe_buf, sizeof(exe_buf), "/proc/%d/cmdline", pid);
		ssize_t bytes_read = read_file_content(exe_buf, argv_read, BUFFER_SIZE);
		if (bytes_read == -1) {
			free(argv_read);
			free(envp_read);
			continue;
		}
					size_t string_amount = count_null_terminated_strings(argv_read, bytes_read);
			argv_buf = malloc((string_amount + 1) * sizeof(char *));
			parse_strings(argv_read, argv_buf, BUFFER_SIZE / sizeof(char *));
		snprintf(exe_buf, sizeof(exe_buf), "/proc/%d/environ", pid);
		bytes_read = read_file_content(exe_buf, envp_read, BUFFER_SIZE);
		if (bytes_read == -1)
		{
			free(argv_read);
			free(envp_read);
			continue;
		}
		 string_amount = count_null_terminated_strings(envp_read, bytes_read);
			envp_buf = malloc((string_amount + 1) * sizeof(char *));
			parse_strings(envp_read, envp_buf, BUFFER_SIZE / sizeof(char *));
		report_process(pid, exe_buf, argv_buf, envp_buf);
		free(argv_buf);
		free(envp_buf);
		free(argv_read);
		free(envp_read);
	}

	closedir(proc_dir);
}
