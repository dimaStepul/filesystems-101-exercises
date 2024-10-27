#include <solution.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#define BUFFER_SIZE 65536
#define PATH_MAX 4096
#define PROC_DIRECTORY "/proc"

int is_pid(const char *name) {
	while (*name) {
		if (!isdigit(*name)) {
			return 0;
		}
		name++;
	}
	return 1;
}

DIR *open_proc_dir() {
	DIR *proc_dir = opendir(PROC_DIRECTORY);
	if (!proc_dir) {
		report_error(PROC_DIRECTORY, ENOENT);
		return NULL;
	}
	return proc_dir;
}

// void *allocate_buffer(size_t size) {
// 	void *buffer = malloc(size + 1);
// 	if (!buffer) {
// 		free(buffer);
// 		report_error(PROC_DIRECTORY, ENOMEM);
// 		exit(EXIT_FAILURE);
// 	}
// 	memset(buffer, 0, size);
// 	return buffer;
// }


ssize_t get_executable_path(pid_t pid, char *exe_buf) {
	char path_buf[256];
	snprintf(path_buf, sizeof(path_buf), "/proc/%d/exe", pid);
	ssize_t exe_len = readlink(path_buf, exe_buf, PATH_MAX);
	if (exe_len == -1) {
		if (errno == EACCES)
			return -1;
		report_error(path_buf, errno);
	}
	exe_buf[exe_len] = '\0';
	return exe_len;
}


ssize_t read_file_content(const char *path, char *buffer, size_t buffer_size) {
	FILE *file = fopen(path, "r");
	if (!file) {
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


int parse_strings(char *input, char **output, size_t max_output_size){
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



void get_process_info(pid_t pid, char *exe_buf, char **argv_buf, char **envp_buf){
	if (get_executable_path(pid, exe_buf) == -1)
		return;

	char path_buf[256];
	char argv_read[BUFFER_SIZE];
	char envp_read[BUFFER_SIZE];

	snprintf(path_buf, sizeof(path_buf), "/proc/%d/cmdline", pid);
	if (read_file_content(path_buf, argv_read, BUFFER_SIZE) >= 0)
	{
		parse_strings(argv_read, argv_buf, BUFFER_SIZE / sizeof(char *));
	}

	snprintf(path_buf, sizeof(path_buf), "/proc/%d/environ", pid);
	if (read_file_content(path_buf, envp_read, BUFFER_SIZE) >= 0)
	{
		parse_strings(envp_read, envp_buf, BUFFER_SIZE / sizeof(char *));
	}
}

void ps(void)
{
	DIR *proc_dir = open_proc_dir();
	if (!proc_dir)
		return;
	char exe_buf[PATH_MAX];
	char **argv_buf = malloc((BUFFER_SIZE / sizeof(char *)) * sizeof(char *));
	char **envp_buf = malloc((BUFFER_SIZE / sizeof(char *)) * sizeof(char *));
	if (!argv_buf || !envp_buf)
	{
		free(argv_buf);
		free(envp_buf);
		closedir(proc_dir);
		exit(EXIT_FAILURE);
	}
	struct dirent *cur_dir;
	while ((cur_dir = readdir(proc_dir)))
	{
		if (!is_pid(cur_dir->d_name))
			continue;

		pid_t pid = atol(cur_dir->d_name);
		get_process_info(pid, exe_buf, argv_buf, envp_buf);
		report_process(pid, exe_buf, argv_buf, envp_buf);
		errno = 0;
	}

	free(argv_buf);
	free(envp_buf);
	closedir(proc_dir);
}
