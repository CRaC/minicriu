/*
 * Copyright 2023 Azul Systems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dynamic_api.hpp"
#include "minicriu-client.h"

// minicriu-client.c
extern int minicriu_dump_internal(const char *path, signal_handler *wrapper, signal_handler **handler_ptr);
extern bool minicriu_is_restore();
extern void minicriu_finalize_checkpoint();
// minicriu.c
extern int minicriu_restore(const char *path, restore_handler *restore_handler);

static bool ensure_dir(const char *path) {
	struct stat st;
	if (stat(path, &st) != 0) {
		if (errno == ENOENT) {
			char buf[PATH_MAX];
			snprintf(buf, sizeof(buf), "%s", path);
			buf[sizeof(buf) - 1] = '\0';
			char *last = strrchr(buf, '/');
			if (last[1] == '\0') {
				--last;
			}
			--last;
			while (last >= buf && *last != '/') --last;
			if (last >= buf) {
				*last = '\0';
				if (!ensure_dir(buf)) {
					return false;
				}
			}
			if (mkdir(path, 0700)) {
				fprintf(stderr, "minicriu: Cannot create directory %s: %s\n", buf, strerror(errno));
				return false;
			}
		} else {
			perror("minicriu: Cannot stat checkpoint directory");
			return false;
		}
	} else {
		if (st.st_mode & S_IFDIR) {
			return true;
		} else {
			fprintf(stderr, "minicriu: Cannot use %s for checkpoint: already exists but is not a directory\n", path);
		}
	}
}

int checkpoint(const char* const* args, bool stop_current, signal_handler *wrapper, signal_handler **handler_ptr) {
	if (args == NULL) {
		fprintf(stderr, "No arguments\n");
		return -1;
	}
	int i = 0;
	while (args[i] != NULL) ++i;
	if (i == 0) {
		fprintf(stderr, "No checkpoint target!\n");
		return -1;
	}
	const char* path = args[i - 1];

	if (!ensure_dir(path)) {
		return -1;
	}

	fprintf(stderr, "minicriu: checkpoint to %s\n", path);
	int retval = minicriu_dump_internal(path, wrapper, handler_ptr);
	if (retval == 0) {
		fprintf(stderr, "minicriu: success!\n");
		if (!minicriu_is_restore() && stop_current) {
			exit(137);
		} else {
			minicriu_finalize_checkpoint();
			return 0;
		}
	} else {
		fprintf(stderr, "minicriu: dump failed! %d\n", retval);
		return retval;
	}
}

int restore(const char* const* args, restore_handler *on_restore) {
	if (args == NULL) {
		fprintf(stderr, "minicriu: No args for restore!\n");
		return -1;
	}
	int i = 0;
	while (args[i] != NULL) ++i;
	if (i == 0) {
		fprintf(stderr, "minicriu: No restore source core dump!\n");
		return -1;
	}
	const char *source = args[i - 1];
	char path[PATH_MAX];

	struct stat st;
	if (stat(source, &st) != 0) {
		perror("minicriu: failed to stat restore path");
		return -1;
	}
	if (st.st_mode & S_IFDIR) {
		snprintf(path, PATH_MAX, "%s/minicriu-core", source);
	} else {
		snprintf(path, PATH_MAX, "%s", source);
	}
	return minicriu_restore(path, on_restore);
}
