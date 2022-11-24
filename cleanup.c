/*
 * Copyright 2017-2022 Azul Systems, Inc.
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

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "cleanup.h"

maps *getmap() {
    maps *map = NULL;
    char line[512];
    size_t size = 0;
    FILE *proc_maps;
    proc_maps = fopen("/proc/self/maps", "r");

    if (!proc_maps)
        return NULL;

    while (fgets(line, sizeof(line), proc_maps)) {
        char perms[8];
        unsigned int devmajor, devminor;
        unsigned long offset, inode;
        void *addr_start, *addr_end;
        int name_start = 0;
        int name_end = 0;

        if (sscanf(line, "%p-%p %7s %lx %u:%u %lu %n%*[^\n]%n",
                   &addr_start, &addr_end, perms, &offset,
                   &devmajor, &devminor, &inode,
                   &name_start, &name_end) < 7) {
            fclose(proc_maps);
            freemap(map);
            return NULL;
        }
        maps *curr = (maps*)malloc(sizeof(maps));

        if (name_end > name_start) {
            memcpy(curr->name, line + name_start, name_end - name_start);
        }
        curr->name[name_end - name_start] = '\0';

        curr->start = addr_start;
        curr->end = addr_end;
        memcpy(curr->perms, perms, sizeof(curr->perms));
        curr->devmajor = devmajor;
        curr->devminor = devminor;
        curr->inode = inode;
        curr->offset = offset;

        curr->next = map;
        map = curr;
    }
    fclose(proc_maps);

    return map;
}

void cleanup(maps *oldmap, maps *newmap) {
    while(newmap) {
        int diff = 1;
		maps *curr = oldmap;
        while(curr) {
            if (newmap->start == curr->start) {
                diff = 0;
                break;
            }
            curr = curr->next;
        }

        if (diff) {
            if (munmap(newmap->start, newmap->end - newmap->start)) {
                perror("munmap");
            }
        }
        newmap = newmap->next;
    }
}

void freemap(maps *map) {
    while(map) {
        maps *curr = map;
        map = map->next;
		curr->next = NULL;
        free(curr);
    }
}
