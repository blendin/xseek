/*
 * Brendon Tiszka
 * xseek - simple tool for reading memory without ptrace using
 * open/lseek/read, /proc/pid/maps, /proc/pid/mem
 * MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

/* User defined variables */

#define MAXBUF    8192
#define DEBUG	  0

/* User defined values */
#define MAPPREFIX "map-"
#define MEMPREFIX "mem-"
#define BINSUFFIX ".bin"

#define FILTER      1
#define RWX_FILTER  "rw-"
#define INTERVALS   100
#define SLEEP_MICRO 10000

/* End user defined variables */

#define debug(x...) { \
fprintf(stderr, x); \
fflush(stderr); \
}\

#define fatal(x...) { \
fprintf(stderr, "[-] ERROR: " x); \
exit(1); \
}\


void usage(char *myname) {
  debug("Usage: %s PID\n", myname);
  exit(3);
}

void dump_memory(pid_t child, int count) {
  char *filepath, tmp[MAXBUF], procmem[MAXBUF];
  FILE *mapfile;
  int memfd;

  sprintf(tmp, "/proc/%d/maps", child);
  mapfile = fopen(tmp, "r");

  if (!mapfile) {
    fatal("/proc/%d/maps could not be open\n", child);
  }

  sprintf(tmp, "/proc/%d/mem", child);
  memfd = open(tmp, O_RDONLY);

  if (memfd == -1) {
    fatal("[!] failed to open %s\n", tmp);
  }

  while (fgets(tmp, MAXBUF, mapfile)) {
    char line[MAXBUF], perms[MAXBUF], r, w, x;
    long unsigned int st, en, len, retval;
    char *writeptr;
    int dumpfile;

    // Read the memory ranges for each segment along with read/write/execute
    if (sscanf(tmp, "%lx-%lx %c%c%cp", &st, &en, &r, &w, &x) != 5) {
      debug("[!] Parse error in /proc/%d/maps: %s", child, tmp);
      continue;
    }

    // Calculate size of segment
    len = en - st;

    if (DEBUG) debug("%lx %lx\n", st, en);

    if ((filepath=strchr(tmp,'/'))) {
      *(filepath-1)=0;
      sprintf(line, MAPPREFIX "%lx-%lx-%d" BINSUFFIX, st, en, count);
    } else {
      if (strchr(tmp, '\n')) *strchr(tmp,'\n')=0;
      sprintf(line, MEMPREFIX "%lx-%lx-%d" BINSUFFIX, st, en, count);
    }

    // Filter by memory segment permissions
    if (FILTER && (r != RWX_FILTER[0] || w != RWX_FILTER[1] || x != RWX_FILTER[2])) {
      if (DEBUG)  debug("[!] line %s %c%c%c\n", line, r, w, x);
      continue;
    }

    writeptr = (char *) calloc(len, 1);

    if (!writeptr) {
      debug("[!] failed to calloc(%ld, 1) bytes\n", len);
      continue;
    }

    lseek(memfd, st, SEEK_SET);

    retval = read(memfd, writeptr, len);

    if (retval == -1) {
      debug("[!] failed to read(%d, buf, %ld) bytes\n", memfd, len);
      continue;
    }

    dumpfile = open(line, O_WRONLY | O_TRUNC | O_CREAT | O_EXCL, 0600);

    if (dumpfile == -1) {
      debug("[!] failed to open(%s)\n", line);
      continue;
    }

    if (write(dumpfile, writeptr, len) != len)
      debug("[!] short write to %s.\n", line);

    close(dumpfile);
  }
}

void dump_wrapper(pid_t child) {
  char tmp[MAXBUF];
  int count = 0;

  while (count < INTERVALS) {
    dump_memory(child, count++);
    usleep(SLEEP_MICRO);
  }
}

int main(int argc, char *argv[]) {
  pid_t child;

  if (DEBUG) debug("version 0.1 brendon tiszka\n\n");
  if (argc < 2) usage(argv[0]);

  child = atoi(argv[1]);

  dump_wrapper(child);

  return 0;
}
