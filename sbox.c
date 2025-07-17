#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct Share {
  int files;
  int fs;
  int newcgroup;
  int newipc;
  int newnet;
  int newns;
  int newpid;
  int newtime;
  int newuser;
  int newuts;
  int sysvsem;
};

struct Limits {};

struct Share share = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

struct Options {
  int delete_after;
  int network_acces;
  char *resource_file;
  char *symlinks;
  char *files;
  char *chroot_path;
  char *unshare_flags;
  char *exec;
};

struct Options opts;

// UNCHROOT PROCESSES
void copy_f_to_chroot(char *dirs[]) {
  pid_t pid = fork();
  if (pid == -1) {
    perror("fork failed.");
    return;
  }

  if (pid == 0) {
    execvp(dirs[0], dirs);
    perror("execvp is failed");
    _exit(1);
  } else {
    waitpid(pid, NULL, 0);
  }
}

void clean_chroot(char *dirname) {
  pid_t pid = fork();
  if (pid == -1) {
    perror("fork failed");
    return;
  }

  if (pid == 0) {
    execlp("rm", "rm", "-rf", dirname, NULL);
    perror("execlp is failed");
    _exit(1);
  } else {
    waitpid(pid, NULL, 0);
  }
}

void symlink_parser(char *file_path) {
  FILE *file = fopen(file_path, "r");
  char line[256];

  if (file == NULL) {
    perror("fopen failed in limits_parser");
    return;
  }
  while (fgets(line, sizeof(line), file)) {
    line[strcspn(line, "\n")] = '\0';
    if (line[0] == '\0')
      continue;
    char link_path[128];
    char target[128];
    if (sscanf(line, "%127[^-]->%127s", link_path, target) == 2) {
      if (symlink(link_path, target) == -1) {
        perror("symlink is failed");
        _exit(1);
      }
    }
  }
  fclose(file);
}

char *dirs[256];

void file_parser(char *file_path) {
  FILE *file = fopen(file_path, "r");
  char line[256];
  dirs[0] = "cp";
  dirs[1] = "--parents";
  dirs[2] = "-r";

  if (file == NULL) {
    perror("fopen failed in limits_parser");
    return;
  }
  int i = 3;
  while (fgets(line, sizeof(line), file)) {
    line[strcspn(line, "\n")] = '\0';
    if (line[0] == '\0')
      continue;
    dirs[i++] = strdup(line);
  }
  dirs[i] = strdup(opts.chroot_path);
  dirs[i + 1] = NULL;

  fclose(file);
}

void free_dirs() {
  for (int i = 3; dirs[i] != NULL && dirs[i] != opts.chroot_path; i++) {
    free(dirs[i]);
  }
}

void limit(const char *key, rlim_t soft, rlim_t hard) {
  struct rlimit lim;
  lim.rlim_cur = soft;
  lim.rlim_max = hard;

  int resource;

  if (strcmp(key, "cpu") == 0)
    resource = RLIMIT_CPU;
  else if (strcmp(key, "fsize") == 0)
    resource = RLIMIT_FSIZE;
  else if (strcmp(key, "data") == 0)
    resource = RLIMIT_DATA;
  else if (strcmp(key, "stack") == 0)
    resource = RLIMIT_STACK;
  else if (strcmp(key, "core") == 0)
    resource = RLIMIT_CORE;
  else if (strcmp(key, "rss") == 0)
    resource = RLIMIT_RSS;
  else if (strcmp(key, "nproc") == 0)
    resource = RLIMIT_NPROC;
  else if (strcmp(key, "nofile") == 0)
    resource = RLIMIT_NOFILE;
  else if (strcmp(key, "memlock") == 0)
    resource = RLIMIT_MEMLOCK;
  else if (strcmp(key, "as") == 0)
    resource = RLIMIT_AS;
  else if (strcmp(key, "locks") == 0)
    resource = RLIMIT_LOCKS;
  else if (strcmp(key, "sigpending") == 0)
    resource = RLIMIT_SIGPENDING;
  else if (strcmp(key, "msgqueue") == 0)
    resource = RLIMIT_MSGQUEUE;
  else if (strcmp(key, "nice") == 0)
    resource = RLIMIT_NICE;
  else if (strcmp(key, "rtprio") == 0)
    resource = RLIMIT_RTPRIO;
  else if (strcmp(key, "rttime") == 0)
    resource = RLIMIT_RTTIME;
  else {
    fprintf(stderr, "error unknown limit: %s\n", key);
    return;
  }

  if (setrlimit(resource, &lim) == -1) {
    perror("rlimit is failed");
    _exit(0);
  }
}

void limits_parser(char *file_path) {
  FILE *file = fopen(file_path, "r");
  char line[256];

  if (file == NULL) {
    perror("fopen failed in limits_parser");
    return;
  }
  while (fgets(line, sizeof(line), file)) {
    line[strcspn(line, "\n")] = '\0';
    if (line[0] == '\0') {
      continue;
    }

    char key[64];
    unsigned long long soft_ll, hard_ll;
    if (sscanf(line, "%63[^=]=%llu:%llu", key, &soft_ll, &hard_ll) == 3) {
      limit(key, (rlim_t)soft_ll, (rlim_t)hard_ll);
    } else {
      fprintf(stderr, "unknown format (use this key=soft:hard): %s\n", line);
      _exit(1);
    }
  }
  fclose(file);
}

char **arg_parser(char *arguments) {
  static char *args[300];
  char *token = strtok(arguments, ",");
  int i = 0;
  while (token != NULL) {
    args[i++] = token;
    token = strtok(NULL, ",");
  }
  args[i] = NULL;
  return args;
}

void set_chroot() {
  if (mkdir(opts.chroot_path, S_IRWXU | S_IRWXG | S_IRWXO) == -1) {
    perror("mkdir is failed");
    return;
  }
  file_parser(opts.files);
  copy_f_to_chroot(dirs);
  symlink_parser(opts.symlinks);
}

void chrooting() {
  int flags = 0;

  if (!share.files)
    flags |= CLONE_FILES;
  if (!share.fs)
    flags |= CLONE_FS;
  if (!share.newcgroup)
    flags |= CLONE_NEWCGROUP;
  if (!share.newipc)
    flags |= CLONE_NEWIPC;
  if (!opts.network_acces)
    flags |= CLONE_NEWNET;
  if (!share.newns)
    flags |= CLONE_NEWNS;
  if (!share.newpid)
    flags |= CLONE_NEWPID;
  if (!share.newtime)
    flags |= CLONE_NEWTIME;
  if (!share.newuser)
    flags |= CLONE_NEWUSER;
  if (!share.newuts)
    flags |= CLONE_NEWUTS;
  if (!share.sysvsem)
    flags |= CLONE_SYSVSEM;

  if (unshare(flags) == -1) {
    perror("unshare is failed");
    _exit(1);
  }
  // RLIMITS
  if (strlen(opts.resource_file) > 0) {
    char schroot_path[200];

    snprintf(schroot_path, sizeof(schroot_path), "%s/limits", opts.chroot_path);
    FILE *file = fopen(opts.resource_file, "r");
    FILE *out = fopen(schroot_path, "w");
    char line[256];

    if (out == NULL) {
      perror("Failed to open limits file for writing");
      fclose(file);
      _exit(1);
    }

    if (file != NULL) {
      while (fgets(line, sizeof(line), file)) {
        fputs(line, out);
      }
      fclose(out);
      fclose(file);
    } else {
      fprintf(stderr, "Unable to open file!\n");
    }
  }

  if (chroot(opts.chroot_path) == -1) {
    perror("chroot is failed");
    _exit(1);
  }
  chdir("/");

  if (opts.resource_file > 0) {
    limits_parser("/limits");
  }

  execlp(opts.exec, opts.exec, NULL);
  perror("exevcp is failed");
  _exit(1);
}

int main(int argc, char *argv[]) {
  opts.delete_after = 0;
  opts.network_acces = 0;
  opts.files = "";
  opts.symlinks = "";
  opts.resource_file = "";
  opts.unshare_flags = "";
  opts.chroot_path = "/tmp/sbox_chroot";
  opts.exec = "/usr/bin/bash";
  int opt;
  while ((opt = getopt(argc, argv, "hcnf:s:m:u:r:e:")) != -1) {
    switch (opt) {
    case 'h':
      // help message
      break;
    case 'c':
      opts.delete_after = 1;
      break;
    case 'n':
      opts.network_acces = 1;
      break;
    case 'f':
      opts.files = optarg;
      break;
    case 's':
      opts.symlinks = optarg;
      break;
    case 'm':
      opts.chroot_path = optarg;
      break;
    case 'u':
      opts.unshare_flags = optarg;
      break;
    case 'r':
      opts.resource_file = optarg;
      break;
    case 'e':
      opts.exec = optarg;
      break;
    }
  }

  char **arguments = arg_parser(opts.unshare_flags);
  if (arguments != NULL) {
    for (int i = 0; arguments[i] != NULL; i++) {
      if (strcmp(arguments[i], "files") == 0)
        share.files = 0;
      if (strcmp(arguments[i], "fs") == 0)
        share.fs = 0;
      if (strcmp(arguments[i], "cgroup") == 0)
        share.newcgroup = 0;
      if (strcmp(arguments[i], "ipc") == 0)
        share.newipc = 0;
      if (strcmp(arguments[i], "ns") == 0)
        share.newns = 0;
      if (strcmp(arguments[i], "pid") == 0)
        share.newpid = 0;
      if (strcmp(arguments[i], "time") == 0)
        share.newtime = 0;
      if (strcmp(arguments[i], "user") == 0)
        share.newuser = 0;
      if (strcmp(arguments[i], "uts") == 0)
        share.newuts = 0;
      if (strcmp(arguments[i], "sysvsem") == 0)
        share.sysvsem = 0;
    }
  }

  set_chroot();
  pid_t pid = fork();

  if (pid == -1) {
    perror("fork is failed");
    return -1;
  }

  if (pid == 0) {
    chrooting();
  } else {
    waitpid(pid, NULL, 0);
    if (opts.delete_after == 1) {
      clean_chroot(opts.chroot_path);
    }
  }

  free_dirs();
  return 0;
}
