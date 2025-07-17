#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
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
  int network;
};

struct Share share = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

struct Options {
  int delete_after;
  char *config;
  char *chroot_path;
  char *exec;
  char *limits;
};

struct Options opts;

// UNCHROOT PROCESSES
void copy_f_to_chroot(char *dir) {
  pid_t pid = fork();
  if (pid == -1) {
    perror("fork failed.");
    return;
  }

  if (pid == 0) {
    execlp("cp", "cp", "--parents", "-r", dir, opts.chroot_path, NULL);
    perror("execvp is failed");
    _exit(1);
  } else {
    waitpid(pid, NULL, 0);
  }
}

char *mounted_paths[100];
int mounted = 0;

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
    for (int i = 0; i < mounted; i++) {
      if (umount(mounted_paths[i]) == -1) {
        perror("umount is failed");
      }
      free(mounted_paths[i]);
    }
    waitpid(pid, NULL, 0);
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

typedef struct {
  int files;
  int symlinks;
  int share;
  int limits;
  int mounts;
} Config;

Config conf = {0, 0, 0, 0, 0};
void file_parser(char *file_path) {
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
    if (strcmp(line, "files:") == 0) {
      conf = (Config){1, 0, 0, 0};
      continue;
    }
    if (strcmp(line, "symlinks:") == 0) {
      conf = (Config){0, 1, 0, 0, 0};
      continue;
    }
    if (strcmp(line, "share:") == 0) {
      conf = (Config){0, 0, 1, 0, 0};
      continue;
    }

    if (strcmp(line, "mounts:") == 0) {
      conf = (Config){0, 0, 0, 0, 1};
      continue;
    }

    if (conf.files == 1) {
      copy_f_to_chroot(line);
    }

    if (conf.mounts == 1) {
      char source[128], target[128], fstype[64], options[256], data[256];
      if (sscanf(line, "%127s %127s %63s %255s %255[^\n]", source, target,
                 fstype, options, data) == 5) {
        char *options_tokens = strtok(options, ",");
        unsigned long mountopt = 0;
        while (options_tokens != NULL) {
          if (strcmp(options_tokens, "readonly") == 0) {
            mountopt |= MS_RDONLY;
          } else if (strcmp(options_tokens, "nosuid") == 0) {
            mountopt |= MS_NOSUID;
          } else if (strcmp(options_tokens, "nodev") == 0) {
            mountopt |= MS_NODEV;
          } else if (strcmp(options_tokens, "noexec") == 0) {
            mountopt |= MS_NOEXEC;
          } else if (strcmp(options_tokens, "synchronous") == 0) {
            mountopt |= MS_SYNCHRONOUS;
          } else if (strcmp(options_tokens, "remount") == 0) {
            mountopt |= MS_REMOUNT;
          } else if (strcmp(options_tokens, "mandlock") == 0) {
            mountopt |= MS_MANDLOCK;
          } else if (strcmp(options_tokens, "dirsync") == 0) {
            mountopt |= MS_DIRSYNC;
          } else if (strcmp(options_tokens, "noatime") == 0) {
            mountopt |= MS_NOATIME;
          } else if (strcmp(options_tokens, "nodiratime") == 0) {
            mountopt |= MS_NODIRATIME;
          } else if (strcmp(options_tokens, "bind") == 0) {
            mountopt |= MS_BIND;
          } else if (strcmp(options_tokens, "move") == 0) {
            mountopt |= MS_MOVE;
          } else if (strcmp(options_tokens, "rec") == 0 ||
                     strcmp(options_tokens, "recursive") == 0) {
            mountopt |= MS_REC;
          } else if (strcmp(options_tokens, "silent") == 0) {
            mountopt |= MS_SILENT;
          } else if (strcmp(options_tokens, "posixacl") == 0) {
            mountopt |= MS_POSIXACL;
          } else if (strcmp(options_tokens, "unbindable") == 0) {
            mountopt |= MS_UNBINDABLE;
          } else if (strcmp(options_tokens, "private") == 0) {
            mountopt |= MS_PRIVATE;
          } else if (strcmp(options_tokens, "slave") == 0) {
            mountopt |= MS_SLAVE;
          } else if (strcmp(options_tokens, "shared") == 0) {
            mountopt |= MS_SHARED;
          } else if (strcmp(options_tokens, "relatime") == 0) {
            mountopt |= MS_RELATIME;
          } else if (strcmp(options_tokens, "iversion") == 0) {
            mountopt |= MS_I_VERSION;
          } else if (strcmp(options_tokens, "strictatime") == 0) {
            mountopt |= MS_STRICTATIME;
          } else {
            fprintf(stderr, "Unknown mount flag: %s\n", options_tokens);
          }
          options_tokens = strtok(NULL, ",");
        }
        char path[256];
        if (target[0] == '/') {
          snprintf(path, sizeof(path), "%s%s", opts.chroot_path, target);
        } else {
          snprintf(path, sizeof(path), "%s/%s", opts.chroot_path, target);
        }
        mkdir(path, 0755);
        if (mount(source, path, fstype, mountopt,
                  strlen(data) > 0 ? data : NULL) == -1) {
          perror("mount failed");
        }
        mounted_paths[mounted++] = strdup(path);
      }
    }

    if (conf.symlinks == 1) {
      char linkpath[128];
      char target[128];
      char target_path[256];
      if (sscanf(line, "%127[^-]->%127s", linkpath, target) == 2) {
        snprintf(target_path, sizeof(target_path), "%s/%s", opts.chroot_path,
                 target);
        if (symlink(linkpath, target_path) == -1) {
          perror("symlink is failed");
          _exit(1);
        }
      }
    }

    if (conf.share == 1) {
      if (strcmp(line, "files") == 0)
        share.files = 0;
      if (strcmp(line, "fs") == 0)
        share.fs = 0;
      if (strcmp(line, "cgroup") == 0)
        share.newcgroup = 0;
      if (strcmp(line, "ipc") == 0)
        share.newipc = 0;
      if (strcmp(line, "ns") == 0)
        share.newns = 0;
      if (strcmp(line, "pid") == 0)
        share.newpid = 0;
      if (strcmp(line, "time") == 0)
        share.newtime = 0;
      if (strcmp(line, "user") == 0)
        share.newuser = 0;
      if (strcmp(line, "uts") == 0)
        share.newuts = 0;
      if (strcmp(line, "sysvsem") == 0)
        share.sysvsem = 0;
      if (strcmp(line, "network") == 0)
        share.network = 0;
    }
  }
  fclose(file);
}

void limits_parser(char *filepath) {
  FILE *file = fopen(filepath, "r");
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
}

void set_chroot() {
  if (mkdir(opts.chroot_path, S_IRWXU | S_IRWXG | S_IRWXO) == -1) {
    perror("mkdir is failed");
    return;
  }
  file_parser(opts.config);
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
  if (!share.network)
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

  char schroot_path[200];
  // RLIMITS
  if (strlen(opts.limits) > 0) {
    snprintf(schroot_path, sizeof(schroot_path), "%s/limits", opts.chroot_path);
    FILE *file = fopen(opts.limits, "r");
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

  if (strlen(opts.limits) > 0) {
    limits_parser("/limits");
  }

  if (strlen(opts.exec) > 0) {
    execlp(opts.exec, opts.exec, NULL);
    perror("exevlp is failed");
    _exit(1);
  }
}

int main(int argc, char *argv[]) {
  opts.delete_after = 0;
  opts.limits = "";
  opts.chroot_path = "/tmp/sbox_chroot";
  opts.exec = "/usr/bin/bash";
  int opt;
  while ((opt = getopt(argc, argv, "hdc:f:e:p:l:")) != -1) {
    switch (opt) {
    case 'h':
      // help message
      break;
    case 'c':
      opts.config = optarg;
      break;
    case 'e':
      opts.exec = optarg;
      break;
    case 'l':
      opts.limits = optarg;
      break;
    case 'p':
      opts.chroot_path = optarg;
      break;
    case 'd':
      opts.delete_after = 1;
      break;
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

  if (opts.limits && strlen(opts.limits) > 0) {
    free(opts.limits);
  }

  return 0;
}
