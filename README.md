# SBOX
**sbox** is minimal sandbox utility for linux.

## Features
- Binary size is only 23 kb. 
- Resource limits via `rlimit` (CPU, memory, files, etc.)
- Fine-grained syscall permissions with seccomp filters
- Namespace isolation (mount, pid, user, network, uts, cgroup, ipc, etc.)
- Custom chroot environment setup with file copying and bind mounts
- Configurable via simple text files
- Optional cleanup of sandbox environment after execution

## Usage
```bash
git clone https://git.sr.ht/~oled/sbox
cd sbox/
make

./sbox -h
```

## Config Syntax
Sections (case sensitive):
- files: — list of files/directories to copy into chroot
- symlinks: — list of symlink definitions linkpath->target
- unshare: — namespaces to unshare (files, fs, cgroup, ipc, ns, pid, time, user, uts, sysvsem, network)
- mounts: — mount points with format:
    source target fstype options data
    (e.g. /proc proc proc ro,nosuid,nodev,noexec non)
- perms: — list of allowed syscalls for seccomp filter

Example are available in the project tree. (example.sbox, limits.sbox)

## License
This project is licensed under the **GPL-3.0 License**.

# Author
Created by **oled**
