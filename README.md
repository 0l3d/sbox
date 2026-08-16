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
Example are available in the project tree. (example.sbox, limits.sbox)

## License
This project is licensed under the **GPL-3.0 License**.

# Author
Created by **oled**
