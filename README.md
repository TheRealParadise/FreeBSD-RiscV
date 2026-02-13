FreeBSD Source:
---------------
This is the top level of the FreeBSD source directory.

FreeBSD is an operating system used to power modern servers, desktops, and embedded platforms.
A large community has continually developed it for more than thirty years.
Its advanced networking, security, and storage features have made FreeBSD the platform of choice for many of the busiest web sites and most pervasive embedded networking and storage devices.

For copyright information, please see [the file COPYRIGHT](COPYRIGHT) in this directory.
Additional copyright information also exists for some sources in this tree - please see the specific source directories for more information.

The Makefile in this directory supports a number of targets for building components (or all) of the FreeBSD source tree.
See build(7), config(8), [FreeBSD handbook on building userland](https://docs.freebsd.org/en/books/handbook/cutting-edge/#makeworld), and [Handbook for kernels](https://docs.freebsd.org/en/books/handbook/kernelconfig/) for more information, including setting make(1) variables.

For information on the CPU architectures and platforms supported by FreeBSD, see the [FreeBSD
website's Platforms page](https://www.freebsd.org/platforms/).

For official FreeBSD bootable images, see the [release page](https://download.freebsd.org/ftp/releases/ISO-IMAGES/).

Source Roadmap:
---------------
| Directory | Description |
| --------- | ----------- |
| bin | System/user commands. |
| cddl | Various commands and libraries under the Common Development and Distribution License. |
| contrib | Packages contributed by 3rd parties. |
| crypto | Cryptography stuff (see [crypto/README](crypto/README)). |
| etc | Template files for /etc. |
| gnu | Commands and libraries under the GNU General Public License (GPL) or Lesser General Public License (LGPL). Please see [gnu/COPYING](gnu/COPYING) and [gnu/COPYING.LIB](gnu/COPYING.LIB) for more information. |
| include | System include files. |
| kerberos5 | Kerberos5 (Heimdal) package. |
| lib | System libraries. |
| libexec | System daemons. |
| release | Release building Makefile & associated tools. |
| rescue | Build system for statically linked /rescue utilities. |
| sbin | System commands. |
| secure | Cryptographic libraries and commands. |
| share | Shared resources. |
| stand | Boot loader sources. |
| sys | Kernel sources (see [sys/README.md](sys/README.md)). |
| targets | Support for experimental `DIRDEPS_BUILD` |
| tests | Regression tests which can be run by Kyua.  See [tests/README](tests/README) for additional information. |
| tools | Utilities for regression testing and miscellaneous tasks. |
| usr.bin | User commands. |
| usr.sbin | System administration commands. |

For information on synchronizing your source tree with one or more of the FreeBSD Project's development branches, please see [FreeBSD Handbook](https://docs.freebsd.org/en/books/handbook/cutting-edge/#current-stable).

-----

This is an experimental version, there maybe new bugs that I didn't run into yet but here it's stable on myu SiFive Unmatched running and compiling native and Linux stuff in the linuxulator for weeks.

This pathed version was made for SiFive Unmatched and includes;
* Fully working Linuxulator
* Patched and included the IWLWIFI driver in the build
* Patched linprocfs/psuedofs and some other stuff for more Linux stuff to work correctly
* - added /proc/PID/task/TID/stuff [experimental but mostly working]
* Adapted driver for temperature sensor and added driver for reading the onboard eeprom
* Fixed some small bugs in the kernel (signals when working with the FP have a chance to mess up the FP state in the base kernel)
* Added driver for the PWM so we can control the leds.
* Some experimental 'fixes' for sharing kqueue/epoll between threads.
* Probably doesn't completely compile on other platforms anymore because of some modified file where I forgot to check for arch, not tested this yet.
* Implemented some experimental stuff like the linux splice syscall (using sendfile) and some others
* May still include some debug messages (I'm currently doublechecking if I left any)

Take what you need to implement this in BASE;
 If you copy riscv/linux, restore the syscall.master file (no added syscalls) and apply some minor changes to compat/linux you get this running on the vanilla kernel in no-time.
 linprocfs changes require you to pull the pseudofs code to give it thread enumeration powers.
 iwlwifi drivers fix are a couple of defines and a dummy function and also easy to replicate
 'get gdb working' patches are what probably breaks compatibility (compat/linux/linux_ptrace.c and linux_misc.c) and need some #ifdef stuff to make it other arch friendly again probably.

Known limitations/bugs;
* dtrace context switches may panic (don't think it's something I did)
* Icinga2 does not yet run in the Linuxulator because of some bugs in futexes
* Ubuntu 2024 binaries have difficulty with NFS, works fine if I use tmpfs (didn't test anything else yet)
* There is a lock traversal message when you use Witness; this is becuase of a 'bad' hack to get glusterfds running don't worry about it the order should always be correct
* Thermal sensor is still work in progress, it should activate PWM 1.2 when there is an interrupt and set it back to 50% duty when it hits the ice age.
* hexdump on /dev/mem may crash the tilelink bus; this is also in base and I did hava a patch but removed it because it was a bit too aggressive sometimes and may need revising
* Linuxulator currenty always stores FP registers and should check if they even have been used and not store when to used
* Some hardcoded values may not be compatible with other CPU's (cacheline size, identity bits, etc); they need to be made dynamic.

Linuxulator;
* Tested with Ubuntu 2024 - Downloaded the image, mounted it, copied the files to /compat/linux and did `chroot /compat/linux /bin/bash`
* Runs glusterfsd to the extend you can mount it and put files in it and tools see the node/cluster but at some point after a couple of hours it crashes
* Almost runs Icinga2 but there is a Futex issue
* Fully compiled the latest GDB in the Linuxulator
* GDB can actually live debug linux processes in the Linuxulator (this doesn't even work on Tier 1 platforms yet)
* Tested a bunch of other stuff like python, go and nodejs and they seem to work fine
* You can even use lsmod and rmmod and some other linux tools now just work like you are running a real Linux.
* Fixed an issue with fuse so you can mount and dismount the glusterfs volume from within the Linuxulator

