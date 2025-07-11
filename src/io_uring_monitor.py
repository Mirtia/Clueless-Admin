# Enable or disable for kernel
# What is the architecture difference for each kernel?
# https://man7.org/linux/man-pages/man7/io_uring.7.html

# Once you place one or more SQEs on to the SQ, you need to
# let the kernel know that you've done so.  You can do this
# by calling the io_uring_enter(2) system call.


# 0 syscalls is of course not possible,
# but the idea is to prove that the rootkit is not using any syscalls that are related to the attack, only the io_uring syscalls are used.

# Known rootkit will use this method with the only visible syscalls being the 
# some known modules that use the io_uring is qemu and nginx



