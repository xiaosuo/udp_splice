# udp\_splice

Splice two UDP sockets to relay the packets between them in the kernel space. It
can improve the performance as:

* ZERO copy: no data is copied to/from the user space.
* NO context switch: don't need to switch to the user space.
