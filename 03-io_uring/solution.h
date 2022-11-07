#pragma once

/**
   Implement this function to copy data from @in to @out with io_uring.
   File descriptors @in and @out are guaranteed to be regular files.

   IO patterns generated by copy() must be reasonably efficient:
   1. the size of reads and writes must be 256k, except maybe the last block,
   2. there must be 4 queued read requests as long as there is enough
      data in @in.

   Do not use Linux kernel interfaces directly, use liburing.

   If a copy was successful, return 0. If an error occurred during a read
   or a write, return -errno.
*/
int copy(int in, int out);