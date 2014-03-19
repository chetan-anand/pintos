#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/synch.h"
/*
	Added Code Starts.
	FileSystem Lock for synchronizing access to file system.
*/
	struct lock filesys_lock;
/*
	Added Code Ends.
*/
void syscall_init (void);

#endif /* userprog/syscall.h */
