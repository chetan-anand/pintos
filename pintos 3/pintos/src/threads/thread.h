#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "synch.h"

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING,        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    /****************************
	Added Code starts.
****************************/
    int64_t time_remaining_for_sleep;	/*time remaining for thread to sleep if it had called timer_sleep()*/
    int priority;                       /* Priority(Donated). */
    int actual_priority;                /* Actual Priority */
    /*
    	A thread can either wait on a lock or a semaphore only one at a time.
    */
    struct lock *waiting_lock;          /* Lock on which this thread is waiting.*/
    struct semaphore *waiting_sema;     /* Semaphore on which this thread is waiting.*/
    /****************************
	Added Code ends.
****************************/
    struct list_elem allelem;           /* List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */
    
    struct thread *parent;		/* Parent of the current thread. */
    struct list child_list;		/* List of child processes. */
    struct lock child_list_lock;        /* Useful when parent of this thread and this thread both change the same data structure(child_list of this thread's parent.)*/
    struct list_elem child_list_elem;
    struct thread *waiting_child;       /* On which child does the this thread wait. */
    struct lock child_exec_lock;	/* keeps track of the fact that parent will not execute until the child has loaded it's program.*/
    int return_value;			/* Return value of the thread.(which it is returned by the child.) */
    bool waited_on;			/* Is used whether parent of the this thread ever waited on this thread or not.*/
    struct list dead_child_list;	/* List of all the processes of which this thread is a parent,but has never waited on them.*/
    int last_fd;			/* Holds the last file descriptor used by the this thread.*/
    struct list open_files_list;        /* Contains a list of open files.*/
    struct semaphore parent_blocked;    /* It is downed by the child only when the parent has upped it.(init=0).*/
    bool wait_called;			/* It keeps whether wait is called or not by this thread,uses in thread_block() (for synchronization).*/ 
    bool parent_died;			/* Keeps track whether parent of this thread has already died.(Useful for dead_child_list insertion).*/
    bool present_in_dead_child_list;	/* Keeps track whether this thread is present in the dead_child_list of the it's parent.
    					   Will hold TRUE if it exited through exit system call. otherwise on abnormal termination
    					   will hold FALSE.*/
    struct list lock_list;		/* Holds the list of locks that this thread holds.*/
    struct list supplementary_page_table;	/* Supplementary page table.*/

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
#endif

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
  };
  
/****************************
	Added Code starts.
****************************/
struct dead_child
{
	int tid;
	int exit_status;
	struct list_elem elem;
};
struct open_file
{
	int fd;
	struct file *file;
	struct list_elem elem;
};
/*
	Frame Table Structure.
*/
struct frame_table
{
	int pid;
	uint32_t *pte;
	bool free_bit;
	uint8_t *kpage;
};
struct frame_table frames[1024];
struct supplementary_page_table_entry
{
	uint32_t *va;     		/* Virtual address for this is the entry.*/
	int type;         		/* 0->in MM,1->in file,2->all zeroes,3->in swap.*/
	struct file *file;		/* file pointer only useful if type=1.*/
	int offset;			/* offset into the file.*/
	int swap_slot_no;		/* Swap slot number only useful if type=3.*/
	uint32_t page_read_bytes;	/* number of bytes to be read from the disk applicable only when the type=1.*/
	uint32_t page_zero_bytes;	/* number of bytes to be zeroed applicable only when the type=1.*/
	bool writable;			/* applicable for type=1.*/
	struct list_elem elem;
};
/*
	Swap Table
	1024 is calculated(assuming that blocks have size 1 page).
*/
bool swap_slot_free[1024];
/***************************
sleep_list:- contains all the threads that have been sleeping.
***************************/
struct list sleep_list;
/****************************
	Added Code ends.
****************************/

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

struct list ready_list;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);
void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);
/****************************
	Added Code starts.
****************************/
int64_t thread_get_time_remaining_for_sleep(void);
void thread_set_time_remaining_for_sleep(int64_t);
/****************************
	Added Code ends.
****************************/
int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);
bool priority_more (const struct list_elem *, const struct list_elem *,
                        void *);
/*
	Added Code Starts
*/
struct thread *get_child_from_tid(tid_t child_tid);
struct thread* thread_from_pid(int pid);
/*
	Added Code ends.
*/
#endif /* threads/thread.h */
