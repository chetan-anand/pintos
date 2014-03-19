#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
//static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);
  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);
  list_init(&sleep_list);
  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();
  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
  {
    //printf("%s thread will yield\n",thread_name());
    intr_yield_on_return ();
  }
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();
  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack' 
     member cannot be observed. */
  old_level = intr_disable ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;
  
  intr_set_level (old_level);

  /* Add to run queue. */
  t->parent=thread_current();
  lock_acquire(&thread_current()->child_list_lock);
  list_push_back(&(thread_current()->child_list),&(t->child_list_elem));
  lock_release(&thread_current()->child_list_lock);
  thread_unblock (t);

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
#ifdef USERPROG
  enum intr_level old_level;
  old_level = intr_disable ();
#endif
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);
  /*
	So that the child thread can start it's process execute.
  */
  if(!thread_current()->wait_called)
  {
	if(thread_current()!=idle_thread)
	{
		//printf("Thread going to sleep:%s with tid:%d\n",thread_name(),thread_current()->tid);
  		sema_up(&(thread_current()->parent_blocked));
	}
  }
  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
#ifdef USERPROG
  intr_set_level (old_level);
#endif
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;
  ASSERT (is_thread (t));
  //printf("IN UNBLOCK() with thread:%s\n",t->name);
  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  /*
  The following code is the priority scheduling code.
  This code inserts the thread t into the ready list but using priority as the parameter.
  */
  list_insert_ordered(&ready_list,&t->elem,priority_more,NULL);
  /*list_push_back (&ready_list, &t->elem);*/
  t->status = THREAD_READY;
  /*
  	Preemption Code if the newly arrived thread at the ready queue has more priority than the 
  	currently excuting one, then preempt the currently running process.
  	If you comment out the lines from 267 to 273 you get a non-preemptive priority scheduler. 
  */
  /*
  	If the running thread is idle then we don't need to put it in the ready list once again.
  */
  /*
  	Added Code Starts.
  */
  if(t->priority > running_thread()->priority && running_thread()!=idle_thread)
  {	
  	//printf("Thread :%s",running_thread()->name);
  	list_insert_ordered(&ready_list,&running_thread()->elem,priority_more,NULL);
  	running_thread()->status=THREAD_READY;
  	schedule();
  }
  /*
  If the current thread is the idle thread then immediately yield the processor.
  */
  if(running_thread==idle_thread)
  {	
  	/*
  		Current thread is set to ready.
  	*/
  	running_thread()->status=THREAD_READY;
	schedule();
  }
  /*
  	Added code ends.
  */
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it call schedule_tail(). */
     //printf("Thread dying with pid:%d should signal the parent with pid :%d\n",thread_current()->tid,thread_current()->parent->tid);
  intr_disable ();
  list_remove (&thread_current()->allelem);
  if(!(thread_current()->parent_died))
  {
	  struct thread *par=thread_current()->parent;
	  if(par!=NULL)
	  {
	  	struct list_elem *e;
	  	lock_acquire(&par->child_list_lock);
	  	for (e = list_begin (&(par->child_list)); e != list_end (&(par->child_list)); e = list_next (e))
	  	{
	  		struct thread *f = list_entry (e, struct thread, child_list_elem);
	  		/*
	  			If the child is found then we block the current thread.
	  			Else it return -1
	  			Cases covered:
	  			1.if it is not the child of the calling process.
	  		*/
	 		if(f==thread_current())
	 		{
	 			if(!f->present_in_dead_child_list)
	 			{
					struct dead_child *dead=malloc(sizeof(struct dead_child));
					dead->tid=thread_current()->tid;
					dead->exit_status=-1;
					list_push_back(&thread_current()->parent->dead_child_list,&dead->elem);
	 			}
	 			list_remove(e);
	 			break;
	 		}
	  	}
	  	lock_release(&par->child_list_lock);
	  	/*
	  		 Because the parent may choose to run concurrently with the child.
	  	*/
	  	if(par->status==THREAD_BLOCKED && par->waiting_child==thread_current())
	  	{
	  		//printf("Parent Was Waiting will be woken up.\n");
	  		thread_unblock(par);
	  	}
	}
   }
  /*struct list_elem *e = list_begin (&thread_current()->open_files_list);*/
  struct open_file *o;
  /*
		As given in pintos.pdf all the open files are closed and removed from the processes list.
		This is done in thread_exit() since the kernel can also kill the process abruptly,in
		which case we have to close the files.
	*/
	while (!list_empty (&thread_current()->open_files_list))
	{
		struct list_elem *e = list_pop_front (&thread_current()->open_files_list);
		o = list_entry (e,struct open_file,elem);
		file_close(o->file);
		free(o);

	}
  struct list_elem *e;
  for (e = list_begin (&(thread_current()->child_list)); e != list_end (&(thread_current()->child_list)); e = list_next (e))
  {
  	struct thread *f = list_entry (e, struct thread, child_list_elem);
  	/* Notify each child that their parent has died.*/
  	f->parent_died = true;
  }
  /* Free the dead_child struct in dead_child_list.*/
  struct dead_child *dead;
  while (!list_empty (&thread_current()->dead_child_list))
	{
		struct list_elem *e = list_pop_front (&thread_current()->dead_child_list);
		dead = list_entry (e,struct dead_child,elem);
		free(dead);

	}
  /* Free all the locks that the thread may have acquired.*/
  struct lock *l;
  while (!list_empty (&thread_current()->lock_list))
	{
		struct list_elem *e = list_pop_front (&thread_current()->lock_list);
		l = list_entry (e,struct lock,elem);
		lock_release(l);
	}
  struct supplementary_page_table_entry *s_p_t_e;
  while (!list_empty (&thread_current()->supplementary_page_table))
  {
	struct list_elem *e = list_pop_front (&thread_current()->supplementary_page_table);
	s_p_t_e = list_entry (e,struct supplementary_page_table_entry,elem);
	list_remove(e);
	if(s_p_t_e->type == 3)
	{
		swap_slot_free[s_p_t_e->swap_slot_no] = true;
	}
	free(s_p_t_e);
  }
  int i;
  for(i=0;i<1024;i++)
  {
  	if(frames[i].pid == thread_current()->tid)
  	{
  		frames[i].pte = NULL;
  		frames[i].free_bit = true;
  		//frames[i].kpage = NULL;
  		frames[i].pid = -1;
  	}
  }
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  //printf("%s thread yielding.\n",cur->name);
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread) 
    list_insert_ordered (&ready_list, &cur->elem,priority_more,NULL);
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
/*  printf("Setting....%s 's priority...\n",running_thread()->name);*/
/*  printf("Current Priority:%d to \n",running_thread()->priority);*/
/*  printf("New Priority:%d",new_priority);*/
/*  printf("Actual priority:%d",running_thread()->actual_priority);*/
  /*
  	Added code starts.
  	Algorithm:
  	1.If the new priority>=current priority NO chance that this thread can be preempted.
  	2.Else we have to check whether the head of the queue has more priority
  	 than current thread's priority if yes the current thread immediately yields.
  	 else continues.
  */
  if(running_thread()->actual_priority<=new_priority)
  {
  	running_thread ()->actual_priority = new_priority;
  	if(running_thread()->priority < running_thread()->actual_priority)
  		running_thread()->priority=new_priority;
  }
  else
  {
  	//printf("Else\n");
  	/*If the thread has not recieved any donations.*/
  	if(running_thread()->priority==running_thread()->actual_priority)
  		running_thread ()->priority = new_priority;
  	running_thread()->actual_priority=new_priority;
  	if(!list_empty(&ready_list) && list_entry(list_front(&ready_list),struct thread,elem)->priority > running_thread()->priority)
  	{
  		thread_yield();
  	}
  }
  //printf("Thread priority: %d\n",running_thread()->priority);
  /*
  	Added code ends.
  */
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) 
{
  /* Not yet implemented. */
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  /* Not yet implemented. */
  return 0;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  /* Not yet implemented. */
  return 0;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  /* Not yet implemented. */
  return 0;
}
int64_t thread_get_time_remaining_for_sleep(void)
{
	return thread_current()->time_remaining_for_sleep;
}
void thread_set_time_remaining_for_sleep(int64_t time_sleep)
{
	thread_current()->time_remaining_for_sleep=time_sleep;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  /*
  	Added Code starts.
  */
  t->priority = priority;
  t->actual_priority=priority;
  t->waiting_lock=NULL; //It is currently waiting on no lock.
  t->waiting_sema=NULL; // It is currently waiting on no semaphore.
  t->parent=NULL;       /* Works only for the main thread for otherwise we
  			   have to set it to current_thread in thread_create().	 */
  list_init(&t->child_list);
  t->waiting_child=NULL;
  lock_init(&t->child_exec_lock);
  t->waited_on=false;
  list_init(&t->dead_child_list);
  t->last_fd=2;		/* Since three file are default opened by pintos STDOUT,STDIN,STDERR.*/
  list_init(&t->open_files_list);
  sema_init(&t->parent_blocked,0); /* Initialised to zero because only when parent will up it will the child down it.*/
  t->wait_called=false;
  t->parent_died = false;
  t->present_in_dead_child_list = false;
  lock_init(&t->child_list_lock);
  list_init(&t->lock_list);
  list_init(&t->supplementary_page_table);
  /*
  	Added code ends.
  */
  t->magic = THREAD_MAGIC;
  list_push_back (&all_list, &t->allelem);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (list_empty (&ready_list))
  {
    return idle_thread;
  }
  else
  {
    return list_entry (list_pop_front (&ready_list), struct thread, elem);
  }
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
schedule_tail (struct thread *prev) 
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until schedule_tail() has
   completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;
#ifdef USERPROG
  enum intr_level old_level;
  old_level = intr_disable ();
#endif
  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  schedule_tail (prev);
#ifdef USERPROG
  intr_set_level (old_level);
#endif 
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

bool priority_more (const struct list_elem *a_, const struct list_elem *b_,void *aux UNUSED) 
{
  /*const struct value *a = list_entry (a_, struct value, elem);
  const struct value *b = list_entry (b_, struct value, elem);*/
  /*
  Compares and returns boolean on whether the a has more time_remaining_for_sleep
  or b has.
  */
  const struct thread *a=list_entry(a_,struct thread,elem);
  const struct thread *b=list_entry(b_,struct thread,elem);
  return a->priority > b->priority;
}
struct thread *get_child_from_tid(tid_t child_tid)
{
	struct list_elem *e;
	for (e = list_begin (&all_list); e != list_end (&all_list);e = list_next (e))
        {
          struct thread *f = list_entry (e, struct thread, allelem);
          if(f->tid==child_tid)
          {
          	return f;
          }
        }
        return NULL;
}
struct thread *thread_from_pid(int pid)
{
	struct list_elem *e;
	for (e = list_begin (&all_list); e != list_end (&all_list);e = list_next (e))
	{
		struct thread *f = list_entry(e, struct thread ,allelem);
		if(f->tid == pid)
			return f;
	}
	return NULL;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);
