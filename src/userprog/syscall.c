#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#define MAX_ARGS 4
#define BOTTOM_USER_VADDR_SPACE ((void *) 0x08048000)
//
struct lock sys_lock;
//
struct file_elements {
    struct file *file;
    int fd;
    struct list_elem elem;
};
//
static void syscall_handler (struct intr_frame *);
int process_add_file (struct file *f);
struct file* process_get_file (int fd);
void process_close_file (int fd);
int is_mapped(const void *vaddr);
void get_arg (struct intr_frame *f, int *arg, int n);
void check_vaddr(const void *vaddr);
void check_buff(void* buffer, unsigned size);
//
void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&sys_lock);
}
//good
static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int i, arg[MAX_ARGS];
  for(i=0;i<MAX_ARGS;i++)
  {
    arg[i]=*((int *) f->esp+i);
  }

  int pesp=is_mapped((const void*) f->esp);
  switch (* (int *) pesp)
  {
    case SYS_HALT:
    {
      halt();
      break;
    }
    case SYS_EXIT:
    {
      get_arg(f, &arg[0], 1);
      exit(arg[0]);
      break;
    }
    case SYS_EXEC:
    {
      get_arg(f, &arg[0], 1);
      arg[0] = is_mapped((const void *) arg[0]);
      f->eax = exec((const char *) arg[0]);
      break;
    }
    case SYS_WAIT:
    {
      get_arg(f, &arg[0], 1);
      f->eax = wait(arg[0]);
      break;
    }
    case SYS_CREATE:
    {
      get_arg(f, &arg[0], 2);
      arg[0] = is_mapped((const void *) arg[0]);
      f->eax = create((const char *)arg[0], (unsigned) arg[1]);
      break;
    }
    case SYS_REMOVE:
    {
      get_arg(f, &arg[0], 1);
      arg[0] = is_mapped((const void *) arg[0]);
      f->eax = remove((const char *) arg[0]);
      break;
    }
    case SYS_OPEN:
    {
      get_arg(f, &arg[0], 1);
      arg[0] = is_mapped((const void *) arg[0]);
      f->eax = open((const char *) arg[0]);
      break;
    }
    case SYS_FILESIZE:
    {
      get_arg(f, &arg[0], 1);
      f->eax = filesize(arg[0]);
      break;
    }
    case SYS_READ:
    {
      get_arg(f, &arg[0], 3);
      check_buff((void *) arg[1], (unsigned) arg[2]);
      arg[1] = is_mapped((const void *) arg[1]);
      f->eax = read(arg[0], (void *) arg[1], (unsigned) arg[2]);
      break;
    }
    case SYS_WRITE:
    {
      get_arg(f, &arg[0], 3);
      check_buff((void *) arg[1], (unsigned) arg[2]);
      arg[1] = is_mapped((const void *) arg[1]);
      f->eax = write(arg[0], (const void *) arg[1], (unsigned) arg[2]);
      break;
    }
    case SYS_SEEK:
    {
      get_arg(f, &arg[0], 2);
      seek(arg[0], (unsigned) arg[1]);
      break;
    }
    case SYS_TELL:
    {
      get_arg(f, &arg[0], 1);
      f->eax = tell(arg[0]);
      break;
    }
    case SYS_CLOSE:
    {
      get_arg(f, &arg[0], 1);
      close(arg[0]);
      break;
    }
  }
}
//good
void halt (void)
{
  shutdown_power_off();
}
//good
void exit (int status)
{
  struct thread *cur = thread_current();
  if (active_thread(cur->parent))
  {
    cur->cp->status = status;
  }
  printf ("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}
//good
pid_t exec (const char *cmd_line)
{
  pid_t pid = process_execute(cmd_line);
  struct child_process* cp = get_child_process(pid);
  while (cp->load == 0)
  {
    barrier();
  }
  if (cp->load == 2)
  {
    return ERROR;
  }
  return pid;
}
//good
int wait (pid_t pid)
{
  return process_wait(pid);
}

//good
bool create (const char *file, unsigned initial_size)
{
  lock_acquire(&sys_lock);
  bool result = filesys_create(file, initial_size);
  lock_release(&sys_lock);
  return result;

}
//good
bool remove (const char *file)
{
  lock_acquire(&sys_lock);
  bool result = filesys_remove (file);
  lock_release(&sys_lock);
  return result;

}
//good
int open (const char *file)
{
  int fd;
  lock_acquire(&sys_lock);
  struct file *temp_f = filesys_open(file);
  if (!temp_f)
  {
    lock_release(&sys_lock);
    return ERROR;
  }
  fd = process_add_file(temp_f);
  lock_release(&sys_lock);
  return fd;
}

//good
int filesize (int fd)
{
  int size;
  lock_acquire(&sys_lock);
  struct file *file = process_get_file(fd);
  if (!file)
  {
    lock_release(&sys_lock);
    return ERROR;
  }
  size = file_length(file);
  lock_release(&sys_lock);
  return size;
}
//good
int read (int fd, void *buffer, unsigned size)
{
  lock_acquire(&sys_lock);
  int result;
  if(fd == STDIN_FILENO)
  {
    unsigned i;
    uint8_t *buff_ptr = (uint8_t *) buffer;
    for(i = 0; i < size; i++)
    {
      buff_ptr[i] = input_getc();
    }
    lock_release(&sys_lock);
    return size;
  }
  struct file *file = process_get_file(fd);
  if (!file)
  {
    lock_release(&sys_lock);
    return ERROR;
  }
  result = file_read(file, buffer, size);
  lock_release(&sys_lock);
  return result;
}
//good
int write (int fd, const void *buffer, unsigned size)
{
  int result;
  if (fd == STDOUT_FILENO)
  {

    putbuf(buffer, size);
    return size;
  }
  lock_acquire(&sys_lock);
  struct file *file = process_get_file(fd);
  if (!file)
  {
    lock_release(&sys_lock);
    return ERROR;
  }
  result = file_write(file, buffer, size);
  lock_release(&sys_lock);
  return result;
}
//good
void seek (int fd, unsigned position)
{
  lock_acquire(&sys_lock);
  struct file *file = process_get_file(fd);
  if (!file)
  {
    lock_release(&sys_lock);
    return;
  }
  file_seek(file, position);
  lock_release(&sys_lock);

}
//good
unsigned tell (int fd)
{
  lock_acquire(&sys_lock);
  struct file *file = process_get_file(fd);
  if (!file)
  {
    lock_release(&sys_lock);
    return ERROR;
  }
  off_t offset = file_tell(file);
  lock_release(&sys_lock);
  return offset;

}
//good
void close (int fd)
{
  lock_acquire(&sys_lock);
  process_close_file(fd);
  lock_release(&sys_lock);
}


//good
struct child_process* add_child_process (int pid)
{
  size_t cp_size = sizeof(struct child_process);
  struct child_process* cp = malloc(cp_size);
  cp->pid = pid;
  cp->load = 0;
  cp->wait = false;
  cp->exit = false;
  lock_init(&cp->wait_lock);
  list_push_back(&thread_current()->child_list, &cp->elem);
  return cp;
}
//good
struct child_process* get_child_process (int pid)
{
  struct thread *temp = thread_current();
  struct list_elem *e;

  for (e = list_begin (&temp->child_list); e != list_end (&temp->child_list); e = list_next (e))
  {
    struct child_process *cp = list_entry (e, struct child_process, elem);
    if (pid == cp->pid)
    {
      return cp;
    }
  }
  return NULL;
}
//good
void remove_child_process (struct child_process *cp)
{
  list_remove(&cp->elem);
  free(cp);//deallocates memoray
}
//good
void remove_child_processes (void)
{
  struct thread *temp = thread_current();
  struct list_elem *next, *e = list_begin(&temp->child_list);

  while (e != list_end (&temp->child_list))
  {
    next = list_next(e);
    struct child_process *cp = list_entry (e, struct child_process, elem);
    list_remove(&cp->elem);
    free(cp);//deallocates memoray
    e = next;
  }
}
//good
int process_add_file (struct file *f)
{
  size_t fe_size = sizeof(struct file_elements);
  struct file_elements *fe = malloc(fe_size);
  fe->file = f;
  fe->fd = thread_current()->fd;
  thread_current()->fd++;
  list_push_back(&thread_current()->file_list, &fe->elem);
  return fe->fd;
}
//good
struct file* process_get_file (int fd)
{
  struct thread *temp = thread_current();
  struct list_elem *e;

  for(e = list_begin (&temp->file_list); e != list_end (&temp->file_list); e = list_next (e))
  {
    struct file_elements *fe = list_entry (e, struct file_elements, elem);
    if (fd == fe->fd)
    {
      return fe->file;
    }
  }
  return NULL;
}
//good
void process_close_file (int fd)
{
  struct thread *temp = thread_current();
  struct list_elem *next, *e = list_begin(&temp->file_list);

  while (e != list_end (&temp->file_list))
  {
    next = list_next(e);
    struct file_elements *fe = list_entry (e, struct file_elements, elem);
    if (fd == fe->fd || fd == -2)
    {
      file_close(fe->file);
      list_remove(&fe->elem);
      free(fe);//deallocates memory pointed to by fe
      if (fd != -2)
      {
        return;
      }
    }
    e = next;
  }
}
//good
void get_arg(struct intr_frame *f, int *arg, int n)
{
  int i;
  int *ptr;
  for (i = 0; i < n; i++)
  {
    ptr = (int *) f->esp + i + 1;
    check_vaddr((const void *) ptr);
    arg[i] = *ptr;
  }
}
//good
void check_buff(void* buffer, unsigned size)
{
  unsigned i;
  char* local_buff = (char *) buffer;
  for (i = 0; i < size; i++)
  {
    check_vaddr((const void*) local_buff);
    local_buff++;
  }
}
//good
void check_vaddr (const void *vaddr)
{
  if (!is_user_vaddr(vaddr) || vaddr < BOTTOM_USER_VADDR_SPACE)
  {
    exit(ERROR);
  }
}
//good
int is_mapped(const void *vaddr)
{
  check_vaddr(vaddr);
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!ptr)
  {
    exit(ERROR);
  }
  return (int) ptr;
}