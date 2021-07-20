#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);
void* check_addr(const void*);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
    int *p = f->esp;

    check_addr(p);

  int system_call = *p;
    switch (system_call)
    {
        case SYS_HALT:
        shutdown_power_off();
        break;

        case SYS_EXIT:
        check_addr(p + 1);
        exit_proc(*(p + 1));
        break;

        case SYS_EXEC:
        break;

        case SYS_WAIT:
        break;

        case SYS_CREATE:
        break;

        case SYS_REMOVE:
        break;

        case SYS_OPEN:
        break;

        case SYS_FILESIZE:
        break;

        case SYS_READ:
        break;

        case SYS_WRITE:
        break;

        case SYS_SEEK:
        break;

        default:
        printf("Default %d\n", *p);
    }
}

void exit_proc(int status)
{
    thread_current()->exit_error = status;

    thread_exit();
}

void* check_addr(const void *vaddr)
{
    if (!is_user_vaddr(vaddr))
    {
        exit_proc(-1);
    }

    /* Verify that the user-addr is mapped to kernel-addr */ 
    void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
    if (!ptr)
    {
        exit_proc(-1);
    }

}
