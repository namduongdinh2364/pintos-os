#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
// #include "list.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "userprog/exception.h"

static void pin_frame(void *uddr);
static void unpin_frame(void *uaddr);
static void add_mmap_page(void *upage, struct file *f, int offset);
static void mmap_handler(struct intr_frame *f);
static void munmap_handler(struct intr_frame *f);
void close_all_files(struct list* files);
void close_file(struct list* files, int fd);
int exec_proc (char *file_name);
static void syscall_handler (struct intr_frame *);
struct file_descriptor* scan_file(struct list* files, int fd);
struct file_descriptor {
	struct file* ptr;
	int fd;
	struct list_elem elem;
};

void check_vali_add(const void*);
void check_user_pointer (void *vaddr, int size);

void
syscall_init (void) 
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
    int *esp = f->esp;
    thread_current()->user_esp = f->esp;	//for page fault handling.
    check_vali_add(esp);

    int system_call = *esp;
    switch (system_call)
    {
        case SYS_HALT:
            shutdown_power_off();
            break;

        case SYS_EXIT:
            check_vali_add(esp + 1);
            exit_proc(*(esp + 1));
            break;

        case SYS_EXEC:
            check_vali_add(esp + 1);
            check_vali_add(*(esp + 1));
            check_user_pointer(*(esp + 1), 0);
            pin_frame(*(esp + 1));
            f->eax = exec_proc(*(esp + 1));
            unpin_frame(*(esp + 1));
            break;

        case SYS_WAIT:
            check_vali_add(esp + 1);
		    f->eax = process_wait(*(esp + 1));
            break;

        case SYS_CREATE:
            check_vali_add(esp+2);
            check_user_pointer(*(esp+1), 0);
            pin_frame(*(esp + 1));
            acquire_lock_filesys();
            f->eax = filesys_create(*(esp+1),*(esp+2));
            release_lock_filesys();
            unpin_frame(*(esp + 1));
            break;

        case SYS_REMOVE:
            check_vali_add(esp+1);
            check_user_pointer(*(esp+1), 0);

            pin_frame(*(esp + 1));
            acquire_lock_filesys();
            f->eax = filesys_remove(*(esp+1));
            release_lock_filesys();
            unpin_frame(*(esp + 1));
            break;

        case SYS_OPEN:
            check_vali_add(esp+1);
            check_user_pointer(*(esp+1), 0);

            pin_frame(*(esp+1));
            acquire_lock_filesys();
            struct file* fptr = filesys_open (*(esp+1));
            if(fptr==NULL)
            {
                f->eax = -1;
                release_lock_filesys();
                unpin_frame(*(esp+1));
                return;
            }
            else
            {
                struct file_descriptor *pfile = malloc(sizeof(*pfile));
                pfile->ptr = fptr;
                pfile->fd = thread_current()->fd_index;
                thread_current()->fd_index++;
                list_push_back (&thread_current()->files, &pfile->elem);
                f->eax = pfile->fd;
            }
            release_lock_filesys();
            unpin_frame(*(esp+1));
            break;

        case SYS_FILESIZE:
            check_vali_add (esp+1);
            acquire_lock_filesys ();
            f->eax = file_length (scan_file(&thread_current()->files, *(esp+1))->ptr);
            release_lock_filesys ();
            break;

        case SYS_READ:
            check_vali_add(esp + 3);
            check_user_pointer(*(esp + 2), *(esp + 3));
	        pin_frame( *(esp+2));
            void *upage = pg_round_down(*(esp+2));
            acquire_lock_page_fault();
            if(vm_sup_pg_table_lookup(upage, thread_current())->writeable != true){
                release_lock_page_fault();
                exit_proc(-1);
            }
            release_lock_page_fault();
            if(*(esp + 1) == 0)
            {
                int i;
                uint8_t* buffer = *(esp + 2);
                for(i = 0; i < *(esp + 3); i++)
                    buffer[i] = input_getc();
                f->eax = *(esp + 3);
            }
            else
            {
                struct file_descriptor* fptr = scan_file(&thread_current()->files, *(esp + 1));
                if(fptr == NULL)
                {
                    f->eax = -1;
                }
                else
                {
                    acquire_lock_filesys();
                    f->eax = file_read (fptr->ptr, *(esp+2), *(esp + 3));
                    release_lock_filesys();
                }
            }
            unpin_frame(*(esp + 2));
            break;

        case SYS_WRITE:
            check_vali_add (esp + 3);
            check_user_pointer (*(esp + 2), *(esp + 3));
            void * buffer = *((void **)(f->esp + 8));
            unsigned size = *((unsigned *)(f->esp + 12));

            pin_frame(*(esp + 2));
            if(*(esp + 1) == 1)   /* Write to stdout */
            {
                if(*(esp + 3) != 0)
                    putbuf(*(esp + 2),*(esp + 3));	/* put buffer and size to func putbuf */
                f->eax = *(esp + 3);			    /* Return size of buffer */
            }
            else
            {
                struct file_descriptor* fptr = scan_file (&thread_current()->files, *(esp + 1));
                if(fptr == NULL)
                {
                    f->eax = -1;
                }
                else
                {
                    acquire_lock_filesys ();
                    f->eax = file_write (fptr->ptr, *(esp + 2), *(esp + 3));
                    release_lock_filesys ();
                }
            }
            unpin_frame(*(esp + 2));
            break;

        case SYS_SEEK:
            check_vali_add(esp+ 2);

            acquire_lock_filesys ();
            file_seek (scan_file(&thread_current()->files, *(esp + 1))->ptr, *(esp + 2));
            release_lock_filesys ();
            break;

		case SYS_TELL:
            check_vali_add(esp+1);

            acquire_lock_filesys();
            f->eax = file_tell(scan_file(&thread_current()->files, *(esp + 1))->ptr);
            release_lock_filesys();
		    break;

		case SYS_CLOSE:
            check_vali_add (esp+1);
            acquire_lock_filesys ();
            close_file (&thread_current()->files,*(esp+1));
            release_lock_filesys ();
		    break;

		case SYS_MMAP:
            mmap_handler(f);
			break;
		case SYS_MUNMAP:
			munmap_handler(f);
			break;

        default:
            exit_proc(-1);
            break;
    }
}

void exit_proc (int status)
{
    struct list_elem *e;

    for (e = list_begin (&thread_current()->parent->child_proc); e != list_end (&thread_current()->parent->child_proc); e = list_next (e))
    {
        struct child *ch = list_entry (e, struct child, elem);
        if(ch->tid == thread_current()->tid)
        {
            ch->action = false;
            ch->exit_error = status;
        }
    }
    thread_current()->exit_error = status;

    if(thread_current()->parent->wait_tid == thread_current()->tid)
        sema_up(&thread_current()->parent->child_lock);

	// if(cur_thread_hold_lock_page_fault())
    // {
	// 	release_lock_page_fault();
	// }

    thread_exit();
}

void check_vali_add (const void *vaddr)
{
    int i;
    char *esp = (char *)vaddr;
    for(i=0; i< 4; i++)
    {
        if (!is_user_vaddr(esp + i))
        {
            exit_proc(-1);
        }
        /* Check if NULL */
        if(esp + i == NULL)
        {
            exit_proc(-1);
        }
        /* Verify that the user-addr is mapped to kernel-addr */ 
        void *check  = pagedir_get_page(thread_current()->pagedir, esp + i);
        if (check == NULL)
        {
            exit_proc(-1);
        }
    }
}

void check_user_pointer (void *vaddr, int size)
{
    int i=0;
	struct thread *cur = thread_current();
    void *user_ptr = vaddr;
    void *esp = vaddr;

    for(i=0; i< 4; i++)
    {
        /* exit if point to kernel virtual address space */
        if (!is_user_vaddr(esp + i))
        {
            exit_proc(-1);
            return;
        }
        /* Check if NULL */
        if(esp + i == NULL)
        {
            exit_proc(-1);
            return;
        }
    }

    acquire_lock_page_fault();
    /* Check if mapped */
    void *upage = pg_round_down(user_ptr);
    void *copy_til = user_ptr + size;
    while(copy_til > upage)
    {
        struct sup_pg_table_entry *ste = vm_sup_pg_table_lookup(upage, cur);
        if(ste == NULL)
        {
            exit_proc(-1);
            return;
        }
        if(ste->location == IN_SWAP)
        {
            void * kpage = palloc_get_page(PAL_USER);

            if(kpage == NULL)
            {
                vm_frame_table_evict_frame();
                kpage = palloc_get_page(PAL_USER);
                ASSERT(kpage != NULL);
            }
            /* Copy data into frame */
            vm_swap_in(kpage, ste->index);
            /* Update tables */
            pagedir_set_page(cur->pagedir, upage, kpage, ste->writeable);
            if(ste->from_file)
                pagedir_set_dirty (cur->pagedir, upage, true);

            vm_sup_pg_table_push_to_RAM (upage, cur);
            vm_frame_table_set_frame (upage, cur->tid);
        }
        else if(ste->location == IN_FILESYS)
        {
            void * kpage = palloc_get_page(PAL_USER);
            if(kpage == NULL){
                vm_frame_table_evict_frame();
                kpage = palloc_get_page(PAL_USER);
                ASSERT(kpage!=NULL);
            }
            /* Read data from file. */
            acquire_lock_filesys();
            file_read_at(ste->file, kpage, ste->read, ste->offset);
            release_lock_filesys();
            memset(kpage + ste->read, 0, ste->zero);
            /* Update tables */
            vm_sup_pg_table_push_to_RAM (upage, cur);
            pagedir_set_page (cur->pagedir, upage, kpage, ste->writeable);
            vm_frame_table_set_frame (upage, cur->tid);
        }

        upage += PGSIZE;
    }

    release_lock_page_fault();
}

int exec_proc (char *file_name)
{
    acquire_lock_filesys();
    char * fn_cp = malloc (strlen(file_name)+1);
    strlcpy(fn_cp, file_name, strlen(file_name)+1);
    char * save_ptr;
    fn_cp = strtok_r(fn_cp," ",&save_ptr);

    struct file* f = filesys_open (fn_cp);

    file_close(f);
    release_lock_filesys();
    if(f == NULL)
    {
        return -1;
    }

    return process_execute(file_name);
}

void close_file(struct list* files, int fd)
{
    struct list_elem *e;

    for (e = list_begin (files); e != list_end (files); e = list_next (e))
    {
        struct file_descriptor *f = list_entry (e, struct file_descriptor, elem);
        if(f->fd == fd)
        {
            file_close (f->ptr);
            list_remove (e);
            free(f);
            break;
        }
    }
}

void close_all_files(struct list* files)
{
    struct list_elem *e;
    while(!list_empty(files))
    {
        e = list_pop_front(files);
        struct file_descriptor *f = list_entry (e, struct file_descriptor, elem); 
        file_close(f->ptr);
        list_remove(e);
        free(f);
    }  
}

struct file_descriptor* scan_file(struct list* files, int fd)
{
	struct list_elem *e;

      for (e = list_begin (files); e != list_end (files); e = list_next (e))
        {
          struct file_descriptor *f = list_entry (e, struct file_descriptor, elem);
          if(f->fd == fd)
          	return f;
        }

    return NULL;
}

static void pin_frame(void * uaddr){
	void *upage = pg_round_down(uaddr);
	struct thread *cur = thread_current();
	struct frame_table_entry *fte;

	acquire_lock_page_fault();
	fte = vm_frame_table_lookup(upage, cur->tid);
	ASSERT(fte!= NULL);
	fte->pinned = true;
	release_lock_page_fault();

}

static void unpin_frame(void * uaddr){
	void *upage = pg_round_down(uaddr);
	struct thread *cur = thread_current();
	struct frame_table_entry *fte;

	acquire_lock_page_fault();
	fte = vm_frame_table_lookup(upage, cur->tid);
	ASSERT(fte!= NULL);
	fte->pinned = false;
	release_lock_page_fault();
}

static void add_mmap_page(void *upage, struct file *f, int offset_index){
	struct thread *cur = thread_current();

	struct mmap_page *mp = malloc(sizeof(struct mmap_page));

	mp->upage = upage;
	mp->map_id = cur->map_id;
	mp->file = f;
	mp->inode = file_get_inode(f);
	mp->offset = offset_index *PGSIZE;

	list_push_front(&cur->mmap_page_list, &mp->list_elem);
}

static void mmap_handler(struct intr_frame *f)
{
    int *esp = f->esp;
    int fd;
    void *addr;
    int file_size;
    struct file *file;
    int no_of_pages;
    struct thread *cur = thread_current();
    void *upage;
    struct file_descriptor *fptr;
    int i;

    fd = *((int *)(esp+1));
    addr = *((void **)(esp+2));
    check_vali_add(esp+2);

    if((int)addr == 0)
    {	
        f->eax = -1;
        return;
    }
    fptr = scan_file (&thread_current()->files, *(esp + 1));
    if(fptr == NULL)
    {
        f->eax = -1;
        return;
    }
    if(pg_round_down(addr) != addr)
    {
        f->eax = -1;
        return;
    }
    if(fd == 0 || fd == 1){
        f->eax = -1;
        return;
    }
    acquire_lock_filesys ();
    file_size = file_length(fptr->ptr);
    if(file_size == 0)
    {
        release_lock_filesys ();
        f->eax = -1;
        return;
    }
    release_lock_filesys ();
    /* Check if the consecutive pages overlap with any other pages.*/
    no_of_pages = file_size / PGSIZE; 
    if(file_size % PGSIZE != 0)
        no_of_pages++;

    upage = addr;
    for(i =0; i < no_of_pages; i++)
    {
        if(vm_sup_pg_table_lookup(upage + i*PGSIZE, cur) != NULL)
        {
            f->eax = -1;
            return;
        }
    }
    /* Acquire locks. */
    acquire_lock_filesys ();
    acquire_lock_page_fault ();

    /* Reopen file for reading. */
    file = file_reopen(fptr->ptr);
    int offset = 0;
    /* Map the pages */
    for(i =0; i < no_of_pages; i++)
    {
        vm_sup_pg_table_set_page (upage + i*PGSIZE, true);
        vm_sup_pg_table_push_to_FILE (upage + i*PGSIZE, file, offset, PGSIZE, 0, cur);
        add_mmap_page (upage+i*PGSIZE, file, i);
        offset += PGSIZE;
    }
    /* Return map id. */
    f->eax = cur->map_id;
    /* Update map id */
    cur->map_id++;
    /* Close file after reading. */
    release_lock_page_fault ();
    release_lock_filesys ();
}

static void munmap_handler(struct intr_frame *f)
{
    int *esp = f->esp;
	int map_id = *((int *)(f->esp + 4));
	check_vali_add(esp+1);

	struct thread *cur = thread_current();
	struct list_elem *e;
	struct list *l = &cur->mmap_page_list;
	struct file *file = NULL;
	struct mmap_page *mp;

	acquire_lock_filesys ();
	acquire_lock_page_fault();

	for(e = list_begin(l); e!= list_end(l); e = list_next(e))
    {
    	mp = list_entry(e, struct mmap_page, list_elem);
    	if(mp->map_id == map_id)
        {
    		struct sup_pg_table_entry *ste = vm_sup_pg_table_lookup(mp->upage, cur);
    		ASSERT(ste->upage == mp->upage);
    		if(ste->location == IN_RAM)
            {
    			if(pagedir_is_dirty(cur->pagedir, ste->upage))
                {
    				void * kpage = pagedir_get_page(cur->pagedir, ste->upage);
    				file_write_at(ste->file, kpage, PGSIZE, ste->offset);

    				palloc_free_page(kpage);
    				pagedir_clear_page(cur->pagedir, ste->upage);
    				vm_frame_table_delete_entry(ste->upage, cur->tid);
    				vm_sup_pg_table_delete_entry(ste->upage);
    			}
    			else
                {
    				void * kpage = pagedir_get_page(cur->pagedir, ste->upage);
    				palloc_free_page(kpage);
    				pagedir_clear_page(cur->pagedir, ste->upage);
    				vm_frame_table_delete_entry(ste->upage, cur->tid);
    				vm_sup_pg_table_delete_entry(ste->upage);
    			}
    		}
    		else if(ste->location == IN_FILESYS)
            {
    			vm_sup_pg_table_delete_entry(ste->upage);
    		}
    		else if(ste->location == IN_SWAP)
            {
    			void * kpage = palloc_get_page(0);
    			vm_swap_in(kpage, ste->index);
    			file_write_at(ste->file, kpage, PGSIZE, ste->offset);
    			palloc_free_page(kpage);
    			vm_swap_free(ste->index);
    			vm_sup_pg_table_delete_entry(ste->upage);
    		}

    		/* Remove from list and free. */
    		list_remove(e);
    		free(mp);
            break;
    	}
	}

	release_lock_page_fault();
	release_lock_filesys ();
}
