#include "frame.h"
#include <stdio.h>
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/swap.h"
#include "vm/page.h"

struct list evict_list;
struct list_elem * clock;

static unsigned frame_hash (const struct hash_elem *f_, void *aux UNUSED);
static bool frame_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);
static void free_each_entry (struct hash_elem *e, void *aux);

void vm_frame_table_init(void)
{
	ft = malloc(sizeof (struct frame_table));
	hash_init(&ft->frames, frame_hash, frame_less, NULL);
	list_init(&evict_list);
	lock_init(&frame_table_lock);
}

void vm_frame_table_set_frame(void * upage, int tid)
{
	ASSERT(vm_frame_table_lookup(upage, tid)== NULL);
	struct frame_table_entry * f = malloc(sizeof(struct frame_table_entry));

	lock_acquire(&frame_table_lock);
	f->upage = upage; 
	f->tid = tid;
	f->pinned = false;
	f->owner_thread = thread_current();
	hash_insert(&ft->frames, &f->hash_elem);
	list_push_front(&evict_list, &f->list_elem);
	/** Make clock point to the only element */
	if(list_size(&evict_list) ==1 ){
		clock = list_front(&evict_list);
	}
	ASSERT(clock != NULL);
	lock_release(&frame_table_lock);

	ASSERT(vm_frame_table_lookup(upage,tid)!= NULL);
}

/** Evict a frame based on algorithm clock */
void vm_frame_table_evict_frame()
{
	uint32_t *pagedir = thread_current()->pagedir;
	void *kpage;
	void *upage;
	struct frame_table_entry *fte;
	struct hash_elem *e;
	struct list_elem *le;

	lock_acquire(&frame_table_lock);
	/** Find a page for removeal base on clock algorithm */
	le = clock;
	while(true)
	{
		fte = list_entry(le, struct frame_table_entry, list_elem);
		upage = fte->upage;
		/* If not been accessed since last consideration */
		if(!pagedir_is_accessed(pagedir, upage))
		{
			if(fte->pinned == false)
			{
				if(clock == list_end(&evict_list))
					clock = list_front(&evict_list);
				else
					clock = list_next(le);
				break;
			}
		}
		else
		{
			pagedir_set_accessed(pagedir, upage, false);
		}
		if(le == list_end(&evict_list))
			le = list_front(&evict_list);
		else
			le = list_next(le);
	}

	/* Delete from hash table and list. */
	e = hash_delete(&ft->frames,&fte->hash_elem);
	ASSERT(e != NULL);
	list_remove(&fte->list_elem);
	ASSERT(hash_size(&ft->frames) == list_size(&evict_list));

	struct thread * owner_thread = thread_current();
	fte = hash_entry(e, struct frame_table_entry, hash_elem);
	upage = fte->upage;
	owner_thread = fte->owner_thread;
	kpage = pagedir_get_page(owner_thread->pagedir, upage);
	/* Free the entry */
	free(fte);

	struct sup_pg_table_entry *ste = vm_sup_pg_table_lookup(upage, owner_thread);

	if(ste->from_file)
	{
		ASSERT(pagedir_get_page(owner_thread->pagedir, upage)!= NULL);
		/* Write out to swap if dirtied. */
		if(pagedir_is_dirty(owner_thread->pagedir, upage))
		{
			int swap_location = vm_swap_out(kpage);

			palloc_free_page(kpage);
			vm_sup_pg_table_push_to_SWAP(upage, swap_location, owner_thread);
			pagedir_clear_page(owner_thread->pagedir, upage);
			lock_release(&frame_table_lock);
		}
		/* Page only accessed, not dirtied. */
		else
		{
			palloc_free_page(kpage);
			vm_sup_pg_table_push_to_FILE(upage, ste->file, ste->offset, ste->read, ste->zero, owner_thread);
			pagedir_clear_page(owner_thread->pagedir, upage);
			lock_release(&frame_table_lock);
		}
	}
	/* Swap slots. */
	else
	{
		/* Swap out this page to swap slot */
		int swap_location = vm_swap_out(kpage);
		palloc_free_page(kpage);
		/* Update sup table and page table. */
		vm_sup_pg_table_push_to_SWAP(upage, swap_location, owner_thread);
		pagedir_clear_page(owner_thread->pagedir, upage);
		ASSERT(hash_size(&ft->frames) != 1);
		lock_release(&frame_table_lock);
	}

}

/* Look up the frame that points to upage. */
struct frame_table_entry * vm_frame_table_lookup(void * upage, int tid)
{
	struct frame_table_entry fte;
	struct hash_elem * e;

	lock_acquire(&frame_table_lock);
	fte.upage = upage;
	fte.tid = tid;
	e = hash_find(&ft->frames,&fte.hash_elem);
	lock_release(&frame_table_lock);

	return e == NULL ? NULL : hash_entry(e, struct frame_table_entry, hash_elem);
}

/* Delete and free entry */
void vm_frame_table_delete_entry(void * upage, int tid)
{
	lock_acquire(&frame_table_lock);
	struct hash_elem * e;
	struct frame_table_entry * p;
	struct frame_table_entry fte;

	fte.upage = upage;
	fte.tid = tid;
	e = hash_delete(&ft->frames,&fte.hash_elem);
	p = hash_entry(e, struct frame_table_entry, hash_elem);
	if(clock == &p->list_elem){
		clock = list_next(&p->list_elem);
	}

	list_remove(&p->list_elem);
	free(p);
	lock_release(&frame_table_lock);
}

void vm_frame_table_destroy(void)
{
	hash_destroy(&ft->frames, free_each_entry);
}

static void free_each_entry(struct hash_elem * e, void * aux)
{
	struct frame_table_entry * fte = hash_entry(e, struct frame_table_entry, hash_elem);
	free(fte);
}

/** 
 * Functions are used for hash table
 * ref: A.8 Hash Table
 */

/** Hash function */
static unsigned frame_hash(const struct hash_elem *f_, void * aux UNUSED)
{
	const struct frame_table_entry *f = hash_entry(f_, struct frame_table_entry, hash_elem);
	int hash_this = hash_bytes(&f->upage, sizeof(f->upage)) ^ hash_bytes(&f->tid, sizeof(f->tid));

	return hash_this;
}

/** Compares the upage address */
static bool frame_less(const struct hash_elem *a_,
						const struct hash_elem *b_,
						void *aux UNUSED)
{
	unsigned a_hash = frame_hash(a_, NULL);
	unsigned b_hash = frame_hash(b_,NULL);

	return a_hash > b_hash;
}

