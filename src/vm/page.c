#include "page.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <stdio.h>

static unsigned sup_pg_table_hash(const struct hash_elem *p_, void *aux UNUSED);
static bool sup_pg_table_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);
static void free_each_entry(struct hash_elem *e, void *aux);

/**
 * Creates a supplemental page table. 
 */
struct sup_pg_table *vm_sup_pg_table_init(void)
{
	struct sup_pg_table *st;

	st = malloc(sizeof(struct sup_pg_table));
	hash_init(&st->supplemental, sup_pg_table_hash, sup_pg_table_less, NULL);

	return st;
}

/**
 * Makes a supplemental page table entry that contains information
 * about a virtual page(upage). Corresponding this page will be
 * placed in RAM when this is called.
 */
void vm_sup_pg_table_set_page(void *upage, bool writeable)
{
	struct sup_pg_table_entry *ste;
	struct thread *cur = thread_current();
	struct sup_pg_table *st_temp = cur->sup_pg_table;

	/* make sure the sup table entry doesn't already exist */
	ASSERT(vm_sup_pg_table_lookup(upage, cur) == NULL);
	/* Make entry in sup table */
	ste = malloc(sizeof(struct sup_pg_table_entry));
	ste->location = IN_RAM;
	ste->writeable = writeable;
	ste->upage = upage;
	ste->index = -100;
	ste->from_file = false;
	ste->read = PGSIZE;
	ste->zero = 0;

	hash_insert(&st_temp->supplemental, &ste->hash_elem);
}


void vm_sup_pg_table_delete_entry(void *upage)
{
	struct hash_elem *e;
	struct sup_pg_table_entry *p, ste;
	struct sup_pg_table *st_temp = thread_current()->sup_pg_table;

	ste.upage = upage;
	e = hash_delete (&st_temp->supplemental, &ste.hash_elem);
	ASSERT(e != NULL);
	p = hash_entry(e, struct sup_pg_table_entry, hash_elem);
	free(p);
}

/* Modifies information of the page */

void vm_sup_pg_table_push_to_RAM(void *upage, struct thread *t)
{
	/* Make sure entry exists in the table already. */
	ASSERT(vm_sup_pg_table_lookup(upage, t) != NULL);
	struct sup_pg_table_entry *ste = vm_sup_pg_table_lookup(upage, t);
	ste->location = IN_RAM;
}

void vm_sup_pg_table_push_to_SWAP(void *upage, int index, struct thread *t)
{
	ASSERT(vm_sup_pg_table_lookup(upage, t) != NULL);

	struct sup_pg_table_entry *ste = vm_sup_pg_table_lookup(upage, t);
	ste->location = IN_SWAP;
	ste->index = index;
}

void vm_sup_pg_table_push_to_FILE(void *upage, struct file *file, int offset, int read, int zero, struct thread *t)
{
	ASSERT(vm_sup_pg_table_lookup(upage, t) != NULL);
	struct sup_pg_table_entry *ste = vm_sup_pg_table_lookup(upage, t);

	ste->location = IN_FILESYS;
	ste->file = file;
	ste->offset = offset;
	ste->read = read;
	ste->zero = zero;
	ste->from_file = true;
}

struct sup_pg_table_entry *vm_sup_pg_table_lookup(void *upage, struct thread *cur)
{
	struct sup_pg_table *st = cur->sup_pg_table;
	struct sup_pg_table_entry ste;
	struct hash_elem *e;

	ste.upage = upage;
	e = hash_find (&st->supplemental, &ste.hash_elem);

	return e == NULL ? NULL : hash_entry(e, struct sup_pg_table_entry, hash_elem);
}


void vm_sup_pg_table_destroy(struct sup_pg_table *st)
{
	hash_destroy(&st->supplemental, free_each_entry);
}

static void free_each_entry(struct hash_elem *e, void *aux)
{
	struct sup_pg_table_entry *ste = hash_entry(e, struct sup_pg_table_entry, hash_elem);
	free(ste);
}

/** 
 * Functions are used for hash table
 * ref: A.8 Hash Table
 */

/* Hash function */
static unsigned sup_pg_table_hash(const struct hash_elem *ste_, void *aux UNUSED)
{
	const struct sup_pg_table_entry *ste = hash_entry(ste_, struct sup_pg_table_entry, hash_elem);
	return hash_bytes(&ste->upage, sizeof(ste->upage));
}

/* Comparison function */
static bool sup_pg_table_less(const struct hash_elem *a_,
							const struct hash_elem *b_,
							void * aux UNUSED)
{
	const struct sup_pg_table_entry *a = hash_entry(a_, struct sup_pg_table_entry, hash_elem);
	const struct sup_pg_table_entry *b = hash_entry(b_, struct sup_pg_table_entry, hash_elem);

	return a->upage < b->upage;
}
