#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "devices/block.h"
#include "lib/kernel/bitmap.h"
#include <bitmap.h>
#include "threads/vaddr.h"

/* Number of sectors needed to store a page */
#define SECTORS_PER_PAGE  (PGSIZE / BLOCK_SECTOR_SIZE)
#define SWAP_ERROR -100

/** 
 *	Bitmap represents whether the pages are free.
 *	Bit at index represents whether page at index is free.
 *	Each bit represents a page.
 */
struct swap_table{
	struct block * swap_block;
	struct bitmap * swap_bitmap;
};


void vm_swap_init(void);
void vm_swap_free(int index);
void vm_swap_destroy(void);
bool vm_swap_in(void * kpage, int bitmap_index);
int vm_swap_out(void * kpage);

#endif /* VM_SWAP_H */
