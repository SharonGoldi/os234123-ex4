#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define MIN_SIZE 0
#define MAX_SIZE 100000000
#define LARGE_ENOUGH_MEM 128
#define MEM_LINE_LEN 4
#define BLOCK_SIZE align_size(sizeof(struct block))


struct block {
    size_t size;
    struct block* next;
    struct block* prev;
    int is_free;
};
typedef struct block* Block;

Block global_last_allocated = NULL;
Block global_first_allocated = NULL;


size_t align_size(size_t size) {
    if (size % MEM_LINE_LEN == 0) {
        return size;
    } else {
        return size + MEM_LINE_LEN - size % MEM_LINE_LEN;
    }
}

Block DivideLargeBlock(Block old_block, size_t size) {
    Block new_block = (Block)((char*)old_block + BLOCK_SIZE + size);

    new_block->size = (size_t)((int)old_block->size - (int)size - (int)BLOCK_SIZE);
    old_block->size = size;
    new_block->next = old_block->next;
    old_block->next = new_block;
    new_block->prev = old_block;
    new_block->is_free = 1;

    if (new_block->next != NULL) {
        new_block->next->prev = new_block;
    }
    return new_block;
}

Block FindFreeBlock(size_t size) {
    Block curr = global_first_allocated;
    while (curr != NULL &&
            !(curr->size >= size && curr->is_free)) { //TODO: check cond
        curr = curr->next;
    }
    size_t aligmnentSize = align_size(size);
    if (curr != NULL &&
            curr->size >= aligmnentSize + BLOCK_SIZE + LARGE_ENOUGH_MEM) {
        DivideLargeBlock(curr, aligmnentSize);
    }
    // if all blocks do not fit and the last block is freed but not big enough
    // - make it bigger.
    if (curr == NULL && global_last_allocated->is_free) {
        unsigned long diff = align_size(size) - global_last_allocated->size;

        void* added = sbrk(diff);
        if (added == (void*) -1) {
            return NULL;
        }
        global_last_allocated->size += diff;
        return global_last_allocated;
    } else {
        return curr;
    }
}

Block AddNewBlock(size_t size) {
    Block block = (Block)sbrk(0);
    
    void* new_block = sbrk(BLOCK_SIZE);

    if (new_block == (void*) -1) {
        return NULL;
    }

    void* new_data = sbrk(align_size(size));
    if (new_data == (void*) -1) {
        sbrk(-BLOCK_SIZE);
        return NULL;
    }

    if(global_last_allocated != NULL) {
        global_last_allocated->next = block;
    }

    block->size = align_size(size);
    block->next = NULL;
    block->prev = global_last_allocated;
    global_last_allocated = block;
    block->is_free = 0;

    return block;
}

void MergeAdjacentBlocks(Block first, Block second) {
    // TODO: be aware, this function changes it's input parameters
    first->size += second->size + BLOCK_SIZE;
    first->next = second->next;

    if (second->next != NULL) {
        second->next->prev = first;
    }

    second->size = 0;
    second->prev = NULL;
    second->next = NULL;
}

/////////////////////////////////////////////////////////////////////////////////

void* malloc(size_t size) {
    //check input
    if (size <= MIN_SIZE || size > MAX_SIZE) {
        return NULL;
    }

    Block block;
    //if its the first call to malloc
    if(global_first_allocated == NULL) {
        block = AddNewBlock(size);
        if (block == NULL) {
            return NULL;
        }
        global_first_allocated = block;
    } else {
        block = FindFreeBlock(size);
        // if there is a freed block, unfree him, update the block info and return it
        if (block != NULL) {
            block->is_free = 0;
        } else { // if there isn't any freed block, allocate a new one
            block = AddNewBlock(size);
            if (block == NULL) {
                return NULL;
            }
        }
    }
    // jump a size of a block and jump over the metadata
    return (char *)block + BLOCK_SIZE;
}

void free(void* p) {
    if (p == NULL) {
        return;
    }

    Block block = (Block)((char *)p - BLOCK_SIZE);
    block->is_free = 1;

    if (block->next != NULL && block->next->is_free) {
        MergeAdjacentBlocks(block, block->next);
    }

    if (block->prev != NULL && block->prev->is_free) {
        MergeAdjacentBlocks(block->prev, block);
    }
}

void* calloc(size_t num, size_t size){
    void* p = malloc(num*size);
    if (p == NULL) {
        return NULL;
    }

    memset(p, 0, num*size);
    return p;
}

void* realloc(void* oldp, size_t size) {
    // check input
    if (size <= MIN_SIZE || size > MAX_SIZE) {
        return NULL;
    }
    if (oldp == NULL) {
        return malloc(size);
    }
    Block old_block = (Block)((char *)oldp - BLOCK_SIZE);
    // if the new size is smaller - no need to realloc (wasteful but works)
    size_t aligned_size = align_size(size);

    if (old_block->size >= aligned_size) {
        Block new_block = NULL;

        if (old_block->size >= aligned_size + BLOCK_SIZE + LARGE_ENOUGH_MEM) {
            new_block = DivideLargeBlock(old_block, aligned_size);
        }
        if (new_block != NULL && new_block->next != NULL && new_block->next->is_free) {
            MergeAdjacentBlocks(new_block, new_block->next);
        }
        return oldp;

    } // if the new size is bigger and the block above it is free and has enough space
    else if (old_block->next != NULL && old_block->next->is_free &&
             old_block->size + BLOCK_SIZE + old_block->next->size >= aligned_size) {
        MergeAdjacentBlocks(old_block, old_block->next);

        if (old_block->size >= aligned_size + BLOCK_SIZE + LARGE_ENOUGH_MEM) {
            DivideLargeBlock(old_block, aligned_size);
        }
        return oldp;

    }// if we realloc on a "wilderness" style block (last allocated block)
    else if (old_block == global_last_allocated) { // same as old_block->next == NULL
        unsigned long diff = aligned_size - old_block->size;

        void* added = sbrk(diff);
        if (added == (void*) -1) {
            return NULL;
        }
        old_block->size += diff;
        return oldp;
    }
    else { // need to allocate a new memory block and free the old one
        void *newp = malloc(size);
        if (newp == NULL) {
            return NULL;
        }

        memcpy(newp, oldp, old_block->size);
        free(oldp);
        return newp;
    }
}

size_t _num_free_blocks() {
    unsigned int num_free = 0;
    Block block = global_first_allocated;
    while (block != NULL) {
        if(block->is_free) {
            num_free++;
        }
        block = block->next;
    }
    return num_free;
}

size_t _num_free_bytes() {
    unsigned int num_free = 0;
    Block block = global_first_allocated;
    while (block != NULL) {
        if(block->is_free) {
            num_free += block->size;
        }
        block = block->next;
    }
    return num_free;
}

size_t _num_allocated_blocks() {
    unsigned int num_allocated = 0;
    Block block = global_first_allocated;
    while (block != NULL) {
        num_allocated++;
        block = block->next;
    }
    return num_allocated;
}

size_t _num_allocated_bytes() {
    unsigned int num_allocated = 0;
    Block block = global_first_allocated;
    while (block != NULL) {
        num_allocated += block->size;
        block = block->next;
    }
    return num_allocated;
}

size_t _num_meta_data_bytes() {
    return _num_allocated_blocks() * BLOCK_SIZE;
}

size_t _size_meta_data() {
    return BLOCK_SIZE;
}
