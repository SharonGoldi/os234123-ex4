
#include <stdlib.h>
#include <unistd.h>
#define MIN_SIZE 0
#define MAX_SIZE 10^8

void* malloc(size_t size) {
    if (size <= MIN_SIZE || size > MAX_SIZE) {
        return NULL;
    }
    void* pointer = sbrk(size);

    if (pointer == (void*) -1) {
        return NULL;
    }
    return pointer;
}
