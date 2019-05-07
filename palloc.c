#include "palloc.h"
#include <stdlib.h>
#include <stddef.h>
void* palloc(size_t size) {
    return malloc(size);
}