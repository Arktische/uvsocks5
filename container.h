#ifndef CONTAINER_H_
#define CONTAINER_H_
#include "palloc.h"
#include <string.h>
typedef struct hash_entry_s {
    void* key;
    void* val;
    struct hash_entry_s* next; // conflict linked list 
}hash_entry_t;
typedef struct hash_map_s hash_map_t;

typedef int(*hash_func)(hash_map_t* map, void* key);
typedef void(*put_func)(hash_map_t* map, void* key, void* val);
typedef int(*equal_func)(hash_map_t* map, void* key1, void* key2);
typedef int(*exist_func)(hash_map_t* map, void* key);
typedef void*(*get_func)(hash_map_t* map, void* key);
typedef void(*clear_func)(hash_map_t* map);
typedef void(*erase_func)(hash_map_t* map, void* key);
struct hash_map_s {
    size_t size;
    size_t capacity;
    hash_entry_t* list;
    hash_func hash;
    put_func put;
    equal_func equal;
    exist_func exist;
    get_func get;
    clear_func clear;
    erase_func erase;
};

typedef void *DLIST[2];

int default_hash(hash_map_t* map, void* key) {
    char* str = (char*)key;
    unsigned long h = 0;
    while(*str) {
        h = (h << 4) + *str++;
        unsigned long g = h & 0xF0000000L;
        if(g) h ^= g >> 24;
        h &= ~g;
    }
    return h%(map->capacity);
}

int default_equal(hash_map_t* map, void* key1, void* key2) {
    char* p1 = (char*)key1;
    char* p2 = (char*)key2;
    while(*p1 && *p2) {
        if(*p1 != *p2) return 0;
        p1++;p2++;
    }
    if(*p1 || *p2) return 0;
    return 1;
}

// notice: never put a key-val pair that exists in stack into the map 
void default_put(hash_map_t* map, void* key, void* val) {
    int idx = map->hash(map, key);
    if(map->list[idx].key == NULL) {
        map->size++;
        map->list[idx].key = key;
        map->list[idx].val = val;
        return;
    }
    hash_entry_t* cur = &map->list[idx];
    while(cur != NULL) {
        if(map->equal(map, key, cur->key)) {
            cur->val = val;
            return;
        }
        cur = cur->next;
    }

    hash_entry_t* entry = (hash_entry_t*)palloc(sizeof(hash_entry_t));

    entry->key = key;
    entry->val = val;
    entry->next = map->list[idx].next;
    map->list[idx].next = entry;
    map->size++;
}

void* default_get(hash_map_t* map, void* key) {
    int idx = map->hash(map, key);
    hash_entry_t* entry = &map->list[idx];

    while(entry->key != NULL && !map->equal(map, key, entry->key)) {
        entry = entry->next;
    }
    return entry->val;
}

int default_exist(hash_map_t* map, void* key) {
    int idx = map->hash(map, key);
    hash_entry_t* entry = &map->list[idx];
    if(entry->key == NULL) {
        return 0;
    } else if(map->equal(map, entry->key, key)) {
        return 1;
    } else if(entry->next != NULL){
        do {
            if(map->equal(map, entry->key, key))
                return 1;
        } while(entry != NULL);
        return 0;
    }
    return 0;
}

void default_clear(hash_map_t* map) {
    for(int i = 0; i < map->capacity; ++i) {
        hash_entry_t* entry = map->list[i].next;
        while(entry != NULL) {
            hash_entry_t* next = entry->next;
            free(entry);
            entry = next;
        }
        map->list[i].next = NULL;
    }
    free(map->list);
    map->list = NULL;
    map->size = 0;
    map->capacity = 0;
    return;
}

void default_erase(hash_map_t* map, void* key) {
    int index = map->hash(map, key);
    hash_entry_t* entry = &map->list[index];
    if (entry->key == NULL) {
        return;
    }
    hash_entry_t* p = entry;
    while(p->next != NULL) {
        if(map->equal(map, key, p->next->key)) {
            hash_entry_t* tmp = p->next;
            p->next = tmp->next;
            free(tmp);
            map->size--;
        }
        p = p->next;
    }
    if(map->equal(map, entry->key, key)) {
        map->size--;
        entry->key = entry->val = NULL;
    }
    return;
}

hash_map_t* default_hash_map(int capacity) {
    hash_map_t* map = (hash_map_t*)palloc(sizeof(hash_map_t));
    map->size = 0;
    map->capacity = capacity;
    map->equal = default_equal;
    map->hash = default_hash;
    map->get = default_get;
    map->put = default_put;
    map->exist = default_exist;
    map->clear = default_clear;
    map->list = (hash_entry_t*)palloc(capacity*sizeof(hash_entry_t));
    map->erase = default_erase;
    memset(map->list, 0, capacity*sizeof(hash_entry_t));
    return map;
}
#endif