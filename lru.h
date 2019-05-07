#ifndef LRU_H_
#define LRU_H_
#include <uv.h>
#include "container.h"
typedef struct lru_data_s lru_data_t;
typedef struct lru_cache_s lru_cache_t;
#define PUT(map, key, val) map->put(map, (void*)key, (void*)val)
// might get NULL
#define GET(map, key) (lru_data_t*)map->get(map, (void*)key)
#define EXIST(map, key) map->exist(map, (void*)key)
#define ERASE(map, key) map->erase(map, (void*)key)

struct lru_data_s {
    char* key;
    struct addrinfo* addrinfo;
    lru_data_t* prev;
    lru_data_t* next;
};

struct lru_cache_s {
    hash_map_t* map;
    size_t size;
    size_t capacity;
    lru_data_t* head;
    lru_data_t* tail;
};
// no need to consider situation that when head = tail = NULL because cache is empty
void _erase_from_list(lru_cache_t* cache, lru_data_t* node) {
    // when node = cache->head or node = cache->tail, head->prev/tail->next != NULL, but doesn't matter
    if(cache->size == 0) return;
    if(node == cache->head) {
        cache->head = node->next;
    } else if(node == cache->tail) {
        cache->tail = node->prev;
    } else {
        node->prev->next = node->next;
        node->next->prev = node->prev;
    }
    free(node);
    cache->size--;
    return;
}

void _emplace_front_from_list(lru_cache_t* cache, char* key, struct addrinfo* val) {
    lru_data_t* node = (lru_data_t*)palloc(sizeof(lru_data_t));
    if(cache->size == 0) {
        cache->head = cache->tail = node;
        cache->size++;
        return;
    }
    node->next = cache->head;
    node->prev = NULL;
    cache->head->prev = node;
    cache->head = node;
    node->key = key;
    node->addrinfo = val;
    cache->size++;
    return;
}

void _pop_back_from_list(lru_cache_t* cache) {
    if(cache->size == 0) return;
    if(cache->size == 1) {
        uv_freeaddrinfo(cache->tail->addrinfo);
        free(cache->tail);
        cache->head = cache->tail = NULL;
        cache->size--;
        return;
    }
    lru_data_t* tail = cache->tail;
    cache->tail = tail->prev;
    cache->tail->next = NULL;
    uv_freeaddrinfo(tail->addrinfo);
    free(tail);
    cache->size--;
}

void put(lru_cache_t* cache, char* key, struct addrinfo* val) {
    if(EXIST(cache->map, key)) {
        _erase_from_list(cache, GET(cache->map, key));
        _emplace_front_from_list(cache, key, val);
        PUT(cache->map, key, cache->head);
    } else {
        if(cache->size == cache->capacity) {
            lru_data_t* last = cache->tail;
            ERASE(cache->map, last->key);
            _pop_back_from_list(cache);
        }
        _emplace_front_from_list(cache, key, val);
        PUT(cache->map, key, cache->head);
    }
}

struct addrinfo* get(lru_cache_t* cache, char* key) {
    lru_data_t* idx = GET(cache->map, key);
    if(!idx) return NULL;
    struct addrinfo* val = idx->addrinfo;
    put(cache, key, val);
    return val;
}

lru_cache_t* new_lru_cache(int capacity) {
    lru_cache_t* cache = (lru_cache_t*)palloc(sizeof(lru_cache_t));
    memset(cache, 0, sizeof(lru_cache_t));
    cache->map = default_hash_map(capacity);
    cache->capacity = capacity;
    return cache;
}
#endif
