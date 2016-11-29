
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */
  nat->aux_counter = 1024;

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  struct sr_nat_mapping *mapping = NULL;
  struct sr_nat_mapping *next = NULL;
  for (mapping = nat->mappings; mapping; mapping = next) {
    next = mapping->next;
    sr_nat_mapping_destroy(mapping);
  }

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void sr_nat_mapping_destroy(struct sr_nat_mapping *mapping) {
  struct sr_nat_connection *conn = NULL;
  struct sr_nat_connection *next = NULL;

  for (conn = mapping->conns; conn; conn = next) {
    next = conn->next;
    free(conn);
  }

  free(mapping);
}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);
    int timeout;

    /* handle periodic tasks here */
    struct sr_nat_mapping *mapping = NULL;
    struct sr_nat_mapping *next = NULL;
    for (mapping = nat->mappings; mapping; mapping = next) {
      next = mapping->next;
      /* get timeout */
      if (mapping->type == nat_mapping_icmp) {
        timeout = nat->timeout_icmp;
      } else if (mapping->type == nat_mapping_tcp) {
        timeout = nat->timeout_tcp_E;
      }
      if (difftime(curtime, mapping->last_updated) >= timeout) {
        sr_nat_mapping_destroy(mapping);
      }
    }
    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *entry = NULL;
  struct sr_nat_mapping *walker = nat->mappings;

  while (walker != NULL) {
    if (walker->aux_ext == aux_ext) {
      entry = walker;
    }
  }

  /* Must return a copy b/c another thread could jump in and modify
     table after we return. */
  if (entry) {
      copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, entry, sizeof(struct sr_nat_mapping));
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *entry = NULL;
  struct sr_nat_mapping *walker = nat->mappings;

  while (walker != NULL) {
    if (walker->aux_int == aux_int && walker->ip_int == ip_int) {
      entry = walker;
    }
  }

  /* Must return a copy b/c another thread could jump in and modify
     table after we return. */
  if (entry) {
      copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, entry, sizeof(struct sr_nat_mapping));
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, uint32_t ip_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;
  struct sr_nat_mapping *entry = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
  struct sr_nat_connection *conns = NULL;
  if (type == nat_mapping_tcp) {
    conns = (struct sr_nat_connection *) malloc(sizeof(struct sr_nat_connection));
  }

  /* assign values */
  entry->type = type;
  entry->ip_int = ip_int;
  entry->ip_ext = ip_ext;
  entry->aux_int = aux_int;
  entry->aux_ext = nat->aux_counter;
  entry->last_updated = time(NULL);
  entry->conns = conns;
  entry->next = nat->mappings;
  nat->mappings = entry;

  /* TODO: now just incrementing the port numbers.
           need to implement when the port reaches max (65535)
           which would probably rarely happen for this assignment */
  nat->aux_counter += 1;

  mapping = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
  memcpy(mapping, entry, sizeof(struct sr_nat_mapping));

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}
