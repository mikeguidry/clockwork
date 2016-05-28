#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "list.h"

LINK *l_last(LINK *start) {
  while (start->next != 0) start = start->next;
  
  return start;
}

void l_link(LINK **list, LINK *ele) {
  ele->next = *list;
  *list = ele;
}


LINK *l_add(LINK **list, int size) {
  LINK *cur, *newptr;

  newptr = (LINK *)calloc(size,1);
  if (newptr == NULL) return NULL;

  l_link(list, newptr);
  
  cur->next = *list;
  *list = cur;

  return newptr;
}

void l_del(LINK **l_ptr, LINK *rem) {
  
  while ((*l_ptr) != rem) {
    l_ptr = &(*l_ptr)->next;
  }
  
  *l_ptr = rem->next;
  
}

int l_count(LINK *l_ptr) {
        int i = 0;

        while (l_ptr != 0) {
                i++;

                l_ptr = l_ptr->next;
        }

        return i;
}
// end linked functions


LIST *L_last(LIST *start) {
  return (LIST *)l_last((LINK *)start);
}

LINK *l_new(int size) {
  LINK *ret = (LINK *)calloc(size, 1);
  
  return ret;
}

LINK *L_new(int size) {
  return (LINK *)l_new(size);
}

LIST *L_add(LIST **list, int size) {
  LIST *ret = (LIST *)L_new(size);
  
  if (ret) {
    L_link((LIST **)list, (LIST *)ret);
    
    ret->start_ts = time(0);
  }
   
  return ret;
}

int L_count(LIST *l_ptr) {
  return l_count((LINK *)l_ptr);
}

void L_del(LIST **l_ptr, LIST *rem) {
  if (rem->buf != NULL) {
    // later we should keep track of sizes.. so we can zero the memory
    free(rem->buf);
  }
  
  // close sock.. make this os independent for win32 , etc
  if (rem->fd > 0)
    close(rem->fd);
    
  l_del((LINK **)l_ptr, (LINK *)rem);
}

void L_del_next(LIST **l_ptr, LIST *rem, LIST **l_next) {
  LIST *lnext = rem->next;
  
  L_del((LIST **)l_ptr, rem);
  
  *l_next = lnext;
}

void ListFree(LIST **qlist) {
    LIST *qptr = *qlist;
    
    while (qptr != NULL) {
        L_del_next((LIST **)qlist, (LIST *)qptr, (LIST **)&qptr);
    }
}

void L_link(LIST **list, LIST *ele) {
  l_link((LINK **)list, (LINK *)ele);
}