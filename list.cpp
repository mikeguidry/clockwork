#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "list.h"


LIST *L_last(LIST *list) {
  while (list->next != NULL) {
    list = list->next;
  }
  
  return list;
}

int L_count(LIST *ele) {
  int count = 0;
  
  while (ele != NULL) {
    count++;
    ele = ele->next;
  }
  
  return count;
}

void L_link(LIST **list, LIST *ele) {
  ele->next = *list;
  
  *list = ele;
}

// order the linking (so its FIFO) instead of LIFO
void L_link_ordered(LIST **list, LIST *ele) {
  LIST *_last = NULL;
  
  if (*list == NULL) {
    *list = ele;
    return;
  }
  
  _last = L_last(*list);
  _last->next = ele;
}


LIST *L_add_0(LIST **list, int size, int ordered) {
  LIST *newptr;

  newptr = (LIST *)calloc(1,size);
  if (newptr == NULL) return NULL;

  if (!ordered) 
    L_link(list, newptr);
  else
    L_link_ordered(list, newptr);
  
  return newptr;
}


LIST *L_add(LIST **list, int size) {
  return L_add_0(list, size, 0);
}

LIST *L_add_ordered(LIST **list, int size) {
  return L_add_0(list, size, 1);
}


void L_del(LIST **l_ptr, LIST *rem) {
 if (rem->buf != NULL) {
    // later we should keep track of sizes.. so we can zero the memory
    free(rem->buf);
  }
  
  // close sock.. make this os independent for win32 , etc
  if (rem->fd > 0)
    close(rem->fd);
   
  while ((*l_ptr) != rem) {
    l_ptr = &(*l_ptr)->next;
  }
  
  *l_ptr = rem->next;
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

