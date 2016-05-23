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

LINK *l_add(LINK **list, int size) {
  LINK *cur, *newptr;

  newptr = (LINK *)malloc(size);
  memset(newptr, 0, size);

  if (*list != 0) {
    cur = (LINK *)l_last(*list);
    cur->next = newptr;
  } else
    *list = newptr;

  return newptr;
}

void l_del(LINK **l_ptr, LINK *rem) {
  LINK *cur = *l_ptr, *last;

  if (*l_ptr == rem) {
    if (cur->next != 0)
      *l_ptr = cur->next;
    else
      *l_ptr = 0;
  } else {
    while ((cur != rem) && (cur != 0)) {
      last = cur;
      cur = cur->next;
    }
      if (cur->next != 0)
        last->next = cur->next;
      else
        last->next = 0;
 }
 free(rem);
 
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


LIST *L_last(LIST *start) { return (LIST *)l_last((LINK *)start); }

LIST *L_add(LIST **list, int size) {
  LIST *ret = (LIST *)l_add((LINK **)list, size);
  if (ret) {
    ret->start_ts = time(0);
  } 
  return ret;
}

int L_count(LIST *l_ptr) { return l_count((LINK *)l_ptr); }
void L_del(LIST **l_ptr, LIST *rem) {
  if (rem->buf != NULL) free(rem->buf);
  
  // close sock.. make this os independent for win32 , etc
  if (rem->fd > 0) close(rem->fd);
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
