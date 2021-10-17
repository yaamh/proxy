#ifndef __LIST_H__
#define __LIST_H__

typedef struct _list_node
{
    struct _list_node *prev,*next;
}list_node;


static inline void list_init(list_node *head)
{
    head->next = head;
    head->prev = head;
}

static inline int list_empty(list_node *head)
{
    return ((head->prev == head)&&(head->next == head));
}

static inline void list_add(list_node *prev, list_node *next,list_node *new)
{
    prev->next = new;
    new->prev = prev;
    new->next = next;
    next->prev = new;
}

static inline void list_add_prev(list_node *node, list_node *new)
{
    list_add(node->prev,node,new);
}

static inline void list_add_next(list_node *node, list_node *new)
{
    list_add(node,node->next,new);
}

static inline void list_del(list_node *node)
{
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->next = node->prev = node;
}

#define LIST_HEAD_INIT(head) {&(head),&(head)}
#define LIST_HEAD(head) list_node head = LIST_HEAD_INIT(head);
#define list_next(node) ((node)->next)
#define list_prev(node) ((node)->prev)
#define list_entry(ptr, type, member) ((type*)((char*)ptr - (char*)&(((type*)0)->member)))
#define list_foreach(pos,head) for(pos=(head)->next;pos!=head;pos=pos->next)
#define list_foreach_resv(pos,head) for(pos=(head)->prev;pos!=head;pos=pos->prev)
#define list_foreach_safe(pos,n,head) for(pos=(head)->next,n=pos->next;pos!=head;pos=n,n=pos->next)


#endif
