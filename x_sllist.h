/* x_sllist.h */

#ifndef __X_SLLIST_H__
#define __X_SLLIST_H__

#include <sys/types.h>
#include <stdio.h>

#define x_sllist_struct_declare(_listname, _entrytype) \
struct _listname { \
	_entrytype *head; \
	_entrytype *tail; \
	int count; \
} _listname

#define x_sllist_struct_define(_listname, _entrytype) \
struct _listname { \
	_entrytype *head; \
	_entrytype *tail; \
	int count; \
}; \
extern struct _listname _listname

#define x_sllist_init(_list) \
do { \
	_list.head = NULL; \
	_list.tail = NULL; \
	_list.count = 0; \
} while(0)

#define x_sllist_static_init(_listname) \
struct _listname _listname = { .head = NULL, .tail = NULL, .count = 0, }

#define x_sllist_insert_head(_list, _entry) \
do { \
	_entry->next = NULL; \
	if (_list.head) { \
		_entry->next = _list.head; \
	} \
	if (!_list.tail) { \
		_list.tail = entry; \
	} \
	_list.head = entry; \
	_list.count++; \
} while(0)

#define x_sllist_insert_tail(_list, _entry) \
do { \
	_entry->next = NULL; \
	if (!_list.head) { \
		_list.head = _entry; \
	} \
	if (_list.tail) { \
		_list.tail->next = _entry; \
	} \
	_list.tail = _entry; \
	_list.count++; \
} while(0)

#define x_sllist_remove_head(_list) \
({ \
	typeof(_list.head) __entry = _list.head; \
	if (__entry) { \
		_list.head = __entry->next; \
		__entry->next = NULL; \
		if (_list.tail == __entry) { \
			_list.tail = NULL; \
		} \
		_list.count--; \
	} \
	__entry; \
})

#define x_sllist_remove_entry(_list, _entry) \
({ \
	typeof(_list.head) __iterator; \
	for ((__iterator) = _list.head; (__iterator); __iterator = (__iterator)->next) { \
		if (_list.head == _entry) { \
			_list.count--; \
			_list.head = _entry->next; \
			__iterator = _entry->next; \
			if (_entry->next == NULL) {\
				_list.tail = NULL; \
			} \
			break; \
		} \
		if (__iterator->next == _entry) { \
			_list.count--; \
			__iterator->next = _entry->next; \
			if (_entry->next == NULL) { \
				_list.tail = __iterator; \
			} \
			break; \
		} \
	} \
	__iterator; \
})

#define is_x_sllist_empty(_list) \
({ \
	int __res = 1; \
	if (_list.head) { \
		__res = 0; \
	} \
	__res; \
})

#endif //__X_SLLIST_H__
