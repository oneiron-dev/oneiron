/**	@file midl.c
 *	@brief ldap bdb back-end ID List functions */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2021 The OpenLDAP Foundation.
 * Portions Copyright 2001-2021 Howard Chu, Symas Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include "midl.h"

/** @defgroup internal	LMDB Internals
 *	@{
 */
/** @defgroup idls	ID List Management
 *	@{
 */
#define CMP(x,y)	 ( (x) < (y) ? -1 : (x) > (y) )

unsigned mdb_midl_search( MDB_IDL ids, MDB_ID id )
{
	/*
	 * binary search of id in ids
	 * if found, returns position of id
	 * if not found, returns first position greater than id
	 */
	unsigned base = 0;
	unsigned cursor = 1;
	int val = 0;
	unsigned n = ids[0];

	while( 0 < n ) {
		unsigned pivot = n >> 1;
		cursor = base + pivot + 1;
		val = CMP( ids[cursor], id );

		if( val < 0 ) {
			n = pivot;

		} else if ( val > 0 ) {
			base = cursor;
			n -= pivot + 1;

		} else {
			return cursor;
		}
	}

	if( val > 0 ) {
		++cursor;
	}
	return cursor;
}

#if 0	/* superseded by append/sort */
int mdb_midl_insert( MDB_IDL ids, MDB_ID id )
{
	unsigned x, i;

	x = mdb_midl_search( ids, id );
	assert( x > 0 );

	if( x < 1 ) {
		/* internal error */
		return -2;
	}

	if ( x <= ids[0] && ids[x] == id ) {
		/* duplicate */
		assert(0);
		return -1;
	}

	if ( ++ids[0] >= MDB_IDL_DB_MAX ) {
		/* no room */
		--ids[0];
		return -2;

	} else {
		/* insert id */
		for (i=ids[0]; i>x; i--)
			ids[i] = ids[i-1];
		ids[x] = id;
	}

	return 0;
}
#endif

/* ONEIRON: heap-only physical owner; IDL[-1]/[0] remain capacity/count.
 * Growth borrows the CURRENT transaction account, never a cached context.
 */
typedef union MDB_IDL_buffer {
	MDB_ID alignment;
	struct {
		size_t bytes;
		void *ticket;
		MDB_page_release_func *release;
	} account;
} MDB_IDL_buffer;

static MDB_IDL
mdb_midl_new(MDB_ID num, const MDB_page_account *account)
{
	MDB_IDL_buffer *buffer;
	MDB_IDL ids;
	void *ticket = NULL;
	size_t bytes;
	if (num > ((size_t)-1 - sizeof(MDB_IDL_buffer)) / sizeof(MDB_ID) - 2)
		return NULL;
	bytes = sizeof(MDB_IDL_buffer) + (num + 2) * sizeof(MDB_ID);
	if (account && account->acquire &&
		account->acquire(account->context, bytes, &ticket))
		return NULL;
	buffer = malloc(bytes);
	if (!buffer) {
		if (account && account->release)
			account->release(ticket, bytes, 0);
		return NULL;
	}
	buffer->account.bytes = bytes;
	buffer->account.ticket = ticket;
	buffer->account.release = account ? account->release : NULL;
	if (account && account->materialized)
		account->materialized(ticket, bytes);
	ids = (MDB_IDL)(buffer + 1);
	*ids++ = num;
	*ids = 0;
	return ids;
}

MDB_IDL
mdb_midl_alloc_accounted(int num, const MDB_page_account *account)
{
	return num < 0 ? NULL : mdb_midl_new(num, account);
}

MDB_IDL mdb_midl_alloc(int num)
{
	return mdb_midl_alloc_accounted(num, NULL);
}

void mdb_midl_free(MDB_IDL ids)
{
	if (ids) {
		MDB_IDL_buffer *buffer = (MDB_IDL_buffer *)(ids - 1) - 1;
		size_t bytes = buffer->account.bytes;
		void *ticket = buffer->account.ticket;
		MDB_page_release_func *release = buffer->account.release;
		free(buffer);
		if (release)
			release(ticket, bytes, 1);
	}
}

static int
mdb_midl_resize(MDB_IDL *idp, MDB_ID num, const MDB_page_account *account)
{
	MDB_IDL old = *idp, ids = mdb_midl_new(num, account);
	MDB_IDL_buffer *buffer = (MDB_IDL_buffer *)(old - 1) - 1;
	size_t old_bytes = buffer->account.bytes - sizeof(MDB_IDL_buffer);
	size_t new_bytes;
	if (!ids)
		return ENOMEM;
	new_bytes = (num + 2) * sizeof(MDB_ID);
	/* Preserve all surviving payload bytes, including spare IDL slices. */
	memcpy(ids - 1, old - 1, old_bytes < new_bytes ? old_bytes : new_bytes);
	ids[-1] = num;
	*idp = ids;
	mdb_midl_free(old);
	return 0;
}

void
mdb_midl_shrink_accounted(MDB_IDL *idp, const MDB_page_account *account)
{
	if ((*idp)[-1] > MDB_IDL_UM_MAX)
		(void)mdb_midl_resize(idp, MDB_IDL_UM_MAX, account);
}

void mdb_midl_shrink(MDB_IDL *idp)
{
	mdb_midl_shrink_accounted(idp, NULL);
}

static int
mdb_midl_grow(MDB_IDL *idp, int num, const MDB_page_account *account)
{
	if (num < 0 || (MDB_ID)num > MDB_SIZE_MAX - (*idp)[-1])
		return ENOMEM;
	return mdb_midl_resize(idp, (*idp)[-1] + num, account);
}

int
mdb_midl_need_accounted(MDB_IDL *idp, unsigned num,
	const MDB_page_account *account)
{
	MDB_IDL ids = *idp;
	if (ids[0] > UINT_MAX - num)
		return ENOMEM;
	num += ids[0];
	if (num > ids[-1]) {
		if (num > UINT_MAX - num/4 - (256 + 2))
			return ENOMEM;
		num = (num + num/4 + (256 + 2)) & -256;
		return mdb_midl_resize(idp, num - 2, account);
	}
	return 0;
}

int mdb_midl_need(MDB_IDL *idp, unsigned num)
{
	return mdb_midl_need_accounted(idp, num, NULL);
}

int
mdb_midl_append_accounted(MDB_IDL *idp, MDB_ID id,
	const MDB_page_account *account)
{
	MDB_IDL ids = *idp;
	/* Too big? */
	if (ids[0] >= ids[-1]) {
		if (mdb_midl_grow(idp, MDB_IDL_UM_MAX, account))
			return ENOMEM;
		ids = *idp;
	}
	ids[0]++;
	ids[ids[0]] = id;
	return 0;
}

int mdb_midl_append(MDB_IDL *idp, MDB_ID id)
{
	return mdb_midl_append_accounted(idp, id, NULL);
}

int
mdb_midl_append_list_accounted(MDB_IDL *idp, MDB_IDL app,
	const MDB_page_account *account)
{
	MDB_IDL ids = *idp;
	/* Too big? */
	if (ids[0] + app[0] >= ids[-1]) {
		if (mdb_midl_grow(idp, app[0], account))
			return ENOMEM;
		ids = *idp;
	}
	memcpy(&ids[ids[0]+1], &app[1], app[0] * sizeof(MDB_ID));
	ids[0] += app[0];
	return 0;
}

int mdb_midl_append_list(MDB_IDL *idp, MDB_IDL app)
{
	return mdb_midl_append_list_accounted(idp, app, NULL);
}

int
mdb_midl_append_range_accounted(MDB_IDL *idp, MDB_ID id, unsigned n,
	const MDB_page_account *account)
{
	MDB_ID *ids = *idp, len = ids[0];
	/* Too big? */
	if (len + n > ids[-1]) {
		if (mdb_midl_grow(idp, n | MDB_IDL_UM_MAX, account))
			return ENOMEM;
		ids = *idp;
	}
	ids[0] = len + n;
	ids += len;
	while (n)
		ids[n--] = id++;
	return 0;
}

int mdb_midl_append_range(MDB_IDL *idp, MDB_ID id, unsigned n)
{
	return mdb_midl_append_range_accounted(idp, id, n, NULL);
}

void mdb_midl_xmerge( MDB_IDL idl, MDB_IDL merge )
{
	MDB_ID old_id, merge_id, i = merge[0], j = idl[0], k = i+j, total = k;
	idl[0] = (MDB_ID)-1;		/* delimiter for idl scan below */
	old_id = idl[j];
	while (i) {
		merge_id = merge[i--];
		for (; old_id < merge_id; old_id = idl[--j])
			idl[k--] = old_id;
		idl[k--] = merge_id;
	}
	idl[0] = total;
}

/* Quicksort + Insertion sort for small arrays */

#define SMALL	8
#define	MIDL_SWAP(a,b)	{ itmp=(a); (a)=(b); (b)=itmp; }

void
mdb_midl_sort( MDB_IDL ids )
{
	/* Max possible depth of int-indexed tree * 2 items/level */
	int istack[sizeof(int)*CHAR_BIT * 2];
	int i,j,k,l,ir,jstack;
	MDB_ID a, itmp;

	ir = (int)ids[0];
	l = 1;
	jstack = 0;
	for(;;) {
		if (ir - l < SMALL) {	/* Insertion sort */
			for (j=l+1;j<=ir;j++) {
				a = ids[j];
				for (i=j-1;i>=1;i--) {
					if (ids[i] >= a) break;
					ids[i+1] = ids[i];
				}
				ids[i+1] = a;
			}
			if (jstack == 0) break;
			ir = istack[jstack--];
			l = istack[jstack--];
		} else {
			k = (l + ir) >> 1;	/* Choose median of left, center, right */
			MIDL_SWAP(ids[k], ids[l+1]);
			if (ids[l] < ids[ir]) {
				MIDL_SWAP(ids[l], ids[ir]);
			}
			if (ids[l+1] < ids[ir]) {
				MIDL_SWAP(ids[l+1], ids[ir]);
			}
			if (ids[l] < ids[l+1]) {
				MIDL_SWAP(ids[l], ids[l+1]);
			}
			i = l+1;
			j = ir;
			a = ids[l+1];
			for(;;) {
				do i++; while(ids[i] > a);
				do j--; while(ids[j] < a);
				if (j < i) break;
				MIDL_SWAP(ids[i],ids[j]);
			}
			ids[l+1] = ids[j];
			ids[j] = a;
			jstack += 2;
			if (ir-i+1 >= j-l) {
				istack[jstack] = ir;
				istack[jstack-1] = i;
				ir = j-1;
			} else {
				istack[jstack] = j-1;
				istack[jstack-1] = l;
				l = i;
			}
		}
	}
}

unsigned mdb_mid2l_search( MDB_ID2L ids, MDB_ID id )
{
	/*
	 * binary search of id in ids
	 * if found, returns position of id
	 * if not found, returns first position greater than id
	 */
	unsigned base = 0;
	unsigned cursor = 1;
	int val = 0;
	unsigned n = (unsigned)ids[0].mid;

	while( 0 < n ) {
		unsigned pivot = n >> 1;
		cursor = base + pivot + 1;
		val = CMP( id, ids[cursor].mid );

		if( val < 0 ) {
			n = pivot;

		} else if ( val > 0 ) {
			base = cursor;
			n -= pivot + 1;

		} else {
			return cursor;
		}
	}

	if( val > 0 ) {
		++cursor;
	}
	return cursor;
}

int mdb_mid2l_insert( MDB_ID2L ids, MDB_ID2 *id )
{
	unsigned x, i;

	x = mdb_mid2l_search( ids, id->mid );

	if( x < 1 ) {
		/* internal error */
		return -2;
	}

	if ( x <= ids[0].mid && ids[x].mid == id->mid ) {
		/* duplicate */
		return -1;
	}

	if ( ids[0].mid >= MDB_IDL_UM_MAX ) {
		/* too big */
		return -2;

	} else {
		/* insert id */
		ids[0].mid++;
		for (i=(unsigned)ids[0].mid; i>x; i--)
			ids[i] = ids[i-1];
		ids[x] = *id;
	}

	return 0;
}

int mdb_mid2l_append( MDB_ID2L ids, MDB_ID2 *id )
{
	/* Too big? */
	if (ids[0].mid >= MDB_IDL_UM_MAX) {
		return -2;
	}
	ids[0].mid++;
	ids[ids[0].mid] = *id;
	return 0;
}

MDB_ID2L mdb_mid2l_alloc(int num)
{
	MDB_ID2L ids = malloc((num+2) * sizeof(MDB_ID2));
	if (ids) {
		ids->mid = num;
		ids++;
		ids->mid = 0;
	}
	return ids;
}

void mdb_mid2l_free(MDB_ID2L ids)
{
	if (ids)
		free(ids-1);
}

int mdb_mid2l_need( MDB_ID2L *idp, unsigned num )
{
	MDB_ID2L ids = *idp;
	num += ids[0].mid;
	if (num > ids[-1].mid) {
		num = (num + num/4 + (256 + 2)) & -256;
		if (!(ids = realloc(ids-1, num * sizeof(MDB_ID2))))
			return ENOMEM;
		ids[0].mid = num - 2;
		*idp = ids+1;
	}
	return 0;
}

#if MDB_RPAGE_CACHE
unsigned mdb_mid3l_search( MDB_ID3L ids, MDB_ID id )
{
	/*
	 * binary search of id in ids
	 * if found, returns position of id
	 * if not found, returns first position greater than id
	 */
	unsigned base = 0;
	unsigned cursor = 1;
	int val = 0;
	unsigned n = (unsigned)ids[0].mid;

	while( 0 < n ) {
		unsigned pivot = n >> 1;
		cursor = base + pivot + 1;
		val = CMP( id, ids[cursor].mid );

		if( val < 0 ) {
			n = pivot;

		} else if ( val > 0 ) {
			base = cursor;
			n -= pivot + 1;

		} else {
			return cursor;
		}
	}

	if( val > 0 ) {
		++cursor;
	}
	return cursor;
}

int mdb_mid3l_insert( MDB_ID3L ids, MDB_ID3 *id )
{
	unsigned x, i;

	x = mdb_mid3l_search( ids, id->mid );

	if( x < 1 ) {
		/* internal error */
		return -2;
	}

	if ( x <= ids[0].mid && ids[x].mid == id->mid ) {
		/* duplicate */
		return -1;
	}

	/* insert id */
	ids[0].mid++;
	for (i=(unsigned)ids[0].mid; i>x; i--)
		ids[i] = ids[i-1];
	ids[x] = *id;

	return 0;
}
#endif /* MDB_RPAGE_CACHE */

/** @} */
/** @} */
