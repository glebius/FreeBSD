/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2007, 2008 Kip Macy <kmacy@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/counter.h>
#include <sys/buf_ring.h>

struct buf_ring *
buf_ring_alloc(int count, struct malloc_type *type, int flags, lock_object_t lo)
{
	struct buf_ring *br;

	KASSERT(powerof2(count), ("buf ring must be size power of 2"));

	br = malloc(sizeof(struct buf_ring) + count * sizeof(void *),
	    type, flags | M_ZERO);
	if (br == NULL)
		return (NULL);
	br->br_drops = counter_u64_alloc(flags);
	if (br->br_drops == NULL) {
		free(br, type);
		return (NULL);
	}
	br->br_lock = lo.lo;
	br->br_malloc_type = type;
	br->br_prod_size = br->br_cons_size = count;
	br->br_prod_mask = br->br_cons_mask = count-1;
	br->br_prod_head = br->br_cons_head = 0;
	br->br_prod_tail = br->br_cons_tail = 0;
		
	return (br);
}

void
buf_ring_free(struct buf_ring *br, struct malloc_type *type)
{
	counter_u64_free(br->br_drops);
	free(br, type);
}

static void
buf_ring_free_delayed(epoch_context_t ctx)
{
	struct buf_ring *br = __containerof(ctx, struct buf_ring, br_epoch_ctx);
	void *ele;

	LOCK_CLASS(br->br_lock)->lc_lock(br->br_lock, 0);
	while ((ele = buf_ring_dequeue_sc(br)))
		br->br_epoch_free(ele);
	LOCK_CLASS(br->br_lock)->lc_unlock(br->br_lock);
	counter_u64_free(br->br_drops);
	free(br, br->br_malloc_type);
}

void
buf_ring_free_epoch(struct buf_ring *br, epoch_t epoch, br_epoch_free_t freefn)
{
	br->br_epoch_free = freefn;
	epoch_call(epoch, buf_ring_free_delayed, &br->br_epoch_ctx);
}
