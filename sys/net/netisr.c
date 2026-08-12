/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2007-2009 Robert N. M. Watson
 * Copyright (c) 2010-2011 Juniper Networks, Inc.
 * All rights reserved.
 *
 * This software was developed by Robert N. M. Watson under contract
 * to Juniper Networks, Inc.
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

#include <sys/cdefs.h>
/*
 * netisr is a packet dispatch service, allowing synchronous (directly
 * dispatched) and asynchronous (deferred dispatch) processing of packets by
 * registered protocol handlers.  Callers pass a protocol identifier and
 * packet to netisr, along with a direct dispatch hint, and work will either
 * be immediately processed by the registered handler, or passed to a
 * software interrupt (SWI) thread for deferred dispatch.  Callers will
 * generally select one or the other based on:
 *
 * - Whether directly dispatching a netisr handler lead to code reentrance or
 *   lock recursion, such as entering the socket code from the socket code.
 * - Whether directly dispatching a netisr handler lead to recursive
 *   processing, such as when decapsulating several wrapped layers of tunnel
 *   information (IPSEC within IPSEC within ...).
 *
 * Maintaining ordering for protocol streams is a critical design concern.
 * Enforcing ordering limits the opportunity for concurrency, but maintains
 * the strong ordering requirements found in some protocols, such as TCP.  Of
 * related concern is CPU affinity--it is desirable to process all data
 * associated with a particular stream on the same CPU over time in order to
 * avoid acquiring locks associated with the connection on different CPUs,
 * keep connection data in one cache, and to generally encourage associated
 * user threads to live on the same CPU as the stream.  It's also desirable
 * to avoid lock migration and contention where locks are associated with
 * more than one flow.
 *
 * netisr supports several policy variations, represented by the
 * NETISR_POLICY_* constants, allowing protocols to play various roles in
 * identifying flows, assigning work to CPUs, etc.  These are described in
 * netisr.h.
 */

#include "opt_device_polling.h"

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/malloc.h>
#include <sys/interrupt.h>
#include <sys/lock.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/rmlock.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_private.h>
#include <net/netisr.h>
#include <net/vnet.h>

/*
 * Each protocol is described by a struct netisr_proto, which holds all
 * global per-protocol information.  This data structure is set up by
 * netisr_register(), and derived from the public struct netisr_handler.
 */
struct netisr_proto {
	const char	*np_name;	/* Character string protocol name. */
	netisr_handler_t *np_handler;	/* Protocol handler. */
	netisr_m2flow_t	*np_m2flow;	/* Query flow for untagged packet. */
	netisr_m2cpuid_t *np_m2cpuid;	/* Query CPU to process packet on. */
	netisr_drainedcpu_t *np_drainedcpu; /* Callback when drained a queue. */
	u_int		 np_qlimit;	/* Maximum per-CPU queue depth. */
	u_int		 np_policy;	/* Work placement policy. */
	u_int		 np_dispatch;	/* Work dispatch policy. */
};

/*
 * Workstreams hold a queue of ordered work across each protocol, and are
 * described by netisr_workstream.  Each workstream is associated with a
 * worker thread, which in turn is pinned to a CPU.  Work associated with a
 * workstream can be processd in other threads during direct dispatch;
 * concurrent processing is prevented by the NWS_RUNNING flag, which
 * indicates that a thread is already processing the work queue.  It is
 * important to prevent a directly dispatched packet from "skipping ahead" of
 * work already in the workstream queue.
 */
#define	NETISR_MAXPROT	16		/* Compile-time limit. */
struct netisr_workstream {
	struct intr_event *nws_intr_event;	/* Handler for stream. */
	void		*nws_swi_cookie;	/* swi(9) cookie for stream. */
	struct mtx	 nws_mtx;		/* Synchronize work. */
	u_int		 nws_cpu;		/* CPU pinning. */
	enum __attribute__((flag_enum)) {
		NWS_RUNNING	= 0x00000001,	/* running in a thread */
		NWS_DISPATCHING	= 0x00000002,	/* being direct-dispatched */
		NWS_SCHEDULED	= 0x00000004,	/* Signal issued. */
	} nws_flags;
	u_int		 nws_pendingbits;	/* Scheduled protocols. */

	/*
	 * Protocol-specific work for each workstream is described by struct
	 * netisr_work.  Each work descriptor consists of an mbuf queue and
	 * statistics.
	 */
	struct netisr_work {
		struct buf_ring *nw_br;
		u_int		 nw_watermark;

		counter_u64_t nw_dispatched; /* Number of direct dispatches. */
		counter_u64_t nw_hybrid_dispatched; /* "" hybrid dispatches. */
		counter_u64_t nw_queued;	/* "" enqueues. */
		counter_u64_t nw_handled;	/* "" handled in worker. */
	} nws_work[NETISR_MAXPROT];
} __aligned(CACHE_LINE_SIZE);

static MALLOC_DEFINE(M_NETISR, "netisr", "netisr(9) work streams");

/*-
 * Synchronize use and modification of the registered netisr data structures;
 * acquire a read lock while modifying the set of registered protocols to
 * prevent partially registered or unregistered protocols from being run.
 *
 * The following data structures and fields are protected by this lock:
 *
 * - The netisr_proto array, including all fields of struct netisr_proto.
 * - The nws array, including all fields of struct netisr_worker.
 * - The nws_array array.
 */
static struct sx netisr_lock;
#define	NETISR_WLOCK()		sx_xlock(&netisr_lock)
#define	NETISR_WUNLOCK()	sx_xunlock(&netisr_lock)

static SYSCTL_NODE(_net, OID_AUTO, isr, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "netisr");

/*-
 * Three global direct dispatch policies are supported:
 *
 * NETISR_DISPATCH_DEFERRED: All work is deferred for a netisr, regardless of
 * context (may be overridden by protocols).
 *
 * NETISR_DISPATCH_HYBRID: If the executing context allows direct dispatch,
 * and we're running on the CPU the work would be performed on, then direct
 * dispatch it if it wouldn't violate ordering constraints on the workstream.
 *
 * NETISR_DISPATCH_DIRECT: If the executing context allows direct dispatch,
 * always direct dispatch.  (The default.)
 *
 * Notice that changing the global policy could lead to short periods of
 * misordered processing, but this is considered acceptable as compared to
 * the complexity of enforcing ordering during policy changes.  Protocols can
 * override the global policy (when they're not doing that, they select
 * NETISR_DISPATCH_DEFAULT).
 */
#define	NETISR_DISPATCH_POLICY_DEFAULT	NETISR_DISPATCH_DIRECT
#define	NETISR_DISPATCH_POLICY_MAXSTR	20 /* Used for temporary buffers. */
static u_int	netisr_dispatch_policy = NETISR_DISPATCH_POLICY_DEFAULT;
static int	sysctl_netisr_dispatch_policy(SYSCTL_HANDLER_ARGS);
SYSCTL_PROC(_net_isr, OID_AUTO, dispatch,
    CTLTYPE_STRING | CTLFLAG_RWTUN | CTLFLAG_NEEDGIANT,
    0, 0, sysctl_netisr_dispatch_policy, "A",
    "netisr dispatch policy");

/*
 * Allow the administrator to limit the number of threads (CPUs) to use for
 * netisr.  We don't check netisr_maxthreads before creating the thread for
 * CPU 0. This must be set at boot. We will create at most one thread per CPU.
 * By default we initialize this to 1 which would assign just 1 cpu (cpu0) and
 * therefore only 1 workstream. If set to -1, netisr would use all cpus
 * (mp_ncpus) and therefore would have those many workstreams. One workstream
 * per thread (CPU).
 */
static int	netisr_maxthreads = 1;		/* Max number of threads. */
SYSCTL_INT(_net_isr, OID_AUTO, maxthreads, CTLFLAG_RDTUN,
    &netisr_maxthreads, 0,
    "Use at most this many CPUs for netisr processing");

static int	netisr_bindthreads = 0;		/* Bind threads to CPUs. */
SYSCTL_INT(_net_isr, OID_AUTO, bindthreads, CTLFLAG_RDTUN,
    &netisr_bindthreads, 0, "Bind netisr threads to CPUs.");

/*
 * Limit per-workstream mbuf queue limits s to at most net.isr.maxqlimit,
 * both for initial configuration and later modification using
 * netisr_setqlimit().
 */
#define	NETISR_DEFAULT_MAXQLIMIT	10240
static u_int	netisr_maxqlimit = NETISR_DEFAULT_MAXQLIMIT;
SYSCTL_UINT(_net_isr, OID_AUTO, maxqlimit, CTLFLAG_RDTUN,
    &netisr_maxqlimit, 0,
    "Maximum netisr per-protocol, per-CPU queue depth.");

/*
 * The default per-workstream mbuf queue limit for protocols that don't
 * initialize the nh_qlimit field of their struct netisr_handler.  If this is
 * set above netisr_maxqlimit, we truncate it to the maximum during boot.
 */
#define	NETISR_DEFAULT_DEFAULTQLIMIT	256
static u_int	netisr_defaultqlimit = NETISR_DEFAULT_DEFAULTQLIMIT;
SYSCTL_UINT(_net_isr, OID_AUTO, defaultqlimit, CTLFLAG_RDTUN,
    &netisr_defaultqlimit, 0,
    "Default netisr per-protocol, per-CPU queue limit if not set by protocol");

/*
 * Store and export the compile-time constant NETISR_MAXPROT limit on the
 * number of protocols that can register with netisr at a time.  This is
 * required for crashdump analysis, as it sizes netisr_proto[].
 */
static u_int	netisr_maxprot = NETISR_MAXPROT;
SYSCTL_UINT(_net_isr, OID_AUTO, maxprot, CTLFLAG_RD,
    &netisr_maxprot, 0,
    "Compile-time limit on the number of protocols supported by netisr.");

/*
 * The netisr_proto array describes all registered protocols, indexed by
 * protocol number.
 */
static struct netisr_proto	netisr_proto[NETISR_MAXPROT];

/*
 * The array is populated up to net.isr.numthreads / nws_count.
 * A workstream can be picked up with curcpu % nws_count and once number of
 * workstreams reaches mp_ncpus, this basically means curcpu is used as
 * index.  Note that without thread binding enabled, the workstreams don't
 * really belong to CPUs.
 */
static struct netisr_workstream	*nws_array[MAXCPU];

/*
 * Number of registered workstreams.  Will be at most the number of running
 * CPUs once fully started.
 */
static u_int				 nws_count;
SYSCTL_UINT(_net_isr, OID_AUTO, numthreads, CTLFLAG_RD,
    &nws_count, 0, "Number of extant netisr threads.");

/*
 * Synchronization for each workstream: a mutex protects all mutable fields
 * in each stream, including per-protocol state (mbuf queues).  The SWI is
 * woken up if asynchronous dispatch is required.
 */
#define	NWS_LOCK(s)		mtx_lock(&(s)->nws_mtx)
#define	NWS_LOCK_ASSERT(s)	mtx_assert(&(s)->nws_mtx, MA_OWNED)
#define	NWS_UNLOCK(s)		mtx_unlock(&(s)->nws_mtx)
#define	NWS_SIGNAL(s)		swi_sched((s)->nws_swi_cookie, 0)

/*
 * Dispatch tunable and sysctl configuration.
 */
struct netisr_dispatch_table_entry {
	u_int		 ndte_policy;
	const char	*ndte_policy_str;
};
static const struct netisr_dispatch_table_entry netisr_dispatch_table[] = {
	{ NETISR_DISPATCH_DEFAULT, "default" },
	{ NETISR_DISPATCH_DEFERRED, "deferred" },
	{ NETISR_DISPATCH_HYBRID, "hybrid" },
	{ NETISR_DISPATCH_DIRECT, "direct" },
};

static void
netisr_dispatch_policy_to_str(u_int dispatch_policy, char *buffer,
    u_int buflen)
{
	const struct netisr_dispatch_table_entry *ndtep;
	const char *str;
	u_int i;

	str = "unknown";
	for (i = 0; i < nitems(netisr_dispatch_table); i++) {
		ndtep = &netisr_dispatch_table[i];
		if (ndtep->ndte_policy == dispatch_policy) {
			str = ndtep->ndte_policy_str;
			break;
		}
	}
	snprintf(buffer, buflen, "%s", str);
}

static int
netisr_dispatch_policy_from_str(const char *str, u_int *dispatch_policyp)
{
	const struct netisr_dispatch_table_entry *ndtep;
	u_int i;

	for (i = 0; i < nitems(netisr_dispatch_table); i++) {
		ndtep = &netisr_dispatch_table[i];
		if (strcmp(ndtep->ndte_policy_str, str) == 0) {
			*dispatch_policyp = ndtep->ndte_policy;
			return (0);
		}
	}
	return (EINVAL);
}

static int
sysctl_netisr_dispatch_policy(SYSCTL_HANDLER_ARGS)
{
	char tmp[NETISR_DISPATCH_POLICY_MAXSTR];
	size_t len;
	u_int dispatch_policy;
	int error;

	netisr_dispatch_policy_to_str(netisr_dispatch_policy, tmp,
	    sizeof(tmp));
	/*
	 * netisr is initialised very early during the boot when malloc isn't
	 * available yet so we can't use sysctl_handle_string() to process
	 * any non-default value that was potentially set via loader.
	 */
	if (req->newptr != NULL) {
		len = req->newlen - req->newidx;
		if (len >= NETISR_DISPATCH_POLICY_MAXSTR)
			return (EINVAL);
		error = SYSCTL_IN(req, tmp, len);
		if (error == 0) {
			tmp[len] = '\0';
			error = netisr_dispatch_policy_from_str(tmp,
			    &dispatch_policy);
			if (error == 0 &&
			    dispatch_policy == NETISR_DISPATCH_DEFAULT)
				error = EINVAL;
			if (error == 0)
				netisr_dispatch_policy = dispatch_policy;
		}
	} else {
		error = sysctl_handle_string(oidp, tmp, sizeof(tmp), req);
	}
	return (error);
}

/*
 * Register a new netisr handler, which requires initializing per-protocol
 * fields for each workstream.  All netisr work is briefly suspended while
 * the protocol is installed.
 */
void
netisr_register(const struct netisr_handler *nhp)
{
	const char *name;
	u_int proto;

	proto = nhp->nh_proto;
	name = nhp->nh_name;

	/*
	 * Test that the requested registration is valid.
	 */
	CURVNET_ASSERT_SET();
	MPASS(IS_DEFAULT_VNET(curvnet));
	KASSERT(nhp->nh_name != NULL,
	    ("%s: nh_name NULL for %u", __func__, proto));
	KASSERT(nhp->nh_handler != NULL,
	    ("%s: nh_handler NULL for %s", __func__, name));
	KASSERT(nhp->nh_policy == NETISR_POLICY_FLOW ||
	    nhp->nh_m2flow == NULL,
	    ("%s: nh_policy != FLOW but m2flow defined for %s", __func__,
	    name));
	KASSERT(nhp->nh_policy == NETISR_POLICY_CPU || nhp->nh_m2cpuid == NULL,
	    ("%s: nh_policy != CPU but m2cpuid defined for %s", __func__,
	    name));
	KASSERT(nhp->nh_policy != NETISR_POLICY_CPU || nhp->nh_m2cpuid != NULL,
	    ("%s: nh_policy == CPU but m2cpuid not defined for %s", __func__,
	    name));

	KASSERT(proto < NETISR_MAXPROT,
	    ("%s(%u, %s): protocol too big", __func__, proto, name));

	/*
	 * Test that no existing registration exists for this protocol.
	 */
	NETISR_WLOCK();
	KASSERT(netisr_proto[proto].np_name == NULL,
	    ("%s(%u, %s): name present", __func__, proto, name));
	KASSERT(netisr_proto[proto].np_handler == NULL,
	    ("%s(%u, %s): handler present", __func__, proto, name));

	netisr_proto[proto].np_name = name;
	netisr_proto[proto].np_handler = nhp->nh_handler;
	netisr_proto[proto].np_m2flow = nhp->nh_m2flow;
	netisr_proto[proto].np_m2cpuid = nhp->nh_m2cpuid;
	netisr_proto[proto].np_drainedcpu = nhp->nh_drainedcpu;
	if (nhp->nh_qlimit == 0)
		netisr_proto[proto].np_qlimit = netisr_defaultqlimit;
	else if (nhp->nh_qlimit > netisr_maxqlimit) {
		printf("%s: %s requested queue limit %u capped to "
		    "net.isr.maxqlimit %u\n", __func__, name, nhp->nh_qlimit,
		    netisr_maxqlimit);
		netisr_proto[proto].np_qlimit = netisr_maxqlimit;
	} else
		netisr_proto[proto].np_qlimit = nhp->nh_qlimit;
	netisr_proto[proto].np_policy = nhp->nh_policy;
	netisr_proto[proto].np_dispatch = nhp->nh_dispatch;
	for (u_int i = 0; i < nws_count; i++) {
		struct netisr_workstream *nws = nws_array[i];
		struct netisr_work *nw = &nws->nws_work[proto];

		nw->nw_br = buf_ring_alloc(netisr_proto[proto].np_qlimit,
		    M_NETISR, M_WAITOK, &nws->nws_mtx);
		nw->nw_dispatched = counter_u64_alloc(M_WAITOK);
		nw->nw_hybrid_dispatched = counter_u64_alloc(M_WAITOK);
		nw->nw_queued = counter_u64_alloc(M_WAITOK);
		nw->nw_handled = counter_u64_alloc(M_WAITOK);
	}
	NETISR_WUNLOCK();
}

/*
 * Clear drop counters across all workstreams for a protocol.
 */
void
netisr_clearqdrops(const struct netisr_handler *nhp)
{
	u_int proto = nhp->nh_proto;

	KASSERT(proto < NETISR_MAXPROT,
	    ("%s(%u): protocol too big for %s", __func__, proto, nhp->nh_name));

	NETISR_WLOCK();
	KASSERT(netisr_proto[proto].np_handler != NULL,
	    ("%s(%u): protocol not registered for %s", __func__, proto,
	    nhp->nh_name));

	for (u_int i = 0; i < nws_count; i++)
		counter_u64_zero(nws_array[i]->nws_work[proto].nw_br->br_drops);
	NETISR_WUNLOCK();
}

/*
 * Query current drop counters across all workstreams for a protocol.
 */
void
netisr_getqdrops(const struct netisr_handler *nhp, uint64_t *qdropp)
{
	u_int proto = nhp->nh_proto;

	KASSERT(proto < NETISR_MAXPROT,
	    ("%s(%u): protocol too big for %s", __func__, proto, nhp->nh_name));

	KASSERT(netisr_proto[proto].np_handler != NULL,
	    ("%s(%u): protocol not registered for %s", __func__, proto,
	    nhp->nh_name));

	*qdropp = 0;
	for (u_int i = 0; i < nws_count; i++)
		*qdropp +=
		    buf_ring_drops(nws_array[i]->nws_work[proto].nw_br);
}

/*
 * Query current per-workstream queue limit for a protocol.
 */
void
netisr_getqlimit(const struct netisr_handler *nhp, u_int *qlimitp)
{
	u_int proto = nhp->nh_proto;

	KASSERT(proto < NETISR_MAXPROT,
	    ("%s(%u): protocol too big for %s", __func__, proto, nhp->nh_name));

	KASSERT(netisr_proto[proto].np_handler != NULL,
	    ("%s(%u): protocol not registered for %s", __func__, proto,
	    nhp->nh_name));
	*qlimitp = netisr_proto[proto].np_qlimit;
}

/*
 * Update the queue limit across per-workstream queues for a protocol.
 * This requires re-allocating the buf_ring(9)s.  Packets are moved from old
 * ring to new.  There is a risk of reordeing and packet loss, we just try our
 * best effort.
 */
int
netisr_setqlimit(const struct netisr_handler *nhp, u_int qlimit)
{
	u_int proto = nhp->nh_proto;

	KASSERT(proto < NETISR_MAXPROT,
	    ("%s(%u): protocol too big for %s", __func__, proto, nhp->nh_name));

	if (qlimit > netisr_maxqlimit)
		return (EINVAL);

	NETISR_WLOCK();
	KASSERT(netisr_proto[proto].np_handler != NULL,
	    ("%s(%u): protocol not registered for %s", __func__, proto,
	    nhp->nh_name));

	netisr_proto[proto].np_qlimit = qlimit;
	for (u_int i = 0; i < nws_count; i++) {
		struct netisr_workstream *nws = nws_array[i];
		struct netisr_work *nw = &nws->nws_work[proto];
		struct buf_ring *new, *old;
		void *m;

		new = buf_ring_alloc(qlimit, M_NETISR, M_WAITOK, &nws->nws_mtx);
		NWS_LOCK(nws);
		old = nw->nw_br;
		nw->nw_br = new;
		while ((m = buf_ring_dequeue_sc(old)))
			(void)buf_ring_enqueue(new, m);
		NWS_UNLOCK(nws);
		buf_ring_free_epoch(old, net_epoch_preempt,
		    (br_epoch_free_t *)m_freem);
	}
	NETISR_WUNLOCK();

	return (0);
}

/*
 * Remove the registration of a network protocol, which requires clearing
 * per-protocol fields across all workstreams, including freeing all mbufs in
 * the queues at time of unregister.  All work in netisr is briefly suspended
 * while this takes place.
 */
void
netisr_unregister(const struct netisr_handler *nhp)
{
	u_int proto = nhp->nh_proto;

	KASSERT(proto < NETISR_MAXPROT,
	    ("%s(%u): protocol too big for %s", __func__, proto, nhp->nh_name));

	NETISR_WLOCK();
	KASSERT(netisr_proto[proto].np_handler != NULL,
	    ("%s(%u): protocol not registered for %s", __func__, proto,
	    nhp->nh_name));

	netisr_proto[proto].np_name = NULL;
	netisr_proto[proto].np_handler = NULL;
	netisr_proto[proto].np_m2flow = NULL;
	netisr_proto[proto].np_m2cpuid = NULL;
	netisr_proto[proto].np_qlimit = 0;
	netisr_proto[proto].np_policy = 0;
	for (u_int i = 0; i < nws_count; i++) {
		struct netisr_workstream *nws = nws_array[i];
		struct netisr_work *nw = &nws->nws_work[proto];
		struct buf_ring *br;
		struct mbuf *m;

		br = nw->nw_br;
		nw->nw_br = NULL;
		NWS_LOCK(nws);
		while ((m = buf_ring_dequeue_sc(br)))
			m_freem(m);
		NWS_UNLOCK(nws);
		buf_ring_free_epoch(br, net_epoch_preempt,
		    (br_epoch_free_t *)m_freem);
		counter_u64_free(nw->nw_dispatched);
		counter_u64_free(nw->nw_hybrid_dispatched);
		counter_u64_free(nw->nw_queued);
		counter_u64_free(nw->nw_handled);
	}
	NETISR_WUNLOCK();
}

/*
 * Compose the global and per-protocol policies on dispatch, and return the
 * dispatch policy to use.
 */
static u_int
netisr_get_dispatch(struct netisr_proto *npp)
{

	/*
	 * Protocol-specific configuration overrides the global default.
	 */
	if (npp->np_dispatch != NETISR_DISPATCH_DEFAULT)
		return (npp->np_dispatch);
	return (netisr_dispatch_policy);
}

/*
 * Look up the workstream given a packet and source identifier.  Do this by
 * checking the protocol's policy, and optionally call out to the protocol
 * for assistance if required.
 */
static struct mbuf *
netisr_select_nws(struct netisr_proto *npp, u_int dispatch_policy,
    uintptr_t source, struct mbuf *m, u_int *nws_id)
{
	struct ifnet *ifp;
	u_int policy;

	/*
	 * In the event we have only one worker, shortcut and deliver to it
	 * without further ado.
	 */
	if (nws_count == 1) {
		*nws_id = 0;
		return (m);
	}

	/*
	 * What happens next depends on the policy selected by the protocol.
	 * If we want to support per-interface policies, we should do that
	 * here first.
	 */
	policy = npp->np_policy;
	if (policy == NETISR_POLICY_CPU) {
		m = npp->np_m2cpuid(m, source, nws_id);
		if (m == NULL)
			return (NULL);

		/*
		 * It's possible for a protocol not to have a good idea about
		 * where to process a packet, in which case we fall back on
		 * the netisr code to decide.  In the hybrid case, return the
		 * current CPU ID, which will force an immediate direct
		 * dispatch.  In the queued case, fall back on the SOURCE
		 * policy.
		 */
		if (*nws_id != NETISR_CPUID_NONE) {
			*nws_id = *nws_id % nws_count;
			return (m);
		}
		if (dispatch_policy == NETISR_DISPATCH_HYBRID) {
			*nws_id = curcpu % nws_count;
			return (m);
		}
		policy = NETISR_POLICY_SOURCE;
	}

	if (policy == NETISR_POLICY_FLOW) {
		if (M_HASHTYPE_GET(m) == M_HASHTYPE_NONE &&
		    npp->np_m2flow != NULL) {
			m = npp->np_m2flow(m, source);
			if (m == NULL)
				return (NULL);
		}
		if (M_HASHTYPE_GET(m) != M_HASHTYPE_NONE) {
			*nws_id = m->m_pkthdr.flowid % nws_count;
			return (m);
		}
		policy = NETISR_POLICY_SOURCE;
	}

	KASSERT(policy == NETISR_POLICY_SOURCE,
	    ("%s: invalid policy %u for %s", __func__, npp->np_policy,
	    npp->np_name));

	MPASS((m->m_pkthdr.csum_flags & CSUM_SND_TAG) == 0);
	ifp = m->m_pkthdr.rcvif;
	if (ifp != NULL)
		*nws_id = (ifp->if_index + source) % nws_count;
	else
		*nws_id = source % nws_count;
	return (m);
}

/*
 * SWI handler for netisr -- processes packets in a set of workstreams that
 * it owns, woken up by calls to NWS_SIGNAL().  If this workstream is already
 * being direct dispatched, go back to sleep and wait for the dispatching
 * thread to wake us up again.
 */
static void
swi_net(void *arg)
{
	struct netisr_workstream *nws = arg;
	u_int proto;

#ifdef DEVICE_POLLING
	KASSERT(nws_count == 1,
	    ("%s: device_polling but nws_count != 1", __func__));
	netisr_poll();
#endif
	NWS_LOCK(nws);
	for (proto = 0; proto < NETISR_MAXPROT; proto++) {
		struct netisr_proto *np = &netisr_proto[proto];
		struct netisr_work *nw = &nws->nws_work[proto];
		struct mbuf *m;
		u_int handled;

		if (np->np_name == NULL)
			continue;

		/* Lazily update the watermark. */
		if (nw->nw_watermark < netisr_proto[proto].np_qlimit) {
			u_int wmark;

			wmark = buf_ring_count(nw->nw_br);
			if (wmark > nw->nw_watermark)
				nw->nw_watermark = wmark;
		}

		handled = 0;
		/*
		 * As we are processing the queue, more may be enqueued.  To
		 * avoid live lock by a single protocol limit to np_qlimit
		 * packets at one run.
		 */
		while ((m = buf_ring_dequeue_sc(nw->nw_br))) {
			if (__predict_false(m_rcvif_restore(m) == NULL)) {
				m_freem(m);
				continue;
			}
			handled++;
			CURVNET_SET(m->m_pkthdr.rcvif->if_vnet);
			netisr_proto[proto].np_handler(m);
			CURVNET_RESTORE();
			if (handled >= np->np_qlimit)
				break;
		}
		if (netisr_proto[proto].np_drainedcpu)
			netisr_proto[proto].np_drainedcpu(nws->nws_cpu);
		counter_u64_add(nw->nw_handled, handled);
	}
	NWS_UNLOCK(nws);
#ifdef DEVICE_POLLING
	netisr_pollmore();
#endif
}

static int
netisr_queue_internal(u_int proto, struct mbuf *m, u_int nws_id)
{
	struct netisr_workstream *nws = nws_array[nws_id];
	struct netisr_work *nw = &nws->nws_work[proto];
	int error;

	m_rcvif_serialize(m);
	error = buf_ring_enqueue_empty(nw->nw_br, m);
	if (__predict_false(error < 0)) {
		m_freem(m);
		return (-error);
	}
	counter_u64_add(nw->nw_queued, 1);
	if (error > 0) {
		/* Ring was empty. */
		NWS_SIGNAL(nws);
		error = 0;
	}

	return (error);
}

int
netisr_queue_src(u_int proto, uintptr_t source, struct mbuf *m)
{
	u_int nws_id;
	int error;

	KASSERT(proto < NETISR_MAXPROT,
	    ("%s: invalid proto %u", __func__, proto));

	KASSERT(netisr_proto[proto].np_handler != NULL,
	    ("%s: invalid proto %u", __func__, proto));

	m = netisr_select_nws(&netisr_proto[proto], NETISR_DISPATCH_DEFERRED,
	    source, m, &nws_id);
	if (m != NULL) {
		VNET_ASSERT(m->m_pkthdr.rcvif != NULL,
		    ("%s:%d rcvif == NULL: m=%p", __func__, __LINE__, m));
		error = netisr_queue_internal(proto, m, nws_id);
	} else
		error = ENOBUFS;
	return (error);
}

int
netisr_queue(u_int proto, struct mbuf *m)
{

	return (netisr_queue_src(proto, 0, m));
}

/*
 * Dispatch a packet for netisr processing; direct dispatch is permitted by
 * calling context.
 */
int
netisr_dispatch_src(u_int proto, uintptr_t source, struct mbuf *m)
{
	struct netisr_proto *npp;
	u_int nws_id, dispatch_policy;
	int error;

	NET_EPOCH_ASSERT();
	KASSERT(proto < NETISR_MAXPROT,
	    ("%s: invalid proto %u", __func__, proto));
	npp = &netisr_proto[proto];
	KASSERT(npp->np_handler != NULL, ("%s: invalid proto %u", __func__,
	    proto));

	dispatch_policy = netisr_get_dispatch(npp);
	if (dispatch_policy == NETISR_DISPATCH_DEFERRED)
		return (netisr_queue_src(proto, source, m));

	/*
	 * If direct dispatch is forced, then unconditionally dispatch
	 * without a formal CPU selection.  Borrow the current CPU's stats,
	 * without pinning, though.  In this case we don't update nws_flags
	 * because all netisr processing will be source ordered due to always
	 * being forced to directly dispatch.
	 */
	if (dispatch_policy == NETISR_DISPATCH_DIRECT) {
		struct netisr_work *nw =
		    &nws_array[curcpu % nws_count]->nws_work[proto];

		counter_u64_add(nw->nw_dispatched, 1);
		counter_u64_add(nw->nw_handled, 1);
		netisr_proto[proto].np_handler(m);

		return (0);
	}

	KASSERT(dispatch_policy == NETISR_DISPATCH_HYBRID,
	    ("%s: unknown dispatch policy (%u)", __func__, dispatch_policy));

	/*
	 * Otherwise, we execute in a hybrid mode where we will try to direct
	 * dispatch if we're on the right CPU.
	 */
	sched_pin();
	m = netisr_select_nws(&netisr_proto[proto], NETISR_DISPATCH_HYBRID,
	    source, m, &nws_id);
	if (m == NULL) {
		sched_unpin();
		return (ENOBUFS);
	}
	if (netisr_bindthreads && nws_id != curcpu % nws_count) {
		error = netisr_queue_internal(proto, m, nws_id);
	} else {
		struct netisr_work *nw = &nws_array[nws_id]->nws_work[proto];

		counter_u64_add(nw->nw_hybrid_dispatched, 1);
		counter_u64_add(nw->nw_handled, 1);
		netisr_proto[proto].np_handler(m);
		error = 0;
	}
	sched_unpin();

	return (error);
}

int
netisr_dispatch(u_int proto, struct mbuf *m)
{

	return (netisr_dispatch_src(proto, 0, m));
}

#ifdef DEVICE_POLLING
/*
 * Kernel polling borrows a netisr thread to run interface polling in; this
 * function allows kernel polling to request that the netisr thread be
 * scheduled even if no packets are pending for protocols.
 */
void
netisr_sched_poll(void)
{
	struct netisr_workstream *nwsp;

	nwsp = nws_array[0];
	NWS_SIGNAL(nwsp);
}
#endif

static void
netisr_start_swi(u_int cpuid, struct pcpu *pc)
{
	char swiname[12];
	struct netisr_workstream *nws;
	int error __diagused;

	KASSERT(!CPU_ABSENT(cpuid), ("%s: CPU %u absent", __func__, cpuid));

	nws = malloc(sizeof(*nws), M_NETISR, M_WAITOK | M_ZERO);
	mtx_init(&nws->nws_mtx, "netisr", NULL, MTX_DEF);
	snprintf(swiname, sizeof(swiname), "netisr %u", cpuid);
	error = swi_add(&nws->nws_intr_event, swiname, swi_net, nws,
	    SWI_NET, INTR_TYPE_NET | INTR_MPSAFE, &nws->nws_swi_cookie);
	MPASS(!error);
	if (netisr_bindthreads) {
		nws->nws_cpu = cpuid;
		error = intr_event_bind(nws->nws_intr_event, cpuid);
		MPASS(!error);
	}
	NETISR_WLOCK();
	nws_array[nws_count] = nws;
	nws_count++;
	NETISR_WUNLOCK();
}

/*
 * Initialize the netisr subsystem.  We rely on BSS and static initialization
 * of most fields in global data structures.
 *
 * Start a worker thread for the boot CPU so that we can support network
 * traffic immediately in case the network stack is used before additional
 * CPUs are started (for example, diskless boot).
 */
static void
netisr_init(void *arg)
{
	struct pcpu *pc;

	sx_init(&netisr_lock, "netisr_global");
	if (netisr_maxthreads == 0 || netisr_maxthreads < -1 )
		netisr_maxthreads = 1;		/* default behavior */
	else if (netisr_maxthreads == -1)
		netisr_maxthreads = mp_ncpus;	/* use max cpus */
	if (netisr_maxthreads > mp_ncpus) {
		printf("netisr_init: forcing maxthreads from %d to %d\n",
		    netisr_maxthreads, mp_ncpus);
		netisr_maxthreads = mp_ncpus;
	}
	if (netisr_defaultqlimit > netisr_maxqlimit) {
		printf("netisr_init: forcing defaultqlimit from %d to %d\n",
		    netisr_defaultqlimit, netisr_maxqlimit);
		netisr_defaultqlimit = netisr_maxqlimit;
	}
#ifdef DEVICE_POLLING
	/*
	 * The device polling code is not yet aware of how to deal with
	 * multiple netisr threads, so for the time being compiling in device
	 * polling disables parallel netisr workers.
	 */
	if (netisr_maxthreads != 1 || netisr_bindthreads != 0) {
		printf("netisr_init: forcing maxthreads to 1 and "
		    "bindthreads to 0 for device polling\n");
		netisr_maxthreads = 1;
		netisr_bindthreads = 0;
	}
#endif

	STAILQ_FOREACH(pc, &cpuhead, pc_allcpu) {
		if (nws_count >= netisr_maxthreads)
			break;
		netisr_start_swi(pc->pc_cpuid, pc);
	}
}
SYSINIT(netisr_init, SI_SUB_SOFTINTR, SI_ORDER_FIRST, netisr_init, NULL);

/*
 * Sysctl monitoring for netisr: query a list of registered protocols.
 */
static int
sysctl_netisr_proto(SYSCTL_HANDLER_ARGS)
{
	struct sysctl_netisr_proto *snpp, *snp_array;
	struct netisr_proto *npp;
	u_int counter, proto;
	int error;

	if (req->newptr != NULL)
		return (EINVAL);
	snp_array = malloc(sizeof(*snp_array) * NETISR_MAXPROT, M_TEMP,
	    M_ZERO | M_WAITOK);
	counter = 0;
	for (proto = 0; proto < NETISR_MAXPROT; proto++) {
		npp = &netisr_proto[proto];
		if (npp->np_name == NULL)
			continue;
		snpp = &snp_array[counter];
		snpp->snp_version = sizeof(*snpp);
		strlcpy(snpp->snp_name, npp->np_name, NETISR_NAMEMAXLEN);
		snpp->snp_proto = proto;
		snpp->snp_qlimit = npp->np_qlimit;
		snpp->snp_policy = npp->np_policy;
		snpp->snp_dispatch = npp->np_dispatch;
		if (npp->np_m2flow != NULL)
			snpp->snp_flags |= NETISR_SNP_FLAGS_M2FLOW;
		if (npp->np_m2cpuid != NULL)
			snpp->snp_flags |= NETISR_SNP_FLAGS_M2CPUID;
		if (npp->np_drainedcpu != NULL)
			snpp->snp_flags |= NETISR_SNP_FLAGS_DRAINEDCPU;
		counter++;
	}
	KASSERT(counter <= NETISR_MAXPROT,
	    ("sysctl_netisr_proto: counter too big (%d)", counter));
	error = SYSCTL_OUT(req, snp_array, sizeof(*snp_array) * counter);
	free(snp_array, M_TEMP);
	return (error);
}

SYSCTL_PROC(_net_isr, OID_AUTO, proto,
    CTLFLAG_RD|CTLTYPE_STRUCT|CTLFLAG_MPSAFE, 0, 0, sysctl_netisr_proto,
    "S,sysctl_netisr_proto",
    "Return list of protocols registered with netisr");

/*
 * Sysctl monitoring for netisr: query a list of workstreams.
 */
static int
sysctl_netisr_workstream(SYSCTL_HANDLER_ARGS)
{
	struct sysctl_netisr_workstream *snwsp, *snws_array;
	u_int counter;
	int error;

	if (req->newptr != NULL)
		return (EINVAL);
	snws_array = malloc(sizeof(*snws_array) * MAXCPU, M_TEMP,
	    M_ZERO | M_WAITOK);
	counter = 0;
	for (u_int i = 0; i < nws_count; i++) {
		struct netisr_workstream *nws = nws_array[i];

		NWS_LOCK(nws);
		snwsp = &snws_array[counter];
		snwsp->snws_version = sizeof(*snwsp);

		/*
		 * For now, we equate workstream IDs and CPU IDs in the
		 * kernel, but expose them independently to userspace in case
		 * that assumption changes in the future.
		 */
		snwsp->snws_wsid = i;
		snwsp->snws_cpu = nws->nws_cpu;
		if (nws->nws_intr_event != NULL)
			snwsp->snws_flags |= NETISR_SNWS_FLAGS_INTR;
		NWS_UNLOCK(nws);
		counter++;
	}
	KASSERT(counter <= MAXCPU,
	    ("sysctl_netisr_workstream: counter too big (%d)", counter));
	error = SYSCTL_OUT(req, snws_array, sizeof(*snws_array) * counter);
	free(snws_array, M_TEMP);
	return (error);
}

SYSCTL_PROC(_net_isr, OID_AUTO, workstream,
    CTLFLAG_RD|CTLTYPE_STRUCT|CTLFLAG_MPSAFE, 0, 0, sysctl_netisr_workstream,
    "S,sysctl_netisr_workstream",
    "Return list of workstreams implemented by netisr");

/*
 * Sysctl monitoring for netisr: query per-protocol data across all
 * workstreams.
 */
static int
sysctl_netisr_work(SYSCTL_HANDLER_ARGS)
{
	struct sysctl_netisr_work *snwp, *snw_array;
	struct netisr_workstream *nwsp;
	struct netisr_proto *npp;
	struct netisr_work *nwp;
	u_int counter, proto;
	int error;

	if (req->newptr != NULL)
		return (EINVAL);
	snw_array = malloc(sizeof(*snw_array) * MAXCPU * NETISR_MAXPROT,
	    M_TEMP, M_ZERO | M_WAITOK);
	counter = 0;
	for (u_int i = 0; i < nws_count; i++) {
		nwsp = nws_array[i];
		NWS_LOCK(nwsp);
		for (proto = 0; proto < NETISR_MAXPROT; proto++) {
			npp = &netisr_proto[proto];
			if (npp->np_name == NULL)
				continue;
			nwp = &nwsp->nws_work[proto];
			snwp = &snw_array[counter];
			snwp->snw_version = sizeof(*snwp);
			snwp->snw_wsid = i;		/* See comment above. */
			snwp->snw_proto = proto;
			snwp->snw_len = buf_ring_count(nwp->nw_br);
			/* Lazily update the watermark. */
			if (snwp->snw_len > nwp->nw_watermark)
				nwp->nw_watermark = snwp->snw_len;
			snwp->snw_watermark = nwp->nw_watermark;
			snwp->snw_dispatched =
			    counter_u64_fetch(nwp->nw_dispatched);
			snwp->snw_hybrid_dispatched =
			    counter_u64_fetch(nwp->nw_hybrid_dispatched);
			snwp->snw_qdrops = buf_ring_drops(nwp->nw_br);
			snwp->snw_queued = counter_u64_fetch(nwp->nw_queued);
			snwp->snw_handled = counter_u64_fetch(nwp->nw_handled);
			counter++;
		}
		NWS_UNLOCK(nwsp);
	}
	KASSERT(counter <= MAXCPU * NETISR_MAXPROT,
	    ("sysctl_netisr_work: counter too big (%d)", counter));
	error = SYSCTL_OUT(req, snw_array, sizeof(*snw_array) * counter);
	free(snw_array, M_TEMP);
	return (error);
}

SYSCTL_PROC(_net_isr, OID_AUTO, work,
    CTLFLAG_RD|CTLTYPE_STRUCT|CTLFLAG_MPSAFE, 0, 0, sysctl_netisr_work,
    "S,sysctl_netisr_work",
    "Return list of per-workstream, per-protocol work in netisr");
