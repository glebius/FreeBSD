/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
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


#include <sys/param.h>
#include <sys/sysctl.h>

#include <sys/_lock.h>
#include <sys/_mutex.h>

#include <net/netisr.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sysexits.h>
#include <libxo/xo.h>
#include "netstat.h"
#include "nl_defs.h"

/*
 * Print statistics for the kernel netisr subsystem.
 */
static u_int				 bindthreads;
static u_int				 maxthreads;
static u_int				 numthreads;

static u_int				 defaultqlimit;
static u_int				 maxqlimit;

static char				 dispatch_policy[20];

static struct sysctl_netisr_proto	*proto_array;
static u_int				 proto_array_len;

static struct sysctl_netisr_workstream	*workstream_array;
static u_int				 workstream_array_len;

static struct sysctl_netisr_work	*work_array;
static u_int				 work_array_len;

static void
netisr_dispatch_policy_to_string(u_int policy, char *buf,
    size_t buflen)
{
	const char *str;

	switch (policy) {
	case NETISR_DISPATCH_DEFAULT:
		str = "default";
		break;
	case NETISR_DISPATCH_DEFERRED:
		str = "deferred";
		break;
	case NETISR_DISPATCH_HYBRID:
		str = "hybrid";
		break;
	case NETISR_DISPATCH_DIRECT:
		str = "direct";
		break;
	default:
		str = "unknown";
		break;
	}
	snprintf(buf, buflen, "%s", str);
}

static const char *
netisr_proto2name(u_int proto)
{
	u_int i;

	for (i = 0; i < proto_array_len; i++) {
		if (proto_array[i].snp_proto == proto)
			return (proto_array[i].snp_name);
	}
	return ("unknown");
}

static int
netisr_protoispresent(u_int proto)
{
	u_int i;

	for (i = 0; i < proto_array_len; i++) {
		if (proto_array[i].snp_proto == proto)
			return (1);
	}
	return (0);
}

static void
netisr_load_sysctl_uint(const char *name, u_int *p)
{
	size_t retlen;

	retlen = sizeof(u_int);
	if (sysctlbyname(name, p, &retlen, NULL, 0) < 0)
		xo_err(EX_OSERR, "%s", name);
	if (retlen != sizeof(u_int))
		xo_errx(EX_DATAERR, "%s: invalid len %ju", name, (uintmax_t)retlen);
}

static void
netisr_load_sysctl_string(const char *name, char *p, size_t len)
{
	size_t retlen;

	retlen = len;
	if (sysctlbyname(name, p, &retlen, NULL, 0) < 0)
		xo_err(EX_OSERR, "%s", name);
	p[len - 1] = '\0';
}

static void
netisr_load_sysctl_config(void)
{

	netisr_load_sysctl_uint("net.isr.bindthreads", &bindthreads);
	netisr_load_sysctl_uint("net.isr.maxthreads", &maxthreads);
	netisr_load_sysctl_uint("net.isr.numthreads", &numthreads);

	netisr_load_sysctl_uint("net.isr.defaultqlimit", &defaultqlimit);
	netisr_load_sysctl_uint("net.isr.maxqlimit", &maxqlimit);

	netisr_load_sysctl_string("net.isr.dispatch", dispatch_policy,
	    sizeof(dispatch_policy));
}

static void
netisr_load_sysctl_proto(void)
{
	size_t len;

	if (sysctlbyname("net.isr.proto", NULL, &len, NULL, 0) < 0)
		xo_err(EX_OSERR, "net.isr.proto: query len");
	if (len % sizeof(*proto_array) != 0)
		xo_errx(EX_DATAERR, "net.isr.proto: invalid len");
	proto_array = malloc(len);
	if (proto_array == NULL)
		xo_err(EX_OSERR, "malloc");
	if (sysctlbyname("net.isr.proto", proto_array, &len, NULL, 0) < 0)
		xo_err(EX_OSERR, "net.isr.proto: query data");
	if (len % sizeof(*proto_array) != 0)
		xo_errx(EX_DATAERR, "net.isr.proto: invalid len");
	proto_array_len = len / sizeof(*proto_array);
	if (proto_array_len < 1)
		xo_errx(EX_DATAERR, "net.isr.proto: no data");
	if (proto_array[0].snp_version != sizeof(proto_array[0]))
		xo_errx(EX_DATAERR, "net.isr.proto: invalid version");
}

static void
netisr_load_sysctl_workstream(void)
{
	size_t len;

	if (sysctlbyname("net.isr.workstream", NULL, &len, NULL, 0) < 0)
		xo_err(EX_OSERR, "net.isr.workstream: query len");
	if (len % sizeof(*workstream_array) != 0)
		xo_errx(EX_DATAERR, "net.isr.workstream: invalid len");
	workstream_array = malloc(len);
	if (workstream_array == NULL)
		xo_err(EX_OSERR, "malloc");
	if (sysctlbyname("net.isr.workstream", workstream_array, &len, NULL,
	    0) < 0)
		xo_err(EX_OSERR, "net.isr.workstream: query data");
	if (len % sizeof(*workstream_array) != 0)
		xo_errx(EX_DATAERR, "net.isr.workstream: invalid len");
	workstream_array_len = len / sizeof(*workstream_array);
	if (workstream_array_len < 1)
		xo_errx(EX_DATAERR, "net.isr.workstream: no data");
	if (workstream_array[0].snws_version != sizeof(workstream_array[0]))
		xo_errx(EX_DATAERR, "net.isr.workstream: invalid version");
}

static void
netisr_load_sysctl_work(void)
{
	size_t len;

	if (sysctlbyname("net.isr.work", NULL, &len, NULL, 0) < 0)
		xo_err(EX_OSERR, "net.isr.work: query len");
	if (len % sizeof(*work_array) != 0)
		xo_errx(EX_DATAERR, "net.isr.work: invalid len");
	work_array = malloc(len);
	if (work_array == NULL)
		xo_err(EX_OSERR, "malloc");
	if (sysctlbyname("net.isr.work", work_array, &len, NULL, 0) < 0)
		xo_err(EX_OSERR, "net.isr.work: query data");
	if (len % sizeof(*work_array) != 0)
		xo_errx(EX_DATAERR, "net.isr.work: invalid len");
	work_array_len = len / sizeof(*work_array);
	if (work_array_len < 1)
		xo_errx(EX_DATAERR, "net.isr.work: no data");
	if (work_array[0].snw_version != sizeof(work_array[0]))
		xo_errx(EX_DATAERR, "net.isr.work: invalid version");
}

static void
netisr_print_proto(struct sysctl_netisr_proto *snpp)
{
	char tmp[20];

	xo_emit("{[:-6}{k:name/%s}{]:}", snpp->snp_name);
	xo_emit(" {:protocol/%5u}", snpp->snp_proto);
	xo_emit(" {:queue-limit/%6u}", snpp->snp_qlimit);
	xo_emit(" {:policy-type/%6s}",
	    (snpp->snp_policy == NETISR_POLICY_SOURCE) ?  "source" :
	    (snpp->snp_policy == NETISR_POLICY_FLOW) ? "flow" :
	    (snpp->snp_policy == NETISR_POLICY_CPU) ? "cpu" : "-");
	netisr_dispatch_policy_to_string(snpp->snp_dispatch, tmp,
	    sizeof(tmp));
	xo_emit(" {:policy/%8s}", tmp);
	xo_emit("   {:flags/%s%s%s}\n",
	    (snpp->snp_flags & NETISR_SNP_FLAGS_M2CPUID) ?  "C" : "-",
	    (snpp->snp_flags & NETISR_SNP_FLAGS_DRAINEDCPU) ?  "D" : "-",
	    (snpp->snp_flags & NETISR_SNP_FLAGS_M2FLOW) ? "F" : "-");
}

static void
netisr_print_workstream(struct sysctl_netisr_workstream *snwsp)
{
	struct sysctl_netisr_work *snwp;
	u_int i;

	xo_open_list("work");
	for (i = 0; i < work_array_len; i++) {
		snwp = &work_array[i];
		if (snwp->snw_wsid != snwsp->snws_wsid)
			continue;
		xo_open_instance("work");
		xo_emit("{t:workstream/%4u} ", snwsp->snws_wsid);
		xo_emit("{t:cpu/%3u} ", snwsp->snws_cpu);
		xo_emit("{P:  }");
		xo_emit("{t:name/%-6s}", netisr_proto2name(snwp->snw_proto));
		xo_emit(" {t:length/%5u}", snwp->snw_len);
		xo_emit(" {t:watermark/%5u}", snwp->snw_watermark);
		xo_emit(" {t:dispatched/%8ju}", snwp->snw_dispatched);
		xo_emit(" {t:hybrid-dispatched/%8ju}",
		    snwp->snw_hybrid_dispatched);
		xo_emit(" {t:queue-drops/%8ju}", snwp->snw_qdrops);
		xo_emit(" {t:queued/%8ju}", snwp->snw_queued);
		xo_emit(" {t:handled/%8ju}", snwp->snw_handled);
		xo_emit("\n");
		xo_close_instance("work");
	}
	xo_close_list("work");
}

void
netisr_stats(void)
{
	struct sysctl_netisr_workstream *snwsp;
	struct sysctl_netisr_proto *snpp;
	u_int i;

	if (!live)
		return;

	netisr_load_sysctl_config();
	netisr_load_sysctl_proto();
	netisr_load_sysctl_workstream();
	netisr_load_sysctl_work();

	xo_open_container("netisr");

	xo_emit("{T:Configuration}:\n");
	xo_emit("{T:/%-25s} {T:/%12s} {T:/%12s}\n",
	    "Setting", "Current", "Limit");
	xo_emit("{T:/%-25s} {T:/%12u} {T:/%12u}\n",
	    "Thread count", numthreads, maxthreads);
	xo_emit("{T:/%-25s} {T:/%12u} {T:/%12u}\n",
	    "Default queue limit", defaultqlimit, maxqlimit);
	xo_emit("{T:/%-25s} {T:/%12s} {T:/%12s}\n",
	    "Dispatch policy", dispatch_policy, "n/a");
	xo_emit("{T:/%-25s} {T:/%12s} {T:/%12s}\n",
	    "Threads bound to CPUs", bindthreads ? "enabled" : "disabled",
	    "n/a");
	xo_emit("\n");

	xo_emit("{T:Protocols}:\n");
	xo_emit("{T:/%-6s} {T:/%5s} {T:/%6s} {T:/%-6s} {T:/%-8s} {T:/%-5s}\n",
	    "Name", "Proto", "QLimit", "Policy", "Dispatch", "Flags");
	xo_open_list("protocol");
	for (i = 0; i < proto_array_len; i++) {
		xo_open_instance("protocol");
		snpp = &proto_array[i];
		netisr_print_proto(snpp);
		xo_close_instance("protocol");
	}
	xo_close_list("protocol");
	xo_emit("\n");

	xo_emit("{T:Workstreams}:\n");
	xo_emit("{T:/%4s} {T:/%3s} ", "WSID", "CPU");
	xo_emit("{P:/%2s}", "");
	xo_emit("{T:/%-6s} {T:/%5s} {T:/%5s} {T:/%8s} {T:/%8s} {T:/%8s} "
	    "{T:/%8s} {T:/%8s}\n",
	    "Name", "Len", "WMark", "Disp'd", "HDisp'd", "QDrops", "Queued",
	    "Handled");
	xo_open_list("workstream");
	for (i = 0; i < workstream_array_len; i++) {
		xo_open_instance("workstream");
		snwsp = &workstream_array[i];
		netisr_print_workstream(snwsp);
		xo_close_instance("workstream");
	}
	xo_close_list("workstream");
	xo_close_container("netisr");
}
