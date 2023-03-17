/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
#ifndef _H_LIB_CLUSTERMESH_H_
#define _H_LIB_CLUSTERMESH_H_

static __always_inline __u8
extract_cluster_id_from_identity(__u32 identity)
{
	return (__u8)(identity >> 16);
}

#endif
