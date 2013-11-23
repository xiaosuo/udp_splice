/**
 * udp_splice - Splice two UDP sockets.
 * Copyright (C) 2013 Changli Gao <xiaosuo@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __UDP_SPLICE_H
#define __UDP_SPLICE_H

#define UDP_SPLICE_GENL_NAME	"udp_splice"
#define UDP_SPLICE_GENL_VERSION	0x1

enum {
	UDP_SPLICE_CMD_UNSPEC = 0,
	UDP_SPLICE_CMD_ADD,
	UDP_SPLICE_CMD_DELETE,
	UDP_SPLICE_CMD_GET,

	__UDP_SPLICE_CMD_MAX,
};

#define UDP_SPLICE_CMD_MAX	(__UDP_SPLICE_CMD_MAX - 1)

enum {
	UDP_SPLICE_ATTR_UNSPEC = 0,
	UDP_SPLICE_ATTR_SOCK,		/* u32 */
	UDP_SPLICE_ATTR_SOCK2,		/* u32 */
	UDP_SPLICE_ATTR_TIMEOUT,	/* u32 */

	__UDP_SPLICE_ATTR_MAX,
};

#define UDP_SPLICE_ATTR_MAX	(__UDP_SPLICE_ATTR_MAX - 1)

#endif /* __UDP_SPLICE_H */
