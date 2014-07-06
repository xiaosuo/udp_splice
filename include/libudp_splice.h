/**
 * udp_splice - Splice two UDP sockets.
 * Copyright (C) 2013-2014 Changli Gao <xiaosuo@gmail.com>
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

#ifndef __LIBUDP_SPLICE_H
#define __LIBUDP_SPLICE_H

#include <stdint.h>
#include <udp_splice.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void *udp_splice_open(void);
int udp_splice_add(void *handle, int sock, int sock2, uint32_t timeout);
int udp_splice_get(void *handle, int sock);
int udp_splice_delete(void *handle, int sock);
void udp_splice_close(void *handle);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LIBUDP_SPLICE_H */
