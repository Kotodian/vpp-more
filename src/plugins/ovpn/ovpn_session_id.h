/*
 * session_id.h - ovpn session id header file
 *
 * Copyright (c) 2025 <blackfaceuncle@gmail.com>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __included_ovpn_session_id_h__
#define __included_ovpn_session_id_h__

#include <vlib/vlib.h>
#include <ovpn/ovpn_buffer.h>

typedef struct ovpn_session_id_t_
{
  u8 id[8];
} ovpn_session_id_t;

extern const ovpn_session_id_t x_session_id_zero;

#define OVPN_SID_SIZE (sizeof (x_session_id_zero.id))

always_inline u8
ovpn_session_id_equal (const ovpn_session_id_t *a, const ovpn_session_id_t *b)
{
  return clib_memcmp (a->id, b->id, OVPN_SID_SIZE) == 0;
}

always_inline u8
ovpn_session_id_defined (const ovpn_session_id_t *sid1)
{
  return clib_memcmp (sid1->id, x_session_id_zero.id, OVPN_SID_SIZE) != 0;
}

always_inline u8
ovpn_session_id_read (ovpn_session_id_t *sid, ovpn_reli_buffer_t *buf)
{
  return ovpn_buf_read (buf, sid->id, OVPN_SID_SIZE);
}

always_inline u8
ovpn_session_id_write_prepend (const ovpn_session_id_t *sid,
			       ovpn_reli_buffer_t *buf)
{
  return ovpn_buf_write_prepend (buf, sid->id, OVPN_SID_SIZE);
}

always_inline u8
ovpn_session_id_write (const ovpn_session_id_t *sid, ovpn_reli_buffer_t *buf)
{
  return ovpn_buf_write (buf, sid->id, OVPN_SID_SIZE);
}

always_inline void
ovpn_session_id_generate (ovpn_session_id_t *sid)
{
  /* Generate random session ID using VPP's random number generator */
  u64 *p = (u64 *) sid->id;
  static u64 seed = 0;
  if (seed == 0)
    seed = (u64) unix_time_now ();
  *p = random_u64 (&seed);
  /* Ensure non-zero */
  if (*p == 0)
    *p = 1;
}

always_inline void
ovpn_session_id_copy (ovpn_session_id_t *dst, const ovpn_session_id_t *src)
{
  clib_memcpy_fast (dst->id, src->id, OVPN_SID_SIZE);
}

#endif /* __included_ovpn_session_id_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */