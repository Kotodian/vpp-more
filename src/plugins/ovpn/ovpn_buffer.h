/*
 * ovpn_buffer.h - OpenVPN buffer header file
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

#ifndef __included_ovpn_buffer_h__
#define __included_ovpn_buffer_h__

#include <vlib/vlib.h>

#define BUF_SIZE_MAX 1000000

typedef struct ovpn_reli_buffer_t_
{
  u32 index;
  int capacity;
  int offset;
  int len;

  u8 *data;
} ovpn_reli_buffer_t;

extern ovpn_reli_buffer_t *ovpn_buf_pool;

always_inline u8
ovpn_buf_valid (const ovpn_reli_buffer_t *buf)
{
  return PREDICT_TRUE (buf != NULL) && PREDICT_TRUE (buf->len >= 0) &&
	 PREDICT_TRUE (buf->data != NULL);
}

always_inline u8 *
ovpn_buf_bptr (const ovpn_reli_buffer_t *buf)
{
  if (ovpn_buf_valid (buf))
    {
      return buf->data + buf->offset;
    }
  else
    {
      return NULL;
    }
}

always_inline int
ovpn_buf_len (const ovpn_reli_buffer_t *buf)
{
  if (ovpn_buf_valid (buf))
    {
      return buf->len;
    }
  return 0;
}

always_inline u8
ovpn_buf_defined (const ovpn_reli_buffer_t *buf)
{
  return buf->data != NULL;
}

always_inline u8 *
ovpn_buf_bend (ovpn_reli_buffer_t *buf)
{
  return ovpn_buf_bptr (buf) + ovpn_buf_len (buf);
}

always_inline u8 *
ovpn_buf_blast (ovpn_reli_buffer_t *buf)
{
  if (ovpn_buf_len (buf) > 0)
    return ovpn_buf_bptr (buf) + ovpn_buf_len (buf) - 1;
  return NULL;
}

always_inline u8
ovpn_buf_size_valid (const size_t size)
{
  return PREDICT_TRUE (size < BUF_SIZE_MAX);
}

always_inline u8
ovpn_buf_valid_signed (const int size)
{

  return PREDICT_TRUE (size >= -BUF_SIZE_MAX) &&
	 PREDICT_TRUE (size < BUF_SIZE_MAX);
}

always_inline void
ovpn_buf_reset (ovpn_reli_buffer_t *buf)
{
  buf->capacity = 0;
  buf->offset = 0;
  buf->len = 0;
  vec_reset_length (buf->data);
}

always_inline void
ovpn_reli_buf_reset_len (ovpn_reli_buffer_t *buf)
{
  buf->len = 0;
  buf->offset = 0;
}

always_inline u8
ovpn_buf_init_dowork (ovpn_reli_buffer_t *buf, int offset)
{
  if (offset < 0 || offset > buf->capacity || buf->data == NULL)
    {
      return 0;
    }
  buf->len = 0;
  buf->offset = offset;
  return 1;
}

always_inline u8
ovpn_buf_init (ovpn_reli_buffer_t *buf, int offset)
{
  return ovpn_buf_init_dowork (buf, offset);
}

always_inline int
ovpn_buf_set_write (ovpn_reli_buffer_t *buf, u8 *data, int size)
{
  if (!ovpn_buf_size_valid (size))
    {
      return -1;
    }

  buf->len = 0;
  buf->offset = 0;
  buf->capacity = size;
  buf->data = data;
  if (size > 0 && data)
    {
      *data = 0;
    }
  return 0;
}

always_inline int
ovpn_buf_set_read (ovpn_reli_buffer_t *buf, u8 *data, int size)
{
  if (!ovpn_buf_size_valid (size))
    {
      return -1;
    }
  buf->len = buf->capacity - size;
  buf->offset = size;
  buf->data = data;

  return 0;
}

always_inline u32
ovpn_buf_alloc (int capacity)
{
  ovpn_reli_buffer_t *buf;
  pool_get (ovpn_buf_pool, buf);
  buf->capacity = capacity;
  buf->offset = 0;
  buf->len = 0;
  vec_resize (buf->data, capacity);
  buf->index = buf - ovpn_buf_pool;
  return buf->index;
}

always_inline ovpn_reli_buffer_t *
ovpn_buf_get (u32 index)
{
  if (pool_is_free_index (ovpn_buf_pool, index))
    return NULL;
  return pool_elt_at_index (ovpn_buf_pool, index);
}

always_inline u32
ovpn_buf_clone (ovpn_reli_buffer_t *buf)
{
  ovpn_reli_buffer_t *new_buf;
  u32 index;
  index = ovpn_buf_alloc (buf->capacity);
  new_buf = ovpn_buf_get (index);
  vec_copy (new_buf->data, buf->data);
  return index;
}

always_inline void
ovpn_buf_clear (ovpn_reli_buffer_t *buf)
{
  buf->len = 0;
  buf->offset = 0;
  vec_reset_length (buf->data);
}

always_inline void
ovpn_buf_free (ovpn_reli_buffer_t *buf)
{
  vec_free (buf->data);
  clib_memset (buf, 0, sizeof (ovpn_reli_buffer_t));
  pool_put (ovpn_buf_pool, buf);
}

always_inline u8
ovpn_buf_safe (ovpn_reli_buffer_t *buf, size_t len)
{
  return ovpn_buf_valid (buf) && ovpn_buf_size_valid (len) &&
	 buf->offset + buf->len + (int) len <= buf->capacity;
}

always_inline u8
ovpn_buf_safe_bidir (ovpn_reli_buffer_t *buf, int len)
{
  if (ovpn_buf_valid (buf) && ovpn_buf_valid_signed (len))
    {
      int newlen = buf->len + len;
      return newlen >= 0 && buf->offset + newlen <= buf->capacity;
    }
  else
    {

      return 0;
    }
}

always_inline int
ovpn_buf_forward_capacity (ovpn_reli_buffer_t *buf, int capacity)
{
  if (ovpn_buf_valid (buf))
    {
      int ret = buf->capacity - (buf->offset + buf->len);
      if (ret < 0)
	{
	  ret = 0;
	}
      return ret;
    }
  else
    {
      return 0;
    }
}

#define OVPN_BPTR(buf)	(ovpn_buf_bptr (buf))
#define OVPN_BEND(buf)	(ovpn_buf_bend (buf))
#define OVPN_BLAST(buf) (ovpn_buf_blast (buf))
#define OVPN_BLEN(buf)	(ovpn_buf_len (buf))
#define OVPN_BDEF(buf)	(ovpn_buf_defined (buf))
#define OVPN_BCAP(buf)	(ovpn_buf_forward_capacity (buf))

always_inline int
ovpn_buf_forward_capacity_total (ovpn_reli_buffer_t *buf)
{
  if (ovpn_buf_valid (buf))
    {
      int ret = buf->capacity - buf->offset;
      if (ret < 0)
	{
	  ret = 0;
	}
      return ret;
    }
  else
    {
      return 0;
    }
}

always_inline int
ovpn_buf_reverse_capacity (ovpn_reli_buffer_t *buf)
{
  if (ovpn_buf_valid (buf))
    {
      return buf->offset;
    }
  else
    {
      return 0;
    }
}

always_inline u8
ovpn_buf_inc_len (ovpn_reli_buffer_t *buf, int inc)
{
  if (!ovpn_buf_safe_bidir (buf, inc))
    {
      return 0;
    }
  buf->len += inc;
  return 1;
}

always_inline u8 *
ovpn_buf_prepend (ovpn_reli_buffer_t *buf, int size)
{
  if (!ovpn_buf_valid (buf) || size < 0 || size > buf->offset)
    {
      return NULL;
    }
  buf->offset -= size;
  buf->len += size;
  return OVPN_BPTR (buf);
}

always_inline u8
ovpn_buf_advance (ovpn_reli_buffer_t *buf, int size)
{
  if (!ovpn_buf_valid (buf) || size < 0 || size > buf->len)
    {
      return 0;
    }
  buf->offset += size;
  buf->len -= size;
  return 1;
}

always_inline u8 *
ovpn_buf_write_alloc (ovpn_reli_buffer_t *buf, size_t size)
{
  u8 *ret;
  if (!ovpn_buf_safe (buf, size))
    {
      return NULL;
    }
  ret = OVPN_BPTR (buf) + buf->len;
  buf->len += (int) size;
  return ret;
}

always_inline u8 *
ovpn_buf_write_alloc_prepend (ovpn_reli_buffer_t *buf, int size, u8 prepend)
{
  if (prepend)
    {
      return ovpn_buf_prepend (buf, size);
    }
  else
    {
      return ovpn_buf_write_alloc (buf, size);
    }
}

always_inline u8 *
ovpn_buf_read_alloc (ovpn_reli_buffer_t *buf, int size)
{
  u8 *ret;
  if (size < 0 || buf->len < size)
    {
      return NULL;
    }
  ret = OVPN_BPTR (buf);
  buf->offset += size;
  buf->len -= size;
  return ret;
}

always_inline u8
ovpn_buf_write (ovpn_reli_buffer_t *dest, const void *src, size_t size)
{
  u8 *cp = ovpn_buf_write_alloc (dest, size);
  if (!cp)
    {
      return 0;
    }
  clib_memcpy_fast (cp, src, size);
  return 1;
}

always_inline u8
ovpn_buf_write_prepend (ovpn_reli_buffer_t *dest, const void *src, int size)
{
  u8 *cp = ovpn_buf_prepend (dest, size);
  if (!cp)
    {
      return 0;
    }
  clib_memcpy_fast (cp, src, size);
  return 1;
}

always_inline u8
ovpn_buf_write_u8 (ovpn_reli_buffer_t *dest, u8 data)
{
  return ovpn_buf_write (dest, &data, sizeof (u8));
}

always_inline u8
ovpn_buf_write_u16 (ovpn_reli_buffer_t *dest, u16 data)
{
  u16 data_net = clib_host_to_net_u16 (data);
  return ovpn_buf_write (dest, &data_net, sizeof (u16));
}

always_inline u8
ovpn_buf_write_u32 (ovpn_reli_buffer_t *dest, u32 data)
{
  u32 data_net = clib_host_to_net_u32 (data);
  return ovpn_buf_write (dest, &data_net, sizeof (u32));
}

always_inline u8
ovpn_buf_copy (ovpn_reli_buffer_t *dest, const ovpn_reli_buffer_t *src)
{
  return ovpn_buf_write (dest, OVPN_BPTR (src), OVPN_BLEN (src));
}

always_inline u8
ovpn_buf_copy_n (ovpn_reli_buffer_t *dest, const ovpn_reli_buffer_t *src,
		 int n)
{
  u8 *cp = ovpn_buf_read_alloc (dest, n);
  if (!cp)
    {
      return 0;
    }
  return ovpn_buf_write (dest, src, n);
}

always_inline u8
ovpn_buf_copy_range (ovpn_reli_buffer_t *dest, int dest_index,
		     const ovpn_reli_buffer_t *src, int src_index, int src_len)
{

  if (src_index < 0 || src_len < 0 || src_index + src_len > src->len ||
      dest_index < 0 || dest->offset + dest_index + src_len > dest->capacity)
    {
      return 0;
    }

  clib_memcpy_fast (dest->data + dest->offset + dest_index,
		    src->data + src->offset + src_index, src_len);
  if (dest_index + src_len > dest->len)
    {
      dest->len = dest_index + src_len;
    }
  return 1;
}

always_inline u8
ovpn_buf_copy_excess (ovpn_reli_buffer_t *dest, ovpn_reli_buffer_t *src,
		      int len)
{
  if (len < 0)
    {
      return 0;
    }

  if (src->len > len)
    {

      ovpn_reli_buffer_t b = *src;
      src->len = len;
      if (!ovpn_buf_advance (&b, len))
	{
	  return 0;
	}
      return ovpn_buf_copy (dest, &b);
    }
  else
    {
      return 1;
    }
}

always_inline u8
ovpn_buf_read (ovpn_reli_buffer_t *src, void *dest, int size)
{
  u8 *cp = ovpn_buf_read_alloc (src, size);
  if (!cp)
    {
      return 0;
    }
  clib_memcpy_fast (dest, cp, size);
  return 1;
}

always_inline int
ovpn_buf_read_u8 (ovpn_reli_buffer_t *buf)
{
  int ret;
  if (OVPN_BLEN (buf) < 1)
    {

      return -1;
    }
  ret = *OVPN_BPTR (buf);
  ovpn_buf_advance (buf, 1);
  return ret;
}

always_inline int
ovpn_buf_read_u16 (ovpn_reli_buffer_t *buf)
{
  int ret;
  if (!ovpn_buf_read (buf, &ret, sizeof (u16)))
    {
      return -1;
    }
  return clib_net_to_host_u16 (ret);
}

always_inline u32
ovpn_buf_read_u32 (ovpn_reli_buffer_t *buf, u8 *good)
{
  int ret;
  if (!ovpn_buf_read (buf, &ret, sizeof (u32)))
    {
      if (good)
	{
	  *good = 0;
	}
      return 0;
    }
  else
    {
      if (good)
	{
	  *good = 1;
	}
      return clib_net_to_host_u32 (ret);
    }
}

always_inline u8
ovpn_buf_equal (ovpn_reli_buffer_t *a, ovpn_reli_buffer_t *b)
{
  return OVPN_BLEN (a) == OVPN_BLEN (b) &&
	 clib_memcmp (OVPN_BPTR (a), OVPN_BPTR (b), OVPN_BLEN (a)) == 0;
}

always_inline ovpn_reli_buffer_t
ovpn_buf_sub (ovpn_reli_buffer_t *buf, int size, u8 prepend)
{
  ovpn_reli_buffer_t ret;
  u8 *data;

  clib_memset (&ret, 0, sizeof (ovpn_reli_buffer_t));
  data =
    prepend ? ovpn_buf_prepend (buf, size) : ovpn_buf_write_alloc (buf, size);
  if (data)
    {
      ret.capacity = size;
      ret.data = data;
    }
  return ret;
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
