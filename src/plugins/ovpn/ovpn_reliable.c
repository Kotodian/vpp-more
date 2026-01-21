/*
 * reliable.c - ovpn reliable source file
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

#include <ovpn/ovpn_buffer.h>
#include <ovpn/ovpn_session_id.h>
#include <vlib/vlib.h>
#include <ovpn/ovpn_reliable.h>

always_inline u32
ovpn_substract_packet_id (u32 test, u32 base)
{
  return test - base;
}

always_inline u8
ovpn_reliable_pid_in_range1 (u32 test, u32 base, unsigned int extent)
{
  return ovpn_substract_packet_id (test, base) < extent;
}

always_inline u8
ovpn_reliable_pid_in_range2 (u32 test, u32 base, unsigned int extent)
{
  if (base + extent >= base)
    {
      if (test < base + extent)
	{
	  return 1;
	}
    }
  else
    {
      if ((test + 0x80000000u) < (base + 0x80000000u) + extent)
	{
	  return 1;
	}
    }

  return 0;
}

always_inline u8
ovpn_reliable_pid_min (u32 p1, u32 p2)
{
  return !ovpn_reliable_pid_in_range1 (p1, p2, 0x80000000u);
}

always_inline u8
ovpn_reliable_ack_packet_id_present (ovpn_reliable_ack_t *ack, u32 pid)
{
  int i;
  for (i = 0; i < ack->len; i++)
    {
      if (ack->packet_id[i] == pid)
	{
	  return 1;
	}
    }
  return 0;
}

u8
ovpn_reliable_ack_read_packet_id (ovpn_reli_buffer_t *buf, u32 *pid)
{
  u32 net_pid;
  if (ovpn_buf_read (buf, &net_pid, sizeof (u32)))
    {
      *pid = clib_net_to_host_u32 (net_pid);
      return 1;
    }
  return 0;
}

u8
ovpn_reliable_ack_acknowledge_packet_id (ovpn_reliable_ack_t *ack, u32 pid)
{
  if (!ovpn_reliable_ack_packet_id_present (ack, pid) &&
      ack->len < OVPN_RELIABLE_ACK_SIZE)
    {
      ack->packet_id[ack->len++] = pid;
      return 1;
    }

  return 0;
}

u8
ovpn_reliable_ack_read (ovpn_reliable_ack_t *ack, ovpn_reli_buffer_t *buf,
			ovpn_session_id_t *sid)
{
  ovpn_session_id_t session_id_remote;
  if (!ovpn_reliable_ack_parse (buf, ack, &session_id_remote))
    {
      return 0;
    }
  if (ack->len >= 1 && (!ovpn_session_id_defined (&session_id_remote) ||
			!ovpn_session_id_equal (&session_id_remote, sid)))
    {
      return 0;
    }

  return 1;
}

u8
ovpn_reliable_ack_parse (ovpn_reli_buffer_t *buf, ovpn_reliable_ack_t *ack,
			 ovpn_session_id_t *sid_remote)
{
  u8 count;
  ack->len = 0;
  if (!ovpn_buf_read (buf, &count, sizeof (u8)))
    {
      return 0;
    }
  for (int i = 0; i < count; i++)
    {
      u32 net_pid;
      if (!ovpn_buf_read (buf, &net_pid, sizeof (u32)))
	{
	  return 0;
	}
      if (ack->len >= OVPN_RELIABLE_ACK_SIZE)
	{
	  return 0;
	}
      ack->packet_id[ack->len++] = clib_net_to_host_u32 (net_pid);
    }

  if (count)
    {
      if (!ovpn_session_id_read (sid_remote, buf))
	{
	  return 0;
	}
    }
  return 1;
}

void
ovpn_reliable_copy_acks_to_mru (ovpn_reliable_ack_t *ack,
				ovpn_reliable_ack_t *ack_mru, int n)
{
  ASSERT (ack->len >= n);
  /* Backward iteration: ack[0] ends up at MRU front position */
  for (int i = n - 1; i >= 0; i--)
    {
      u32 id = ack->packet_id[i];

      /* Handle special case when ack_mru is empty */
      if (ack_mru->len == 0)
	{
	  ack_mru->len = 1;
	  ack_mru->packet_id[0] = id;
	}

      u8 idfound = 0;

      /* Move all existing entries one to the right */
      u32 move = id;

      for (int j = 0; j < ack_mru->len; j++)
	{
	  u32 tmp = ack_mru->packet_id[j];
	  ack_mru->packet_id[j] = move;
	  move = tmp;

	  if (move == id)
	    {
	      idfound = 1;
	      break;
	    }
	}

      if (!idfound && ack_mru->len < OVPN_RELIABLE_ACK_SIZE)
	{
	  ack_mru->packet_id[ack_mru->len++] = move;
	}
    }
}

int
ovpn_reliable_ack_write (ovpn_reliable_ack_t *ack,
			 ovpn_reliable_ack_t *ack_mru, ovpn_reli_buffer_t *buf,
			 ovpn_session_id_t *sid, u32 max, u8 prepend)
{
  int i, j;
  u8 n;
  ovpn_reli_buffer_t sub;

  n = ack->len;
  if (n > max)
    {
      n = max;
    }

  ovpn_reliable_copy_acks_to_mru (ack, ack_mru, n);

  u8 total_acks = clib_min (max, ack_mru->len);
  sub = ovpn_buf_sub (buf, OVPN_ACK_SIZE (total_acks), prepend);
  if (!OVPN_BDEF (&sub))
    {
      goto error;
    }
  ovpn_buf_write_u8 (&sub, total_acks);

  for (i = 0; i < total_acks; i++)
    {
      u32 pid = ack_mru->packet_id[i];
      /* ovpn_buf_write_u32 already handles host-to-network conversion */
      ovpn_buf_write_u32 (&sub, pid);
    }

  if (total_acks)
    {
      ASSERT (ovpn_session_id_defined (sid));
      ASSERT (ovpn_session_id_write (sid, &sub));
    }

  if (n)
    {
      for (i = 0, j = n; j < ack->len;)
	{
	  ack->packet_id[i++] = ack->packet_id[j++];
	}
      ack->len = i;
    }

  return 0;

error:
  return -1;
}

void
ovpn_reliable_init (ovpn_reliable_t *rel, int buf_size, int offset,
		    int array_size, u8 hold)
{
  int i;

  clib_memset (rel, 0, sizeof (ovpn_reliable_t));
  ASSERT (array_size != 0 && array_size <= OVPN_RELIABLE_CAPACITY);
  rel->hold = hold;
  rel->size = array_size;
  rel->offset = offset;
  for (i = 0; i < rel->size; i++)
    {

      ovpn_reliable_entry_t *e = &rel->array[i];
      ovpn_reli_buffer_t *buf;
      u8 init_ok;
      e->buf_index = ovpn_buf_alloc (buf_size);
      buf = ovpn_buf_get (e->buf_index);
      init_ok = ovpn_buf_init (buf, offset);
      ASSERT (init_ok);
      (void) init_ok;
    }
}

void
ovpn_reliable_free (ovpn_reliable_t *rel)
{
  if (!rel)
    return;
  int i;
  for (i = 0; i < rel->size; i++)
    {
      ovpn_reliable_entry_t *e = &rel->array[i];
      ovpn_buf_free (ovpn_buf_get (e->buf_index));
    }
}

/* del acknowledged items from send buf */
void
ovpn_reliable_send_purge (ovpn_reliable_t *rel, ovpn_reliable_ack_t *ack)
{
  int i, j;
  for (i = 0; i < ack->len; i++)
    {
      u32 pid = ack->packet_id[i];
      for (j = 0; j < rel->size; j++)
	{
	  ovpn_reliable_entry_t *e = &rel->array[j];
	  if (e->active && e->packet_id == pid)
	    {
	      e->active = 0;
	    }
	  else if (e->active && e->packet_id < pid)
	    {
	      e->n_acks++;
	    }
	}
    }
}

/* 1 if at least one free buffer avaliable */
u8
ovpn_reliable_can_get (const ovpn_reliable_t *rel)
{
  int i;
  for (i = 0; i < rel->size; i++)
    {
      const ovpn_reliable_entry_t *e = &rel->array[i];
      if (!e->active)
	{
	  return 1;
	}
    }
  return 0;
}

u8
ovpn_reliable_not_replay (ovpn_reliable_t *rel, u32 id)
{
  int i;
  if (ovpn_reliable_pid_min (id, rel->packet_id))
    {
      return 0;
    }
  for (i = 0; i < rel->size; i++)
    {
      const ovpn_reliable_entry_t *e = &rel->array[i];
      if (e->active && e->packet_id == id)
	{
	  return 0;
	}
    }
  return 1;
}

/* make sure that incoming packet ID won't deadlock the receive buffer */
u8
ovpn_reliable_wont_break_sequentiality (ovpn_reliable_t *rel, u32 id)
{
  return ovpn_reliable_pid_in_range2 (id, rel->packet_id, rel->size);
}

/* grab a free buffer */
ovpn_reli_buffer_t *
ovpn_reliable_get_buf (ovpn_reliable_t *rel)
{
  int i;
  for (i = 0; i < rel->size; i++)
    {
      ovpn_reliable_entry_t *e = &rel->array[i];
      if (!e->active)
	{
	  ovpn_reli_buffer_t *buf = ovpn_buf_get (e->buf_index);
	  ovpn_buf_init (buf, rel->offset);
	  return buf;
	}
    }
  return NULL;
}

int
ovpn_reliable_get_num_output_sequenced_available (ovpn_reliable_t *rel)
{
  u32 min_id = 0;
  u8 min_id_defined = 0;

  for (int i = 0; i < rel->size; i++)
    {
      const ovpn_reliable_entry_t *e = &rel->array[i];
      if (e->active)
	{
	  if (!min_id_defined || ovpn_reliable_pid_min (e->packet_id, min_id))
	    {
	      min_id_defined = 1;
	      min_id = e->packet_id;
	    }
	}
    }

  int ret = rel->size;
  if (min_id_defined)
    {
      ret -= ovpn_substract_packet_id (rel->packet_id, min_id);
    }

  return ret;
}

/* grab a free buffer, fail if buffer clogged by unacknowledged low packet IDs
 */
ovpn_reli_buffer_t *
ovpn_reliable_get_buf_output_sequenced (ovpn_reliable_t *rel)
{
  int i;
  u32 min_id = 0;
  u8 min_id_defined = 0;
  ovpn_reli_buffer_t *ret = NULL;

  for (i = 0; i < rel->size; i++)
    {
      ovpn_reliable_entry_t *e = &rel->array[i];
      if (e->active)
	{

	  if (!min_id_defined || ovpn_reliable_pid_min (e->packet_id, min_id))
	    {
	      min_id_defined = 1;
	      min_id = e->packet_id;
	    }
	}
    }

  if (!min_id_defined ||
      ovpn_reliable_pid_in_range1 (rel->packet_id, min_id, rel->size))
    {
      ret = ovpn_reliable_get_buf (rel);
    }
  return ret;
}

ovpn_reliable_entry_t *
ovpn_reliable_get_entry_sequenced (ovpn_reliable_t *rel)
{
  int i;
  for (i = 0; i < rel->size; i++)
    {
      ovpn_reliable_entry_t *e = &rel->array[i];
      if (e->active && e->packet_id == rel->packet_id)
	{
	  return e;
	}
    }
  return NULL;
}

/* return 1 if reliable_send would return a non-NULL result */
u8
ovpn_reliable_can_send (vlib_main_t *vm, ovpn_reliable_t *rel)
{
  int i;
  int n_current = 0;
  f64 now = vlib_time_now (vm);
  for (i = 0; i < rel->size; i++)
    {
      ovpn_reliable_entry_t *e = &rel->array[i];
      if (e->active)
	{
	  if (now >= e->next_try || e->n_acks >= OVPN_N_ACK_RETRANSIMIT)
	    {
	      ++n_current;
	    }
	}
    }
  return n_current > 0 && !rel->hold;
}

ovpn_reli_buffer_t *
ovpn_reliable_send (vlib_main_t *vm, ovpn_reliable_t *rel, u8 *opcode)
{
  int i;
  ovpn_reliable_entry_t *best = NULL;
  f64 local_now = vlib_time_now (vm);

  for (i = 0; i < rel->size; i++)
    {
      ovpn_reliable_entry_t *e = &rel->array[i];
      if (e->active)
	{
	  if (e->active && (e->n_acks >= OVPN_N_ACK_RETRANSIMIT ||
			    local_now >= e->next_try))
	    {
	      if (!best ||
		  ovpn_reliable_pid_min (e->packet_id, best->packet_id))
		{
		  best = e;
		}
	    }
	}
    }

  if (best)
    {
      /* exponential backoff */
      best->next_try = local_now + best->timeout;
      best->timeout *= 2;
      best->n_acks = 0;
      *opcode = best->opcode;
      return ovpn_buf_get (best->buf_index);
    }
  return NULL;
}

void
ovpn_reliable_schedule_now (vlib_main_t *vm, ovpn_reliable_t *rel)
{
  int i;
  rel->hold = 0;
  for (i = 0; i < rel->size; i++)
    {
      ovpn_reliable_entry_t *e = &rel->array[i];
      if (e->active)
	{
	  e->next_try = vlib_time_now (vm);
	  e->timeout = rel->initial_timeout;
	}
    }
}

u8
ovpn_reliable_empty (ovpn_reliable_t *rel)
{
  int i;
  for (i = 0; i < rel->size; i++)
    {
      if (rel->array[i].active)
	return 0;
    }
  return 1;
}

/* in how many seconds should we wake up to check for timeout */
/* if we return BIG_TIMEOUT, nothing to wait for */
f64
ovpn_reliable_send_timeout (vlib_main_t *vm, ovpn_reliable_t *rel)
{
  int i;
  f64 local_now = vlib_time_now (vm);
  f64 ret = OVPN_BIG_TIMEOUT;
  for (i = 0; i < rel->size; i++)
    {
      ovpn_reliable_entry_t *e = &rel->array[i];
      if (e->active)
	{
	  if (e->next_try <= local_now)
	    {
	      ret = 0;
	      break;
	    }
	  else
	    {
	      ret = clib_min (ret, e->next_try - local_now);
	    }
	}
    }
  return ret;
}

/*
 * Enable an incoming buffer previously returned by a get function as active.
 */
void
ovpn_reliable_mark_active_incoming (ovpn_reliable_t *rel,
				    ovpn_reli_buffer_t *buf, u32 pid,
				    u8 opcode)
{
  int i;
  for (i = 0; i < rel->size; i++)
    {
      ovpn_reliable_entry_t *e = &rel->array[i];
      if (e->buf_index == buf->index)
	{
	  e->active = 1;
	  e->packet_id = pid;
	  ASSERT (!ovpn_reliable_pid_min (pid, rel->packet_id));

	  e->opcode = opcode;
	  e->next_try = 0;
	  e->timeout = 0;
	  e->n_acks = 0;
	  return;
	}
    }

  ASSERT (0);
}

/*
 * Enable an outgoing buffer previously returned by a get function as active.
 */
void
ovpn_reliable_mark_active_outgoing (ovpn_reliable_t *rel,
				    ovpn_reli_buffer_t *buf, u8 opcode)
{
  int i;
  for (i = 0; i < rel->size; i++)
    {
      ovpn_reliable_entry_t *e = &rel->array[i];
      if (buf->index == e->buf_index)
	{
	  u32 net_pid;
	  u8 prepend_ok;
	  e->packet_id = rel->packet_id++;
	  net_pid = clib_host_to_net_u32 (e->packet_id);
	  prepend_ok = ovpn_buf_write_prepend (buf, &net_pid, sizeof (net_pid));
	  ASSERT (prepend_ok);
	  (void) prepend_ok; /* Silence unused variable warning in release */
	  e->active = 1;
	  e->opcode = opcode;
	  e->next_try = 0;
	  e->timeout = rel->initial_timeout;
	  return;
	}
    }
  ASSERT (0);
}

/* delete a buffer previously activated by reliable_mark_active() */
void
ovpn_reliable_mark_deleted (ovpn_reliable_t *rel, ovpn_reli_buffer_t *buf)
{
  int i;
  for (i = 0; i < rel->size; i++)
    {
      ovpn_reliable_entry_t *e = &rel->array[i];
      if (e->buf_index == buf->index)
	{
	  e->active = 0;
	  rel->packet_id = e->packet_id + 1;
	  return;
	}
    }

  ASSERT (0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */