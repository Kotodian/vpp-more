/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 * Copyright(c) 2024 Tom Jones <thj@freebsd.org>
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <vppinfra/clib.h>
#include <vppinfra/mem.h>
#include <vppinfra/lock.h>
#include <vppinfra/time.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/format.h>
#include <vppinfra/clib_error.h>

static void
map_lock ()
{
  while (clib_atomic_test_and_set (&clib_mem_main.map_lock))
    CLIB_PAUSE ();
}

static void
map_unlock ()
{
  clib_atomic_release (&clib_mem_main.map_lock);
}

void
clib_mem_main_init (void)
{
  clib_mem_main_t *mm = &clib_mem_main;
  long sysconf_page_size;
  uword page_size;
  void *va;

  if (mm->log2_page_sz != CLIB_MEM_PAGE_SZ_UNKNOWN)
    return;

  /* system page size */
  sysconf_page_size = sysconf (_SC_PAGESIZE);
  if (sysconf_page_size < 0)
    {
      clib_panic ("Could not determine the page size");
    }
  page_size = sysconf_page_size;
  mm->log2_page_sz = min_log2 (page_size);

  mm->log2_default_hugepage_sz = min_log2 (page_size);
  mm->log2_sys_default_hugepage_sz = mm->log2_default_hugepage_sz;

  /* numa nodes */
  va = mmap (0, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
	     -1, 0);
  if (va == MAP_FAILED)
    return;

  if (mlock (va, page_size))
    goto done;

  /*
   * TODO: In linux/mem.c we can move pages to numa domains, this isn't an
   * option in Darwin yet.
   */

done:
  munmap (va, page_size);
}

__clib_export u64
clib_mem_get_fd_page_size (int fd)
{
  struct stat st = { 0 };
  if (fstat (fd, &st) == -1)
    return 0;
  return (u64) sysconf (_SC_PAGESIZE);
}

__clib_export clib_mem_page_sz_t
clib_mem_get_fd_log2_page_size (int fd)
{
  uword page_size = clib_mem_get_fd_page_size (fd);
  return page_size ? min_log2 (page_size) : CLIB_MEM_PAGE_SZ_UNKNOWN;
}

__clib_export void
clib_mem_vm_randomize_va (uword *requested_va,
			  clib_mem_page_sz_t log2_page_size)
{
  /* TODO: Not yet implemented */
}

/* File-backed shared mappings avoid Linux memfd and hugepage dependencies. */
__clib_export int
clib_mem_vm_create_fd (clib_mem_page_sz_t page_sz, char *fmt, ...)
{
  (void) fmt;
  if (page_sz != CLIB_MEM_PAGE_SZ_DEFAULT && page_sz != clib_mem_main.log2_page_sz)
    {
      errno = ENOTSUP;
      clib_mem_main.error = clib_error_return_unix (0, "Darwin huge pages");
      return CLIB_MEM_ERROR;
    }
  char path[] = "/tmp/vpp-shared-XXXXXX";
  int fd = mkstemp (path);
  if (fd >= 0)
    {
      unlink (path);
      fcntl (fd, F_SETFD, FD_CLOEXEC);
    }
  else
    clib_mem_main.error = clib_error_return_unix (0, "mkstemp");
  return fd;
}

__clib_export clib_mem_vm_map_hdr_t *
clib_mem_vm_get_next_map_hdr (clib_mem_vm_map_hdr_t * hdr)
{
  clib_mem_main_t *mm = &clib_mem_main;
  uword sys_page_sz = 1ULL << mm->log2_page_sz;
  clib_mem_vm_map_hdr_t *next;
  if (hdr == 0)
    {
      hdr = mm->first_map;
      if (hdr)
	mprotect (hdr, sys_page_sz, PROT_READ);
      return hdr;
    }
  next = hdr->next;
  mprotect (hdr, sys_page_sz, PROT_NONE);
  if (next)
    mprotect (next, sys_page_sz, PROT_READ);
  return next;
}

void *
clib_mem_vm_map_internal (void *base, clib_mem_page_sz_t log2_page_sz,
			  uword size, int fd, u8 log2_align, uword offset,
			  char *name)
{
  clib_mem_main_t *mm = &clib_mem_main;
  clib_mem_vm_map_hdr_t *hdr;
  uword sys_page_sz = 1ULL << mm->log2_page_sz;
  int mmap_flags = MAP_FIXED, is_huge = 0;

  if (fd != -1)
    {
      mmap_flags |= MAP_SHARED;
      log2_page_sz = clib_mem_get_fd_log2_page_size (fd);
      if (log2_page_sz > mm->log2_page_sz)
	is_huge = 1;
    }
  else
    {
      mmap_flags |= MAP_PRIVATE | MAP_ANONYMOUS;

      if (log2_page_sz == mm->log2_page_sz)
	log2_page_sz = CLIB_MEM_PAGE_SZ_DEFAULT;

      switch (log2_page_sz)
	{
	case CLIB_MEM_PAGE_SZ_UNKNOWN:
	  /* will fail later */
	  break;
	case CLIB_MEM_PAGE_SZ_DEFAULT:
	  log2_page_sz = mm->log2_page_sz;
	  break;
	case CLIB_MEM_PAGE_SZ_DEFAULT_HUGE:
	  /* We shouldn't be selecting HUGETLB on Darwin */
	  log2_page_sz = CLIB_MEM_PAGE_SZ_UNKNOWN;
	  break;
	default:
	  log2_page_sz = mm->log2_page_sz;
	  break;
	}
    }

  size = round_pow2 (size, 1ULL << log2_page_sz);

  base = (void *) clib_mem_vm_reserve ((uword) base, size, clib_max (log2_page_sz, log2_align));

  if (base == (void *) ~0)
    return CLIB_MEM_VM_MAP_FAILED;

  base = mmap (base, size, PROT_READ | PROT_WRITE, mmap_flags, fd, offset);

  if (base == MAP_FAILED)
    return CLIB_MEM_VM_MAP_FAILED;

  if (is_huge && (mlock (base, size) != 0))
    {
      munmap (base, size);
      return CLIB_MEM_VM_MAP_FAILED;
    }

  hdr = mmap (base - sys_page_sz, sys_page_sz, PROT_READ | PROT_WRITE,
	      MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);

  if (hdr != base - sys_page_sz)
    {
      munmap (base, size);
      return CLIB_MEM_VM_MAP_FAILED;
    }

  map_lock ();

  clib_mem_unpoison (hdr, sys_page_sz);
  hdr->next = 0;
  hdr->prev = mm->last_map;
  snprintf (hdr->name, CLIB_VM_MAP_HDR_NAME_MAX_LEN - 1, "%s", (char *) name);
  hdr->base_addr = (uword) base;
  hdr->log2_page_sz = log2_page_sz;
  hdr->num_pages = size >> log2_page_sz;
  hdr->fd = fd;
  hdr->name[CLIB_VM_MAP_HDR_NAME_MAX_LEN - 1] = 0;

  if (mm->last_map)
    {
      mprotect (mm->last_map, sys_page_sz, PROT_READ | PROT_WRITE);
      mm->last_map->next = hdr;
      mprotect (mm->last_map, sys_page_sz, PROT_NONE);
    }
  else
    mm->first_map = hdr;

  mm->last_map = hdr;

  mprotect (hdr, sys_page_sz, PROT_NONE);

  map_unlock ();

  clib_mem_unpoison (base, size);
  return base;
}

__clib_export int
clib_mem_vm_unmap (void *base)
{
  clib_mem_main_t *mm = &clib_mem_main;
  uword size, sys_page_sz = 1ULL << mm->log2_page_sz;
  clib_mem_vm_map_hdr_t *hdr = base - sys_page_sz;
  ;

  map_lock ();
  if (mprotect (hdr, sys_page_sz, PROT_READ | PROT_WRITE) != 0)
    goto out;

  size = hdr->num_pages << hdr->log2_page_sz;
  if (munmap ((void *) hdr->base_addr, size) != 0)
    goto out;

  if (hdr->next)
    {
      mprotect (hdr->next, sys_page_sz, PROT_READ | PROT_WRITE);
      hdr->next->prev = hdr->prev;
      mprotect (hdr->next, sys_page_sz, PROT_NONE);
    }
  else
    mm->last_map = hdr->prev;

  if (hdr->prev)
    {
      mprotect (hdr->prev, sys_page_sz, PROT_READ | PROT_WRITE);
      hdr->prev->next = hdr->next;
      mprotect (hdr->prev, sys_page_sz, PROT_NONE);
    }
  else
    mm->first_map = hdr->next;

  map_unlock ();

  if (munmap (hdr, sys_page_sz) != 0)
    return CLIB_MEM_ERROR;

  return 0;
out:
  map_unlock ();
  return CLIB_MEM_ERROR;
}

__clib_export void
clib_mem_get_page_stats (void *start, clib_mem_page_sz_t log2_page_size,
			 uword n_pages, clib_mem_page_stats_t *stats)
{
  int i, *status = 0;
  void **ptr = 0;

  log2_page_size = clib_mem_log2_page_size_validate (log2_page_size);

  vec_validate (status, n_pages - 1);
  vec_validate (ptr, n_pages - 1);

  for (i = 0; i < n_pages; i++)
    ptr[i] = start + (i << log2_page_size);

  clib_memset (stats, 0, sizeof (clib_mem_page_stats_t));
  stats->total = n_pages;
  stats->log2_page_sz = log2_page_size;

  /*
   * TODO: Until Darwin has support for tracking pages in NUMA domains just
   * return that all are unknown for the statsistics.
   */
  stats->unknown = n_pages;

  vec_free (status);
  vec_free (ptr);
}

/* Physical DMA addresses are unavailable in this userspace-only build. */
__clib_export u64 *
clib_mem_vm_get_paddr (void *mem, clib_mem_page_sz_t page_sz, int n_pages)
{
  (void) mem; (void) page_sz; (void) n_pages;
  errno = ENOTSUP;
  return 0;
}

__clib_export int
clib_mem_set_numa_affinity (u8 numa_node, int force)
{
  /* TODO: Not yet implemented */
  return CLIB_MEM_ERROR;
}

__clib_export int
clib_mem_set_default_numa_affinity ()
{
  /* TODO: Not yet implemented */
  return 0;
}
