/* SPDX-License-Identifier: Apache-2.0 */
#include <dlfcn.h>
#include <errno.h>
#include <vppinfra/elf_clib.h>
#include <vppinfra/format.h>

/* Preserve the diagnostics API while obtaining symbols from Mach-O/dyld. */
static char *darwin_exec_path;

__clib_export void
clib_elf_main_init (char *exec_path)
{
  darwin_exec_path = exec_path;
}

__clib_export clib_elf_section_bounds_t *
clib_elf_get_section_bounds (char *name)
{
  (void) name;
  errno = ENOTSUP;
  return 0;
}

__clib_export uword
clib_elf_symbol_by_address (uword address, clib_elf_symbol_t *result)
{
  Dl_info info;
  if (!dladdr ((void *) address, &info) || !info.dli_sname)
    return 0;
  clib_memset (result, 0, sizeof (*result));
  result->symbol.value = (uword) info.dli_saddr;
  return 1;
}

__clib_export uword
clib_elf_symbol_by_name (char *name, clib_elf_symbol_t *result)
{
  void *address = dlsym (RTLD_DEFAULT, name);
  return address && clib_elf_symbol_by_address ((uword) address, result);
}

__clib_export const char *
clib_elf_symbol_name (clib_elf_symbol_t *symbol)
{
  Dl_info info;
  return dladdr ((void *) symbol->symbol.value, &info) ? info.dli_sname : 0;
}

__clib_export u8 *
format_clib_elf_symbol (u8 *s, va_list *args)
{
  clib_elf_symbol_t *symbol = va_arg (*args, clib_elf_symbol_t *);
  if (!symbol)
    return format (s, "Mach-O symbol");
  const char *name = clib_elf_symbol_name (symbol);
  return format (s, "%s", name ? name : "unknown");
}

__clib_export u8 *
format_clib_elf_symbol_with_address (u8 *s, va_list *args)
{
  uword address = va_arg (*args, uword);
  Dl_info info;
  if (dladdr ((void *) address, &info) && info.dli_sname)
    return format (s, "%s + 0x%lx", info.dli_sname,
                   address - (uword) info.dli_saddr);
  return format (s, "%s: 0x%lx",
                 darwin_exec_path ? darwin_exec_path : "unknown", address);
}
