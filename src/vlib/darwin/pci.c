/* SPDX-License-Identifier: Apache-2.0 */
#include <vlib/vlib.h>
#include <vlib/pci/pci.h>

/* No userspace PCI access or hardware drivers in the Darwin build. */
vlib_pci_addr_t *
vlib_pci_get_addr (vlib_main_t *vm, vlib_pci_dev_handle_t h)
{
  (void) vm; (void) h;
  return 0;
}

clib_error_t *
vlib_pci_read_write_config (vlib_main_t *vm, vlib_pci_dev_handle_t h,
                            vlib_read_or_write_t op, uword address, void *data,
                            u32 n_bytes)
{
  (void) vm; (void) h; (void) op; (void) address; (void) data; (void) n_bytes;
  return clib_error_return (0, "PCI access is not supported on Darwin");
}
