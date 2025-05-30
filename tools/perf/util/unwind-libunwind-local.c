// SPDX-License-Identifier: GPL-2.0
/*
 * Post mortem Dwarf CFI based unwinding on top of regs and stack dumps.
 *
 * Lots of this code have been borrowed or heavily inspired from parts of
 * the libunwind 0.99 code which are (amongst other contributors I may have
 * forgotten):
 *
 * Copyright (C) 2002-2007 Hewlett-Packard Co
 *	Contributed by David Mosberger-Tang <davidm@hpl.hp.com>
 *
 * And the bugs have been added by:
 *
 * Copyright (C) 2010, Frederic Weisbecker <fweisbec@gmail.com>
 * Copyright (C) 2012, Jiri Olsa <jolsa@redhat.com>
 *
 */

#include <elf.h>
#include <errno.h>
#include <gelf.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <linux/list.h>
#include <linux/zalloc.h>
#ifndef REMOTE_UNWIND_LIBUNWIND
#include <libunwind.h>
#include <libunwind-ptrace.h>
#endif
#include "callchain.h"
#include "thread.h"
#include "session.h"
#include "perf_regs.h"
#include "unwind.h"
#include "map.h"
#include "symbol.h"
#include "debug.h"
#include "asm/bug.h"
#include "dso.h"

extern int
UNW_OBJ(dwarf_search_unwind_table) (unw_addr_space_t as,
				    unw_word_t ip,
				    unw_dyn_info_t *di,
				    unw_proc_info_t *pi,
				    int need_unwind_info, void *arg);

#define dwarf_search_unwind_table UNW_OBJ(dwarf_search_unwind_table)

extern int
UNW_OBJ(dwarf_find_debug_frame) (int found, unw_dyn_info_t *di_debug,
				 unw_word_t ip,
				 unw_word_t segbase,
				 const char *obj_name, unw_word_t start,
				 unw_word_t end);

#define dwarf_find_debug_frame UNW_OBJ(dwarf_find_debug_frame)

#define DW_EH_PE_FORMAT_MASK	0x0f	/* format of the encoded value */
#define DW_EH_PE_APPL_MASK	0x70	/* how the value is to be applied */

/* Pointer-encoding formats: */
#define DW_EH_PE_omit		0xff
#define DW_EH_PE_ptr		0x00	/* pointer-sized unsigned value */
#define DW_EH_PE_udata4		0x03	/* unsigned 32-bit value */
#define DW_EH_PE_udata8		0x04	/* unsigned 64-bit value */
#define DW_EH_PE_sdata4		0x0b	/* signed 32-bit value */
#define DW_EH_PE_sdata8		0x0c	/* signed 64-bit value */

/* Pointer-encoding application: */
#define DW_EH_PE_absptr		0x00	/* absolute value */
#define DW_EH_PE_pcrel		0x10	/* rel. to addr. of encoded value */

/*
 * The following are not documented by LSB v1.3, yet they are used by
 * GCC, presumably they aren't documented by LSB since they aren't
 * used on Linux:
 */
#define DW_EH_PE_funcrel	0x40	/* start-of-procedure-relative */
#define DW_EH_PE_aligned	0x50	/* aligned pointer */

/* Flags intentionally not handled, since they're not needed:
 * #define DW_EH_PE_indirect      0x80
 * #define DW_EH_PE_uleb128       0x01
 * #define DW_EH_PE_udata2        0x02
 * #define DW_EH_PE_sleb128       0x09
 * #define DW_EH_PE_sdata2        0x0a
 * #define DW_EH_PE_textrel       0x20
 * #define DW_EH_PE_datarel       0x30
 */

struct unwind_info {
	struct perf_sample	*sample;
	struct machine		*machine;
	struct thread		*thread;
	bool			 best_effort;
};

#define dw_read(ptr, type, end) ({	\
	type *__p = (type *) ptr;	\
	type  __v;			\
	if ((__p + 1) > (type *) end)	\
		return -EINVAL;		\
	__v = *__p++;			\
	ptr = (typeof(ptr)) __p;	\
	__v;				\
	})

static int __dw_read_encoded_value(u8 **p, u8 *end, u64 *val,
				   u8 encoding)
{
	u8 *cur = *p;
	*val = 0;

	switch (encoding) {
	case DW_EH_PE_omit:
		*val = 0;
		goto out;
	case DW_EH_PE_ptr:
		*val = dw_read(cur, unsigned long, end);
		goto out;
	default:
		break;
	}

	switch (encoding & DW_EH_PE_APPL_MASK) {
	case DW_EH_PE_absptr:
		break;
	case DW_EH_PE_pcrel:
		*val = (unsigned long) cur;
		break;
	default:
		return -EINVAL;
	}

	if ((encoding & 0x07) == 0x00)
		encoding |= DW_EH_PE_udata4;

	switch (encoding & DW_EH_PE_FORMAT_MASK) {
	case DW_EH_PE_sdata4:
		*val += dw_read(cur, s32, end);
		break;
	case DW_EH_PE_udata4:
		*val += dw_read(cur, u32, end);
		break;
	case DW_EH_PE_sdata8:
		*val += dw_read(cur, s64, end);
		break;
	case DW_EH_PE_udata8:
		*val += dw_read(cur, u64, end);
		break;
	default:
		return -EINVAL;
	}

 out:
	*p = cur;
	return 0;
}

#define dw_read_encoded_value(ptr, end, enc) ({			\
	u64 __v;						\
	if (__dw_read_encoded_value(&ptr, end, &__v, enc)) {	\
		return -EINVAL;                                 \
	}                                                       \
	__v;                                                    \
	})

static int elf_section_address_and_offset(int fd, const char *name, u64 *address, u64 *offset)
{
	Elf *elf;
	GElf_Ehdr ehdr;
	GElf_Shdr shdr;
	int ret = -1;

	elf = elf_begin(fd, PERF_ELF_C_READ_MMAP, NULL);
	if (elf == NULL)
		return -1;

	if (gelf_getehdr(elf, &ehdr) == NULL)
		goto out_err;

	if (!elf_section_by_name(elf, &ehdr, &shdr, name, NULL))
		goto out_err;

	*address = shdr.sh_addr;
	*offset = shdr.sh_offset;
	ret = 0;
out_err:
	elf_end(elf);
	return ret;
}

#ifndef NO_LIBUNWIND_DEBUG_FRAME
static u64 elf_section_offset(int fd, const char *name)
{
	u64 address, offset = 0;

	if (elf_section_address_and_offset(fd, name, &address, &offset))
		return 0;

	return offset;
}
#endif

static u64 elf_base_address(int fd)
{
	Elf *elf = elf_begin(fd, PERF_ELF_C_READ_MMAP, NULL);
	GElf_Phdr phdr;
	u64 retval = 0;
	size_t i, phdrnum = 0;

	if (elf == NULL)
		return 0;
	(void)elf_getphdrnum(elf, &phdrnum);
	/* PT_LOAD segments are sorted by p_vaddr, so the first has the minimum p_vaddr. */
	for (i = 0; i < phdrnum; i++) {
		if (gelf_getphdr(elf, i, &phdr) && phdr.p_type == PT_LOAD) {
			retval = phdr.p_vaddr & -getpagesize();
			break;
		}
	}

	elf_end(elf);
	return retval;
}

#ifndef NO_LIBUNWIND_DEBUG_FRAME
static int elf_is_exec(int fd, const char *name)
{
	Elf *elf;
	GElf_Ehdr ehdr;
	int retval = 0;

	elf = elf_begin(fd, PERF_ELF_C_READ_MMAP, NULL);
	if (elf == NULL)
		return 0;
	if (gelf_getehdr(elf, &ehdr) == NULL)
		goto out;

	retval = (ehdr.e_type == ET_EXEC);

out:
	elf_end(elf);
	pr_debug("unwind: elf_is_exec(%s): %d\n", name, retval);
	return retval;
}
#endif

struct table_entry {
	u32 start_ip_offset;
	u32 fde_offset;
};

struct eh_frame_hdr {
	unsigned char version;
	unsigned char eh_frame_ptr_enc;
	unsigned char fde_count_enc;
	unsigned char table_enc;

	/*
	 * The rest of the header is variable-length and consists of the
	 * following members:
	 *
	 *	encoded_t eh_frame_ptr;
	 *	encoded_t fde_count;
	 */

	/* A single encoded pointer should not be more than 8 bytes. */
	u64 enc[2];

	/*
	 * struct {
	 *    encoded_t start_ip;
	 *    encoded_t fde_addr;
	 * } binary_search_table[fde_count];
	 */
	char data[];
} __packed;

static int unwind_spec_ehframe(struct dso *dso, struct machine *machine,
			       u64 offset, u64 *table_data_offset, u64 *fde_count)
{
	struct eh_frame_hdr hdr;
	u8 *enc = (u8 *) &hdr.enc;
	u8 *end = (u8 *) &hdr.data;
	ssize_t r;

	r = dso__data_read_offset(dso, machine, offset,
				  (u8 *) &hdr, sizeof(hdr));
	if (r != sizeof(hdr))
		return -EINVAL;

	/* We dont need eh_frame_ptr, just skip it. */
	dw_read_encoded_value(enc, end, hdr.eh_frame_ptr_enc);

	*fde_count  = dw_read_encoded_value(enc, end, hdr.fde_count_enc);
	*table_data_offset = enc - (u8 *) &hdr;
	return 0;
}

struct read_unwind_spec_eh_frame_maps_cb_args {
	struct dso *dso;
	u64 base_addr;
};

static int read_unwind_spec_eh_frame_maps_cb(struct map *map, void *data)
{

	struct read_unwind_spec_eh_frame_maps_cb_args *args = data;

	if (map__dso(map) == args->dso && map__start(map) - map__pgoff(map) < args->base_addr)
		args->base_addr = map__start(map) - map__pgoff(map);

	return 0;
}


static int read_unwind_spec_eh_frame(struct dso *dso, struct unwind_info *ui,
				     u64 *table_data, u64 *segbase,
				     u64 *fde_count)
{
	struct read_unwind_spec_eh_frame_maps_cb_args args = {
		.dso = dso,
		.base_addr = UINT64_MAX,
	};
	int ret, fd;

	if (dso__data(dso)->eh_frame_hdr_offset == 0) {
		if (!dso__data_get_fd(dso, ui->machine, &fd))
			return -EINVAL;

		/* Check the .eh_frame section for unwinding info */
		ret = elf_section_address_and_offset(fd, ".eh_frame_hdr",
						     &dso__data(dso)->eh_frame_hdr_addr,
						     &dso__data(dso)->eh_frame_hdr_offset);
		dso__data(dso)->elf_base_addr = elf_base_address(fd);
		dso__data_put_fd(dso);
		if (ret || dso__data(dso)->eh_frame_hdr_offset == 0)
			return -EINVAL;
	}

	maps__for_each_map(thread__maps(ui->thread), read_unwind_spec_eh_frame_maps_cb, &args);

	args.base_addr -= dso__data(dso)->elf_base_addr;
	/* Address of .eh_frame_hdr */
	*segbase = args.base_addr + dso__data(dso)->eh_frame_hdr_addr;
	ret = unwind_spec_ehframe(dso, ui->machine, dso__data(dso)->eh_frame_hdr_offset,
				   table_data, fde_count);
	if (ret)
		return ret;
	/* binary_search_table offset plus .eh_frame_hdr address */
	*table_data += *segbase;
	return 0;
}

#ifndef NO_LIBUNWIND_DEBUG_FRAME
static int read_unwind_spec_debug_frame(struct dso *dso,
					struct machine *machine, u64 *offset)
{
	int fd;
	u64 ofs = dso__data(dso)->debug_frame_offset;

	/* debug_frame can reside in:
	 *  - dso
	 *  - debug pointed by symsrc_filename
	 *  - gnu_debuglink, which doesn't necessary
	 *    has to be pointed by symsrc_filename
	 */
	if (ofs == 0) {
		if (dso__data_get_fd(dso, machine, &fd)) {
			ofs = elf_section_offset(fd, ".debug_frame");
			dso__data_put_fd(dso);
		}

		if (ofs <= 0) {
			fd = open(dso__symsrc_filename(dso), O_RDONLY);
			if (fd >= 0) {
				ofs = elf_section_offset(fd, ".debug_frame");
				close(fd);
			}
		}

		if (ofs <= 0) {
			char *debuglink = malloc(PATH_MAX);
			int ret = 0;

			if (debuglink == NULL) {
				pr_err("unwind: Can't read unwind spec debug frame.\n");
				return -ENOMEM;
			}

			ret = dso__read_binary_type_filename(
				dso, DSO_BINARY_TYPE__DEBUGLINK,
				machine->root_dir, debuglink, PATH_MAX);
			if (!ret) {
				fd = open(debuglink, O_RDONLY);
				if (fd >= 0) {
					ofs = elf_section_offset(fd,
							".debug_frame");
					close(fd);
				}
			}
			if (ofs > 0) {
				if (dso__symsrc_filename(dso) != NULL) {
					pr_warning(
						"%s: overwrite symsrc(%s,%s)\n",
							__func__,
							dso__symsrc_filename(dso),
							debuglink);
					dso__free_symsrc_filename(dso);
				}
				dso__set_symsrc_filename(dso, debuglink);
			} else {
				free(debuglink);
			}
		}

		dso__data(dso)->debug_frame_offset = ofs;
	}

	*offset = ofs;
	if (*offset)
		return 0;

	return -EINVAL;
}
#endif

static struct map *find_map(unw_word_t ip, struct unwind_info *ui)
{
	struct addr_location al;
	struct map *ret;

	addr_location__init(&al);
	thread__find_map(ui->thread, PERF_RECORD_MISC_USER, ip, &al);
	ret = map__get(al.map);
	addr_location__exit(&al);
	return ret;
}

static int
find_proc_info(unw_addr_space_t as, unw_word_t ip, unw_proc_info_t *pi,
	       int need_unwind_info, void *arg)
{
	struct unwind_info *ui = arg;
	struct map *map;
	struct dso *dso;
	unw_dyn_info_t di;
	u64 table_data, segbase, fde_count;
	int ret = -EINVAL;

	map = find_map(ip, ui);
	if (!map)
		return -EINVAL;

	dso = map__dso(map);
	if (!dso) {
		map__put(map);
		return -EINVAL;
	}

	pr_debug("unwind: find_proc_info dso %s\n", dso__name(dso));

	/* Check the .eh_frame section for unwinding info */
	if (!read_unwind_spec_eh_frame(dso, ui, &table_data, &segbase, &fde_count)) {
		memset(&di, 0, sizeof(di));
		di.format   = UNW_INFO_FORMAT_REMOTE_TABLE;
		di.start_ip = map__start(map);
		di.end_ip   = map__end(map);
		di.u.rti.segbase    = segbase;
		di.u.rti.table_data = table_data;
		di.u.rti.table_len  = fde_count * sizeof(struct table_entry)
				      / sizeof(unw_word_t);
		ret = dwarf_search_unwind_table(as, ip, &di, pi,
						need_unwind_info, arg);
	}

#ifndef NO_LIBUNWIND_DEBUG_FRAME
	/* Check the .debug_frame section for unwinding info */
	if (ret < 0 &&
	    !read_unwind_spec_debug_frame(dso, ui->machine, &segbase)) {
		int fd;
		u64 start = map__start(map);
		unw_word_t base = start;
		const char *symfile;

		if (dso__data_get_fd(dso, ui->machine, &fd)) {
			if (elf_is_exec(fd, dso__name(dso)))
				base = 0;
			dso__data_put_fd(dso);
		}

		symfile = dso__symsrc_filename(dso) ?: dso__name(dso);

		memset(&di, 0, sizeof(di));
		if (dwarf_find_debug_frame(0, &di, ip, base, symfile, start, map__end(map)))
			ret = dwarf_search_unwind_table(as, ip, &di, pi,
							need_unwind_info, arg);
	}
#endif
	map__put(map);
	return ret;
}

static int access_fpreg(unw_addr_space_t __maybe_unused as,
			unw_regnum_t __maybe_unused num,
			unw_fpreg_t __maybe_unused *val,
			int __maybe_unused __write,
			void __maybe_unused *arg)
{
	pr_err("unwind: access_fpreg unsupported\n");
	return -UNW_EINVAL;
}

static int get_dyn_info_list_addr(unw_addr_space_t __maybe_unused as,
				  unw_word_t __maybe_unused *dil_addr,
				  void __maybe_unused *arg)
{
	return -UNW_ENOINFO;
}

static int resume(unw_addr_space_t __maybe_unused as,
		  unw_cursor_t __maybe_unused *cu,
		  void __maybe_unused *arg)
{
	pr_err("unwind: resume unsupported\n");
	return -UNW_EINVAL;
}

static int
get_proc_name(unw_addr_space_t __maybe_unused as,
	      unw_word_t __maybe_unused addr,
		char __maybe_unused *bufp, size_t __maybe_unused buf_len,
		unw_word_t __maybe_unused *offp, void __maybe_unused *arg)
{
	pr_err("unwind: get_proc_name unsupported\n");
	return -UNW_EINVAL;
}

static int access_dso_mem(struct unwind_info *ui, unw_word_t addr,
			  unw_word_t *data)
{
	struct map *map;
	struct dso *dso;
	ssize_t size;

	map = find_map(addr, ui);
	if (!map) {
		pr_debug("unwind: no map for %lx\n", (unsigned long)addr);
		return -1;
	}

	dso = map__dso(map);

	if (!dso) {
		map__put(map);
		return -1;
	}

	size = dso__data_read_addr(dso, map, ui->machine,
				   addr, (u8 *) data, sizeof(*data));
	map__put(map);
	return !(size == sizeof(*data));
}

static int access_mem(unw_addr_space_t __maybe_unused as,
		      unw_word_t addr, unw_word_t *valp,
		      int __write, void *arg)
{
	struct unwind_info *ui = arg;
	const char *arch = perf_env__arch(ui->machine->env);
	struct stack_dump *stack = &ui->sample->user_stack;
	u64 start, end;
	int offset;
	int ret;

	/* Don't support write, probably not needed. */
	if (__write || !stack || !ui->sample->user_regs || !ui->sample->user_regs->regs) {
		*valp = 0;
		return 0;
	}

	ret = perf_reg_value(&start, perf_sample__user_regs(ui->sample),
			     perf_arch_reg_sp(arch));
	if (ret)
		return ret;

	end = start + stack->size;

	/* Check overflow. */
	if (addr + sizeof(unw_word_t) < addr)
		return -EINVAL;

	if (addr < start || addr + sizeof(unw_word_t) >= end) {
		ret = access_dso_mem(ui, addr, valp);
		if (ret) {
			pr_debug("unwind: access_mem %p not inside range"
				 " 0x%" PRIx64 "-0x%" PRIx64 "\n",
				 (void *) (uintptr_t) addr, start, end);
			*valp = 0;
			return ret;
		}
		return 0;
	}

	offset = addr - start;
	*valp  = *(unw_word_t *)&stack->data[offset];
	pr_debug("unwind: access_mem addr %p val %lx, offset %d\n",
		 (void *) (uintptr_t) addr, (unsigned long)*valp, offset);
	return 0;
}

static int access_reg(unw_addr_space_t __maybe_unused as,
		      unw_regnum_t regnum, unw_word_t *valp,
		      int __write, void *arg)
{
	struct unwind_info *ui = arg;
	int id, ret;
	u64 val;

	/* Don't support write, I suspect we don't need it. */
	if (__write) {
		pr_err("unwind: access_reg w %d\n", regnum);
		return 0;
	}

	if (!ui->sample->user_regs || !ui->sample->user_regs->regs) {
		*valp = 0;
		return 0;
	}

	id = LIBUNWIND__ARCH_REG_ID(regnum);
	if (id < 0)
		return -EINVAL;

	ret = perf_reg_value(&val, perf_sample__user_regs(ui->sample), id);
	if (ret) {
		if (!ui->best_effort)
			pr_err("unwind: can't read reg %d\n", regnum);
		return ret;
	}

	*valp = (unw_word_t) val;
	pr_debug("unwind: reg %d, val %lx\n", regnum, (unsigned long)*valp);
	return 0;
}

static void put_unwind_info(unw_addr_space_t __maybe_unused as,
			    unw_proc_info_t *pi __maybe_unused,
			    void *arg __maybe_unused)
{
	pr_debug("unwind: put_unwind_info called\n");
}

static int entry(u64 ip, struct thread *thread,
		 unwind_entry_cb_t cb, void *arg)
{
	struct unwind_entry e;
	struct addr_location al;
	int ret;

	addr_location__init(&al);
	e.ms.sym = thread__find_symbol(thread, PERF_RECORD_MISC_USER, ip, &al);
	e.ip     = ip;
	e.ms.map = al.map;
	e.ms.maps = al.maps;

	pr_debug("unwind: %s:ip = 0x%" PRIx64 " (0x%" PRIx64 ")\n",
		 al.sym ? al.sym->name : "''",
		 ip,
		 al.map ? map__map_ip(al.map, ip) : (u64) 0);

	ret = cb(&e, arg);
	addr_location__exit(&al);
	return ret;
}

static void display_error(int err)
{
	switch (err) {
	case UNW_EINVAL:
		pr_err("unwind: Only supports local.\n");
		break;
	case UNW_EUNSPEC:
		pr_err("unwind: Unspecified error.\n");
		break;
	case UNW_EBADREG:
		pr_err("unwind: Register unavailable.\n");
		break;
	default:
		break;
	}
}

static unw_accessors_t accessors = {
	.find_proc_info		= find_proc_info,
	.put_unwind_info	= put_unwind_info,
	.get_dyn_info_list_addr	= get_dyn_info_list_addr,
	.access_mem		= access_mem,
	.access_reg		= access_reg,
	.access_fpreg		= access_fpreg,
	.resume			= resume,
	.get_proc_name		= get_proc_name,
};

static int _unwind__prepare_access(struct maps *maps)
{
	void *addr_space = unw_create_addr_space(&accessors, 0);

	maps__set_addr_space(maps, addr_space);
	if (!addr_space) {
		pr_err("unwind: Can't create unwind address space.\n");
		return -ENOMEM;
	}

	unw_set_caching_policy(addr_space, UNW_CACHE_GLOBAL);
	return 0;
}

static void _unwind__flush_access(struct maps *maps)
{
	unw_flush_cache(maps__addr_space(maps), 0, 0);
}

static void _unwind__finish_access(struct maps *maps)
{
	unw_destroy_addr_space(maps__addr_space(maps));
}

static int get_entries(struct unwind_info *ui, unwind_entry_cb_t cb,
		       void *arg, int max_stack)
{
	const char *arch = perf_env__arch(ui->machine->env);
	u64 val;
	unw_word_t ips[max_stack];
	unw_addr_space_t addr_space;
	unw_cursor_t c;
	int ret, i = 0;

	ret = perf_reg_value(&val, perf_sample__user_regs(ui->sample),
			     perf_arch_reg_ip(arch));
	if (ret)
		return ret;

	ips[i++] = (unw_word_t) val;

	/*
	 * If we need more than one entry, do the DWARF
	 * unwind itself.
	 */
	if (max_stack - 1 > 0) {
		WARN_ONCE(!ui->thread, "WARNING: ui->thread is NULL");
		addr_space = maps__addr_space(thread__maps(ui->thread));

		if (addr_space == NULL)
			return -1;

		ret = unw_init_remote(&c, addr_space, ui);
		if (ret && !ui->best_effort)
			display_error(ret);

		while (!ret && (unw_step(&c) > 0) && i < max_stack) {
			unw_get_reg(&c, UNW_REG_IP, &ips[i]);

			/*
			 * Decrement the IP for any non-activation frames.
			 * this is required to properly find the srcline
			 * for caller frames.
			 * See also the documentation for dwfl_frame_pc(),
			 * which this code tries to replicate.
			 */
			if (unw_is_signal_frame(&c) <= 0)
				--ips[i];

			++i;
		}

		max_stack = i;
	}

	/*
	 * Display what we got based on the order setup.
	 */
	for (i = 0; i < max_stack && !ret; i++) {
		int j = i;

		if (callchain_param.order == ORDER_CALLER)
			j = max_stack - i - 1;
		ret = ips[j] ? entry(ips[j], ui->thread, cb, arg) : 0;
	}

	return ret;
}

static int _unwind__get_entries(unwind_entry_cb_t cb, void *arg,
			struct thread *thread,
			struct perf_sample *data, int max_stack,
			bool best_effort)
{
	struct unwind_info ui = {
		.sample       = data,
		.thread       = thread,
		.machine      = maps__machine(thread__maps(thread)),
		.best_effort  = best_effort
	};

	if (!data->user_regs || !data->user_regs->regs)
		return -EINVAL;

	if (max_stack <= 0)
		return -EINVAL;

	return get_entries(&ui, cb, arg, max_stack);
}

static struct unwind_libunwind_ops
_unwind_libunwind_ops = {
	.prepare_access = _unwind__prepare_access,
	.flush_access   = _unwind__flush_access,
	.finish_access  = _unwind__finish_access,
	.get_entries    = _unwind__get_entries,
};

#ifndef REMOTE_UNWIND_LIBUNWIND
struct unwind_libunwind_ops *
local_unwind_libunwind_ops = &_unwind_libunwind_ops;
#endif
