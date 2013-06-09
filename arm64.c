/*
 * arm64.c - core analysis suite
 *
 * Copyright (C) 2012,2013 David Anderson
 * Copyright (C) 2012,2013 Red Hat, Inc. All rights reserved.
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
 */

#ifdef ARM64

#include "defs.h"
#include <elf.h>

#define NOT_IMPLEMENTED(X) error((X), "%s: function not implemented\n", __func__)

static struct machine_specific arm64_machine_specific = { 0 };
static int arm64_verify_symbol(const char *, ulong, char);
static void arm64_parse_cmdline_args(void);
static void arm64_calc_phys_offset(void);
static int arm64_kdump_phys_base(ulong *);
static int arm64_eframe_search(struct bt_info *);
static void arm64_back_trace_cmd(struct bt_info *);
static ulong arm64_processor_speed(void);
static int arm64_uvtop(struct task_context *, ulong, physaddr_t *, int);
static int arm64_kvtop(struct task_context *, ulong, physaddr_t *, int);
static ulong arm64_get_task_pgd(ulong);
static void arm64_get_stack_frame(struct bt_info *, ulong *, ulong *);
static int arm64_translate_pte(ulong, void *, ulonglong);
static ulong arm64_vmalloc_start(void);
static int arm64_is_task_addr(ulong);
static int arm64_dis_filter(ulong, char *, unsigned int);
static void arm64_cmd_mach(void);
static void arm64_display_machine_stats(void);
static int arm64_get_smp_cpus(void);
static void arm64_clear_machdep_cache(void);
static int arm64_in_alternate_stack(int, ulong);
static int arm64_get_kvaddr_ranges(struct vaddr_range *);
static int arm64_get_crash_notes(void);

/*
 * Do all necessary machine-specific setup here. This is called several times
 * during initialization.
 */
void
arm64_init(int when)
{
	ulong value;

#if defined(__x86_64__)
	if (ACTIVE())
		error(FATAL, "compiled for the ARM architecture\n");
#endif

	switch (when) {
	case PRE_SYMTAB:
		machdep->machspec = &arm64_machine_specific;
		machdep->process_elf_notes = process_elf64_notes;
		if (pc->flags & KERNEL_DEBUG_QUERY)
			return;
		machdep->verify_paddr = generic_verify_paddr;
		machdep->verify_symbol = arm64_verify_symbol;
		if (machdep->cmdline_args[0])
			arm64_parse_cmdline_args();
		break;

	case PRE_GDB:
		if (kernel_symbol_exists("swapper_pg_dir") &&
		    kernel_symbol_exists("idmap_pg_dir")) {
			value = symbol_value("swapper_pg_dir") -
				symbol_value("idmap_pg_dir");
			machdep->pagesize = value / 2;
		} else
			machdep->pagesize = memory_page_size();   /* host */
		machdep->pageshift = ffs(machdep->pagesize) - 1;
		machdep->pageoffset = machdep->pagesize - 1;
		machdep->pagemask = ~((ulonglong)machdep->pageoffset);
		switch (machdep->pagesize)
		{
		case 4096:
			machdep->ptrs_per_pgd = PTRS_PER_PGD_4K;
			if ((machdep->pgd = 
			    (char *)malloc(PTRS_PER_PGD_4K * 8)) == NULL)
				error(FATAL, "cannot malloc pgd space.");
			if ((machdep->pmd = 
			    (char *)malloc(PTRS_PER_PMD_4K * 8)) == NULL)
				error(FATAL, "cannot malloc pmd space.");
			if ((machdep->ptbl = 
			    (char *)malloc(PTRS_PER_PTE_4K * 8)) == NULL)
				error(FATAL, "cannot malloc ptbl space.");
			machdep->pud = NULL;  /* not used */
			break;

		case 65536:
			machdep->ptrs_per_pgd = PTRS_PER_PGD_64K;
			if ((machdep->pgd = 
			    (char *)malloc(PTRS_PER_PGD_64K * 8)) == NULL)
				error(FATAL, "cannot malloc pgd space.");
			if ((machdep->ptbl = 
			    (char *)malloc(PTRS_PER_PTE_64K * 8)) == NULL)
				error(FATAL, "cannot malloc ptbl space.");
			machdep->pmd = NULL;  /* not used */
			machdep->pud = NULL;  /* not used */
			break;

		default:
			error(FATAL, "invalid/unknown page size: %d\n", 
				machdep->pagesize);
		}
		machdep->last_pud_read = 0;  /* not used */
		machdep->last_pgd_read = 0;
		machdep->last_pmd_read = 0;
		machdep->last_ptbl_read = 0;
		machdep->clear_machdep_cache = arm64_clear_machdep_cache;

		machdep->stacksize = ARM64_STACK_SIZE;
		machdep->machspec->userspace_top = ARM64_USERSPACE_TOP;
		machdep->machspec->page_offset = ARM64_PAGE_OFFSET;
		machdep->machspec->vmalloc_start_addr = ARM64_VMALLOC_START;
		machdep->machspec->vmalloc_end = ARM64_VMALLOC_END;
		machdep->machspec->vmemmap_vaddr = ARM64_VMEMMAP_VADDR;
		machdep->machspec->vmemmap_end = ARM64_VMEMMAP_END;
		machdep->machspec->modules_vaddr = ARM64_MODULES_VADDR;
		machdep->machspec->modules_end = ARM64_MODULES_END;

		machdep->kvbase = ARM64_VMALLOC_START;
		machdep->identity_map_base = ARM64_PAGE_OFFSET; 

		arm64_calc_phys_offset();
		
		machdep->is_kvaddr = generic_is_kvaddr;
		machdep->is_uvaddr = generic_is_uvaddr;
		machdep->eframe_search = arm64_eframe_search;
		machdep->back_trace = arm64_back_trace_cmd;
		machdep->in_alternate_stack = arm64_in_alternate_stack;
		machdep->processor_speed = arm64_processor_speed;
		machdep->uvtop = arm64_uvtop;
		machdep->kvtop = arm64_kvtop;
		machdep->get_task_pgd = arm64_get_task_pgd;
		machdep->get_stack_frame = arm64_get_stack_frame;
		machdep->get_stackbase = generic_get_stackbase;
		machdep->get_stacktop = generic_get_stacktop;
		machdep->translate_pte = arm64_translate_pte;
		machdep->memory_size = generic_memory_size;
		machdep->vmalloc_start = arm64_vmalloc_start;
		machdep->get_kvaddr_ranges = arm64_get_kvaddr_ranges;
		machdep->is_task_addr = arm64_is_task_addr;
		machdep->dis_filter = arm64_dis_filter;
		machdep->cmd_mach = arm64_cmd_mach;
		machdep->get_smp_cpus = arm64_get_smp_cpus;
		machdep->line_number_hooks = NULL;
		machdep->value_to_symbol = generic_machdep_value_to_symbol;
		machdep->init_kernel_pgd = NULL;
		machdep->dump_irq = generic_dump_irq;
		machdep->show_interrupts = generic_show_interrupts;
		machdep->get_irq_affinity = generic_get_irq_affinity;
		machdep->dumpfile_init = NULL;
		machdep->verify_line_number = NULL;
		break;

	case POST_GDB:
		machdep->section_size_bits = _SECTION_SIZE_BITS;
		machdep->max_physmem_bits = _MAX_PHYSMEM_BITS;

		if (symbol_exists("irq_desc"))
			ARRAY_LENGTH_INIT(machdep->nr_irqs, irq_desc,
				  "irq_desc", NULL, 0);
		else if (kernel_symbol_exists("nr_irqs"))
			get_symbol_data("nr_irqs", sizeof(unsigned int),
				&machdep->nr_irqs);

		if (!machdep->hz)
			machdep->hz = 100;

		STRUCT_SIZE_INIT(note_buf, "note_buf_t");
		STRUCT_SIZE_INIT(elf_prstatus, "elf_prstatus");
		MEMBER_OFFSET_INIT(elf_prstatus_pr_pid, 
			"elf_prstatus", "pr_pid");
		MEMBER_OFFSET_INIT(elf_prstatus_pr_reg, 
			"elf_prstatus", "pr_reg");
		break;

	case POST_VM:
		/*
		 * crash_notes contains machine specific information about the
		 * crash. In particular, it contains CPU registers at the time
		 * of the crash. We need this information to extract correct
		 * backtraces from the panic task.
		 */
		if (!ACTIVE() && !arm64_get_crash_notes())
			error(WARNING, "could not retrieve crash_notes\n");

		break;

	case LOG_ONLY:
		machdep->machspec = &arm64_machine_specific;
		machdep->identity_map_base = ARM64_PAGE_OFFSET;
		arm64_calc_phys_offset();
		break;
	}
}

/*
 * Accept or reject a symbol from the kernel namelist.
 */
static int
arm64_verify_symbol(const char *name, ulong value, char type)
{
//	if (STREQ(name, "swapper_pg_dir"))
//		machdep->flags |= KSYMS_START;
//
//	if (!name || !strlen(name) || !(machdep->flags & KSYMS_START))
//		return FALSE;
//
//	if (STREQ(name, "$a") || STREQ(name, "$n") || STREQ(name, "$d"))
//		return FALSE;
//
//	if (STREQ(name, "PRRR") || STREQ(name, "NMRR"))
//		return FALSE;
//
//	if ((type == 'A') && STRNEQ(name, "__crc_"))
//		return FALSE;
//
//	if (CRASHDEBUG(8) && name && strlen(name))
//		fprintf(fp, "%08lx %s\n", value, name);
//
	NOT_IMPLEMENTED(WARNING);
	return TRUE;
}


void
arm64_dump_machdep_table(ulong arg)
{
	const struct machine_specific *ms;
	int others, i;

	others = 0;
	fprintf(fp, "               flags: %lx (", machdep->flags);
	if (machdep->flags & KSYMS_START)
		fprintf(fp, "%sKSYMS_START", others++ ? "|" : "");
	if (machdep->flags & PHYS_OFFSET)
		fprintf(fp, "%sPHYS_OFFSET", others++ ? "|" : "");
	fprintf(fp, ")\n");

	fprintf(fp, "              kvbase: %lx\n", machdep->kvbase);
	fprintf(fp, "   identity_map_base: %lx\n", machdep->kvbase);
	fprintf(fp, "            pagesize: %d\n", machdep->pagesize);
	fprintf(fp, "           pageshift: %d\n", machdep->pageshift);
	fprintf(fp, "            pagemask: %lx\n", (ulong)machdep->pagemask);
	fprintf(fp, "          pageoffset: %lx\n", machdep->pageoffset);
	fprintf(fp, "           stacksize: %ld\n", machdep->stacksize);
	fprintf(fp, "                  hz: %d\n", machdep->hz);
	fprintf(fp, "                 mhz: %ld\n", machdep->mhz);
	fprintf(fp, "             memsize: %lld (0x%llx)\n",
		(ulonglong)machdep->memsize, (ulonglong)machdep->memsize);
	fprintf(fp, "                bits: %d\n", machdep->bits);
	fprintf(fp, "             nr_irqs: %d\n", machdep->nr_irqs);
	fprintf(fp, "       eframe_search: arm64_eframe_search()\n");
	fprintf(fp, "          back_trace: arm64_back_trace_cmd()\n");
	fprintf(fp, "  in_alternate_stack: arm64_in_alternate_stack()\n");
	fprintf(fp, "     processor_speed: arm64_processor_speed()\n");
	fprintf(fp, "               uvtop: arm64_uvtop()\n");
	fprintf(fp, "               kvtop: arm64_kvtop()\n");
	fprintf(fp, "        get_task_pgd: arm64_get_task_pgd()\n");
	fprintf(fp, "            dump_irq: generic_dump_irq()\n");
	fprintf(fp, "     get_stack_frame: arm64_get_stack_frame()\n");
	fprintf(fp, "       get_stackbase: generic_get_stackbase()\n");
	fprintf(fp, "        get_stacktop: generic_get_stacktop()\n");
	fprintf(fp, "       translate_pte: arm64_translate_pte()\n");
	fprintf(fp, "         memory_size: generic_memory_size()\n");
	fprintf(fp, "       vmalloc_start: arm64_vmalloc_start()\n");
	fprintf(fp, "   get_kvaddr_ranges: arm64_get_kvaddr_ranges()\n");
	fprintf(fp, "        is_task_addr: arm64_is_task_addr()\n");
	fprintf(fp, "       verify_symbol: arm64_verify_symbol()\n");
	fprintf(fp, "          dis_filter: arm64_dis_filter()\n");
	fprintf(fp, "            cmd_mach: arm64_cmd_mach()\n");
	fprintf(fp, "        get_smp_cpus: arm64_get_smp_cpus()\n");
	fprintf(fp, "           is_kvaddr: generic_is_kvaddr()\n");
	fprintf(fp, "           is_uvaddr: generic_is_uvaddr()\n");
	fprintf(fp, "     value_to_symbol: generic_machdep_value_to_symbol()\n");
	fprintf(fp, "     init_kernel_pgd: (not used)\n");
	fprintf(fp, "        verify_paddr: generic_verify_paddr()\n");
	fprintf(fp, "     show_interrupts: generic_show_interrupts()\n");
	fprintf(fp, "    get_irq_affinity: generic_get_irq_affinity()\n");
	fprintf(fp, "       dumpfile_init: (not used)\n");
	fprintf(fp, "   process_elf_notes: process_elf64_notes()\n");
	fprintf(fp, "  verify_line_number: (not used)\n");

	fprintf(fp, "  xendump_p2m_create: (n/a)\n");
	fprintf(fp, "xen_kdump_p2m_create: (n/a)\n");
        fprintf(fp, "  xendump_panic_task: (n/a)\n");
        fprintf(fp, "    get_xendump_regs: (n/a)\n");
	fprintf(fp, "   line_number_hooks: (not used)\n");
	fprintf(fp, "       last_pud_read: (not used)\n");
	fprintf(fp, "       last_pgd_read: %lx\n", machdep->last_pgd_read);
	fprintf(fp, "       last_pmd_read: ");
	if (PAGESIZE() == 65536)
		fprintf(fp, "(not used)\n");
	else
		fprintf(fp, "%lx\n", machdep->last_pmd_read);
	fprintf(fp, "      last_ptbl_read: %lx\n", machdep->last_ptbl_read);
	fprintf(fp, " clear_machdep_cache: arm64_clear_machdep_cache()\n");
	fprintf(fp, "                 pgd: %lx\n", (ulong)machdep->pgd);
	fprintf(fp, "                 pmd: %lx\n", (ulong)machdep->pmd);
	fprintf(fp, "                ptbl: %lx\n", (ulong)machdep->ptbl);
	fprintf(fp, "        ptrs_per_pgd: %d\n", machdep->ptrs_per_pgd);
	fprintf(fp, "   section_size_bits: %ld\n", machdep->section_size_bits);
	fprintf(fp, "    max_physmem_bits: %ld\n", machdep->max_physmem_bits);
	fprintf(fp, "   sections_per_root: %ld\n", machdep->sections_per_root);

	for (i = 0; i < MAX_MACHDEP_ARGS; i++) {
		fprintf(fp, "     cmdline_args[%d]: %s\n",
			i, machdep->cmdline_args[i] ?
			machdep->cmdline_args[i] : "(unused)");
	}

	ms = machdep->machspec;

	fprintf(fp, "            machspec: %lx\n", (ulong)ms);
	fprintf(fp, "       userspace_top: %016lx\n", (ulong)ms->userspace_top);
	fprintf(fp, "         page_offset: %016lx\n", (ulong)ms->page_offset);
	fprintf(fp, "  vmalloc_start_addr: %016lx\n", (ulong)ms->vmalloc_start_addr);
	fprintf(fp, "         vmalloc_end: %016lx\n", (ulong)ms->vmalloc_end);
	fprintf(fp, "       modules_vaddr: %016lx\n", (ulong)ms->modules_vaddr);
	fprintf(fp, "         modules_end: %016lx\n", (ulong)ms->modules_end);
	fprintf(fp, "       vmemmap_vaddr: %016lx\n", (ulong)ms->vmemmap_vaddr);
	fprintf(fp, "         phys_offset: %lx\n", ms->phys_offset);
}


/*
 * Parse machine dependent command line arguments.
 *
 * Force the phys_offset address via:
 *
 *  --machdep phys_offset=<address>
 */
static void
arm64_parse_cmdline_args(void)
{
	int index, i, c, err;
	char *arglist[MAXARGS];
	char buf[BUFSIZE];
	char *p;
	ulong value = 0;

	for (index = 0; index < MAX_MACHDEP_ARGS; index++) {
		if (!machdep->cmdline_args[index])
			break;

		if (!strstr(machdep->cmdline_args[index], "=")) {
			error(WARNING, "ignoring --machdep option: %x\n",
				machdep->cmdline_args[index]);
			continue;
		}

		strcpy(buf, machdep->cmdline_args[index]);

		for (p = buf; *p; p++) {
			if (*p == ',')
				*p = ' ';
		}

		c = parse_line(buf, arglist);

		for (i = 0; i < c; i++) {
			err = 0;

			if (STRNEQ(arglist[i], "phys_offset=")) {
				int megabytes = FALSE;
				int flags = RETURN_ON_ERROR | QUIET;

				if ((LASTCHAR(arglist[i]) == 'm') ||
				    (LASTCHAR(arglist[i]) == 'M')) {
					LASTCHAR(arglist[i]) = NULLCHAR;
					megabytes = TRUE;
				}

				p = arglist[i] + strlen("phys_offset=");
				if (strlen(p)) {
					if (megabytes)
						value = dtol(p, flags, &err);
					else
						value = htol(p, flags, &err);
				}

				if (!err) {
					if (megabytes)
						value = MEGABYTES(value);

					machdep->machspec->phys_offset = value;

					error(NOTE,
						"setting phys_offset to: 0x%lx\n",
						machdep->machspec->phys_offset);

					machdep->flags |= PHYS_OFFSET;
					continue;
				}
			}

			error(WARNING, "ignoring --machdep option: %s\n",
				arglist[i]);
		}
	}
}


static void
arm64_calc_phys_offset(void)
{
	struct machine_specific *ms = machdep->machspec;
	ulong phys_offset;

	if (machdep->flags & PHYS_OFFSET) /* --machdep override */
		return;

	/*
	 * Next determine suitable value for phys_offset. User can override this
	 * by passing valid '--machdep phys_offset=<addr>' option.
	 */
	ms->phys_offset = 0;

	if (ACTIVE()) {
		char buf[BUFSIZE];
		char *p1;
		int errflag;
		FILE *fp;

		if ((fp = fopen("/proc/iomem", "r")) == NULL)
			return;

		/*
		 * Memory regions are sorted in ascending order. We take the
		 * first region which should be correct for most uses.
		 */
		errflag = 1;
		while (fgets(buf, BUFSIZE, fp)) {
			if (strstr(buf, ": System RAM")) {
				clean_line(buf);
				errflag = 0;
				break;
			}
		}
		fclose(fp);

		if (errflag)
			return;

		if (!(p1 = strstr(buf, "-")))
			return;

		*p1 = NULLCHAR;

		phys_offset = htol(buf, RETURN_ON_ERROR | QUIET, &errflag);
		if (errflag)
			return;

		ms->phys_offset = phys_offset;
	} else if (DISKDUMP_DUMPFILE() && diskdump_phys_base(&phys_offset)) {
		ms->phys_offset = phys_offset;
	} else if (KDUMP_DUMPFILE() && arm64_kdump_phys_base(&phys_offset)) {
		ms->phys_offset = phys_offset;
	} else {
		error(WARNING,
			"phys_offset cannot be determined from the dumpfile.\n");
		error(CONT,
			"Using default value of 0.  If this is not correct, then try\n");
		error(CONT,
			"using the command line option: --machdep phys_offset=<addr>\n");
	}

	if (CRASHDEBUG(1))
		fprintf(fp, "using %lx as phys_offset\n", ms->phys_offset);
}


/*
 *  Borrow the 32-bit ARM functionality.
 */
static int
arm64_kdump_phys_base(ulong *phys_offset)
{
	return arm_kdump_phys_base(phys_offset);
}

static int arm64_eframe_search(struct bt_info *bt)
{
	return (NOT_IMPLEMENTED(FATAL));
}

static void arm64_back_trace_cmd(struct bt_info *bt)
{
	NOT_IMPLEMENTED(FATAL);
}

static ulong arm64_processor_speed(void) 
{
	NOT_IMPLEMENTED(INFO);
	return 0;
};

static int 
arm64_uvtop(struct task_context *tc, ulong uvaddr, physaddr_t *paddr, int verbose)
{
	return (NOT_IMPLEMENTED(FATAL));
};

static int 
arm64_kvtop(struct task_context *tc, ulong kvaddr, physaddr_t *paddr, int verbose)
{
	if (!IS_KVADDR(kvaddr))
		return FALSE;

	if (!vt->vmalloc_start) {
		*paddr = VTOP(kvaddr);
		return TRUE;
	}

	if (!IS_VMALLOC_ADDR(kvaddr)) {
		*paddr = VTOP(kvaddr);
		if (!verbose)
			return TRUE;
	}

	NOT_IMPLEMENTED(WARNING);
	return FALSE;
}

static ulong 
arm64_get_task_pgd(ulong task)
{
	return (NOT_IMPLEMENTED(FATAL));
}

static void
arm64_get_stack_frame(struct bt_info *bt, ulong *pcp, ulong *spp)
{
	NOT_IMPLEMENTED(FATAL);
}

static int
arm64_translate_pte(ulong pte, void *physaddr, ulonglong unused)
{
	return (NOT_IMPLEMENTED(FATAL));
}

static ulong
arm64_vmalloc_start(void)
{
	return ARM64_VMALLOC_START;
}

/*
 *  Not so accurate since thread_info introduction.
 */
static int
arm64_is_task_addr(ulong task)
{
	if (tt->flags & THREAD_INFO)
		return IS_KVADDR(task);
	else
		return (IS_KVADDR(task) && (ALIGNED_STACK_OFFSET(task) == 0));
}

/*
 * Filter dissassembly output if the output radix is not gdb's default 10
 */
static int
arm64_dis_filter(ulong vaddr, char *inbuf, unsigned int output_radix)
{
	char buf1[BUFSIZE];
	char buf2[BUFSIZE];
	char *colon, *p1;
	int argc;
	char *argv[MAXARGS];
	ulong value;

	if (!inbuf)
		return TRUE;

	console("IN: %s", inbuf);

	colon = strstr(inbuf, ":");

	if (colon) {
		sprintf(buf1, "0x%lx <%s>", vaddr,
			value_to_symstr(vaddr, buf2, output_radix));
		sprintf(buf2, "%s%s", buf1, colon);
		strcpy(inbuf, buf2);
	}

	strcpy(buf1, inbuf);
	argc = parse_line(buf1, argv);

	if ((FIRSTCHAR(argv[argc-1]) == '<') &&
	    (LASTCHAR(argv[argc-1]) == '>')) {
		p1 = rindex(inbuf, '<');
		while ((p1 > inbuf) && !STRNEQ(p1, " 0x"))
			p1--;

		if (!STRNEQ(p1, " 0x"))
			return FALSE;
		p1++;

		if (!extract_hex(p1, &value, NULLCHAR, TRUE))
			return FALSE;

		sprintf(buf1, "0x%lx <%s>\n", value,
			value_to_symstr(value, buf2, output_radix));

		sprintf(p1, buf1);
	}

	console("    %s", inbuf);

	return TRUE;
}

/*
 * Machine dependent command.
 */
static void
arm64_cmd_mach(void)
{
	int c;

	while ((c = getopt(argcnt, args, "cm")) != -1) {
		switch (c) {
		case 'c':
		case 'm':
			option_not_supported(c);
			break;

		default:
			argerrs++;
			break;
		}
	}

	if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);

	arm64_display_machine_stats();
}

static void
arm64_display_machine_stats(void)
{
	struct new_utsname *uts;
	char buf[BUFSIZE];
	ulong mhz;

	uts = &kt->utsname;

	fprintf(fp, "       MACHINE TYPE: %s\n", uts->machine);
	fprintf(fp, "        MEMORY SIZE: %s\n", get_memory_size(buf));
	fprintf(fp, "               CPUS: %d\n", get_cpus_to_display());
	if ((mhz = machdep->processor_speed()))
		fprintf(fp, "    PROCESSOR SPEED: %ld Mhz\n", mhz);
	fprintf(fp, "                 HZ: %d\n", machdep->hz);
	fprintf(fp, "          PAGE SIZE: %d\n", PAGESIZE());
	fprintf(fp, "KERNEL VIRTUAL BASE: %lx\n", ARM64_PAGE_OFFSET);
	fprintf(fp, "KERNEL VMALLOC BASE: %lx\n", ARM64_VMALLOC_START);
	fprintf(fp, "KERNEL MODULES BASE: %lx\n", ARM64_MODULES_VADDR);
	fprintf(fp, "  KERNEL STACK SIZE: %ld\n", STACKSIZE());
}

static int
arm64_get_smp_cpus(void)
{
	return MAX(get_cpus_online(), get_highest_cpu_online()+1);
}


/*
 * Retrieve task registers for the time of the crash.
 */
static int
arm64_get_crash_notes(void)
{
	struct machine_specific *ms = machdep->machspec;
	ulong crash_notes;
	Elf64_Nhdr *note;
	ulong offset;
	char *buf, *p;
	ulong *notes_ptrs;
	ulong i;

	if (!symbol_exists("crash_notes"))
		return FALSE;

	crash_notes = symbol_value("crash_notes");

	notes_ptrs = (ulong *)GETBUF(kt->cpus*sizeof(notes_ptrs[0]));

	/*
	 * Read crash_notes for the first CPU. crash_notes are in standard ELF
	 * note format.
	 */
	if (!readmem(crash_notes, KVADDR, &notes_ptrs[kt->cpus-1], 
	    sizeof(notes_ptrs[kt->cpus-1]), "crash_notes", RETURN_ON_ERROR)) {
		error(WARNING, "cannot read crash_notes\n");
		FREEBUF(notes_ptrs);
		return FALSE;
	}

	if (symbol_exists("__per_cpu_offset")) {
		/* 
		 * Add __per_cpu_offset for each cpu to form the notes pointer.
		 */
		for (i = 0; i<kt->cpus; i++)
			notes_ptrs[i] = notes_ptrs[kt->cpus-1] + kt->__per_cpu_offset[i];	
	}

	buf = GETBUF(SIZE(note_buf));

	if (!(ms->panic_task_regs = malloc(kt->cpus * sizeof(struct arm64_pt_regs))))
		error(FATAL, "cannot malloc panic_task_regs space\n");
	
	for  (i = 0; i < kt->cpus; i++) {

		if (!readmem(notes_ptrs[i], KVADDR, buf, SIZE(note_buf), 
		    "note_buf_t", RETURN_ON_ERROR)) {
			error(WARNING, "failed to read note_buf_t\n");
			goto fail;
		}

		/*
		 * Do some sanity checks for this note before reading registers from it.
		 */
		note = (Elf64_Nhdr *)buf;
		p = buf + sizeof(Elf64_Nhdr);

		if (note->n_type != NT_PRSTATUS) {
			error(WARNING, "invalid note (n_type != NT_PRSTATUS)\n");
			goto fail;
		}
		if (p[0] != 'C' || p[1] != 'O' || p[2] != 'R' || p[3] != 'E') {
			error(WARNING, "invalid note (name != \"CORE\"\n");
			goto fail;
		}

		/*
		 * Find correct location of note data. This contains elf_prstatus
		 * structure which has registers etc. for the crashed task.
		 */
		offset = sizeof(Elf64_Nhdr);
		offset = roundup(offset + note->n_namesz, 4);
		p = buf + offset; /* start of elf_prstatus */

		BCOPY(p + OFFSET(elf_prstatus_pr_reg), &ms->panic_task_regs[i],
		      sizeof(struct arm64_pt_regs));
	}

	FREEBUF(buf);
	FREEBUF(notes_ptrs);
	return TRUE;

fail:
	FREEBUF(buf);
	FREEBUF(notes_ptrs);
	free(ms->panic_task_regs);
	ms->panic_task_regs = NULL;
	return FALSE;
}

static void
arm64_clear_machdep_cache(void) {
	/*
	 * TBD: probably not necessary...
	 */
	return;
}

static int
arm64_in_alternate_stack(int cpu, ulong stkptr)
{
	NOT_IMPLEMENTED(INFO);
	return FALSE;
}


static int
compare_kvaddr(const void *v1, const void *v2)
{
        struct vaddr_range *r1, *r2;

        r1 = (struct vaddr_range *)v1;
        r2 = (struct vaddr_range *)v2;

        return (r1->start < r2->start ? -1 :
                r1->start == r2->start ? 0 : 1);
}

static int
arm64_get_kvaddr_ranges(struct vaddr_range *vrp)
{
	int cnt;

	cnt = 0;

	vrp[cnt].type = KVADDR_UNITY_MAP;
	vrp[cnt].start = machdep->machspec->page_offset;
	vrp[cnt++].end = vt->high_memory;

	vrp[cnt].type = KVADDR_VMALLOC;
	vrp[cnt].start = machdep->machspec->vmalloc_start_addr;
	vrp[cnt++].end = last_vmalloc_address();

	if (st->mods_installed) {
		vrp[cnt].type = KVADDR_MODULES;
		vrp[cnt].start = lowest_module_address();
		vrp[cnt++].end = roundup(highest_module_address(), 
			PAGESIZE());
	}

	if (machdep->flags & VMEMMAP) {
		vrp[cnt].type = KVADDR_VMEMMAP;
		vrp[cnt].start = machdep->machspec->vmemmap_vaddr;
		vrp[cnt++].end = vt->node_table[vt->numnodes-1].mem_map +
			(vt->node_table[vt->numnodes-1].size * SIZE(page));
	}

	qsort(vrp, cnt, sizeof(struct vaddr_range), compare_kvaddr);

	return cnt;
}

/*
 *  Include both vmalloc'd, module and vmemmap address space as VMALLOC space.
 */
int
arm64_IS_VMALLOC_ADDR(ulong vaddr)
{
        return ((vaddr >= ARM64_VMALLOC_START && vaddr <= ARM64_VMALLOC_END) ||
                ((machdep->flags & VMEMMAP) &&
                 (vaddr >= ARM64_VMEMMAP_VADDR && vaddr <= ARM64_VMEMMAP_END)) ||
                (vaddr >= ARM64_MODULES_VADDR && vaddr <= ARM64_MODULES_END));
}

#endif  /* ARM64 */

