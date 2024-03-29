#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/smp.h>
#include <linux/sem.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include <linux/stat.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/utsname.h>
#include <linux/personality.h>
#include <linux/random.h>
#include <linux/uaccess.h>
#include <linux/security.h>

#include <asm/elf.h>
#include <asm/ia32.h>
#include <asm/syscalls.h>

/*
 * Align a virtual address to avoid aliasing in the I$ on AMD F15h.
 * The bits defined by the va_align.bits, [12:upper_bit), are set to
 * a random value instead of zeroing them. This random value is
 * computed once per boot. This form of ASLR is known as "per-boot
 * ASLR".
 *
 * @flags denotes the allocation direction - bottomup or topdown -
 * or vDSO; see call sites below.
 */
unsigned long align_addr(unsigned long addr, struct file *filp,
			 enum align_flags flags)
{
	unsigned long tmp_addr;

	/* handle 32- and 64-bit case with a single conditional */
	if (va_align.flags < 0 || !(va_align.flags & (2 - mmap_is_ia32())))
		return addr;

	if (!(current->flags & PF_RANDOMIZE))
		return addr;

	if (!((flags & ALIGN_VDSO) || filp))
		return addr;

	tmp_addr = addr;

	/*
	 * We need an address which is <= than the original
	 * one only when in topdown direction.
	 */
	if (!(flags & ALIGN_TOPDOWN))
		tmp_addr += va_align.mask;
	else
		tmp_addr -= va_align.mask;

	tmp_addr &= ~va_align.mask;
	tmp_addr |= va_align.bits;

	return tmp_addr;
}

static int __init control_va_addr_alignment(char *str)
{
	/* guard against enabling this on other CPU families */
	if (va_align.flags < 0)
		return 1;

	if (*str == 0)
		return 1;

	if (*str == '=')
		str++;

	if (!strcmp(str, "32"))
		va_align.flags = ALIGN_VA_32;
	else if (!strcmp(str, "64"))
		va_align.flags = ALIGN_VA_64;
	else if (!strcmp(str, "off"))
		va_align.flags = 0;
	else if (!strcmp(str, "on"))
		va_align.flags = ALIGN_VA_32 | ALIGN_VA_64;
	else
		return 0;

	return 1;
}
__setup("align_va_addr", control_va_addr_alignment);

SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
		unsigned long, prot, unsigned long, flags,
		unsigned long, fd, unsigned long, off)
{
	long error;
	error = -EINVAL;
	if (off & ~PAGE_MASK)
		goto out;

	error = sys_mmap_pgoff(addr, len, prot, flags, fd, off >> PAGE_SHIFT);
out:
	return error;
}

static void find_start_end(unsigned long flags, unsigned long *begin,
			   unsigned long *end)
{
	if (!test_thread_flag(TIF_IA32) && (flags & MAP_32BIT)) {
		unsigned long new_begin;
		/* This is usually used needed to map code in small
		   model, so it needs to be in the first 31bit. Limit
		   it to that.  This means we need to move the
		   unmapped base down for this case. This can give
		   conflicts with the heap, but we assume that glibc
		   malloc knows how to fall back to mmap. Give it 1GB
		   of playground for now. -AK */
		*begin = 0x40000000;
		*end = 0x80000000;
		if (current->flags & PF_RANDOMIZE) {
			new_begin = randomize_range(*begin, *begin + 0x02000000, 0);
			if (new_begin)
				*begin = new_begin;
		}
	} else {
		*begin = TASK_UNMAPPED_BASE;
		*end = TASK_SIZE;
	}
}

unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long start_addr;
	unsigned long begin, end;
	unsigned int unmap_factor = sysctl_unmap_area_factor;

	if (flags & MAP_FIXED)
		return addr;

	find_start_end(flags, &begin, &end);

	if (len > end)
		return -ENOMEM;

	if (addr) {
		addr = PAGE_ALIGN(addr);
		vma = find_vma(mm, addr);
		if (end - len >= addr &&
		    (!vma || addr + len <= vma->vm_start) &&
		    (addr >= mmap_min_addr))
			return addr;
	}
	if (((flags & MAP_32BIT) || test_thread_flag(TIF_IA32))) {
		if (!unmap_factor && len <= mm->cached_hole_size)
			mm->cached_hole_size = 0;
		mm->free_area_cache = begin;
	}
	addr = mm->free_area_cache;
	if (addr < begin)
		addr = begin;
	start_addr = addr;

full_search:

	addr = align_addr(addr, filp, 0);

	for (vma = find_vma(mm, addr); ; vma = vma->vm_next) {
		/* At this point:  (!vma || addr < vma->vm_end). */
		if (end - len < addr) {
			/*
			 * Start a new search - just in case we missed
			 * some holes.
			 */
			if (start_addr != begin) {
				start_addr = addr = begin;
				if (likely(!unmap_factor))
					mm->cached_hole_size = 0;
				goto full_search;
			}
			return -ENOMEM;
		}
		if (!vma || addr + len <= vma->vm_start) {
			/*
			 * Remember the place where we stopped the search:
			 */
			mm->free_area_cache = addr + len;
			return addr;
		}
		if (!unmap_factor &&
				addr + mm->cached_hole_size < vma->vm_start)
			mm->cached_hole_size = vma->vm_start - addr;

		addr = vma->vm_end;
		addr = align_addr(addr, filp, 0);
	}
}


unsigned long
arch_get_unmapped_area_topdown(struct file *filp, const unsigned long addr0,
			  const unsigned long len, const unsigned long pgoff,
			  const unsigned long flags)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	unsigned long addr = addr0;
	unsigned int unmap_factor = sysctl_unmap_area_factor;
	int firsttime = 1;

	/* requested length too big for entire address space */
	if (len > TASK_SIZE)
		return -ENOMEM;

	if (flags & MAP_FIXED)
		return addr;

	/* for MAP_32BIT mappings we force the legact mmap base */
	if (!test_thread_flag(TIF_IA32) && (flags & MAP_32BIT))
		goto bottomup;

	/* requesting a specific address */
	if (addr) {
		addr = PAGE_ALIGN(addr);
		vma = find_vma(mm, addr);
		if (TASK_SIZE - len >= addr &&
				(!vma || addr + len <= vma->vm_start) &&
				(addr >= mmap_min_addr))
			return addr;
	}

	/* check if free_area_cache is useful for us */
	if (len <= mm->cached_hole_size && !unmap_factor) {
		mm->cached_hole_size = 0;
		mm->free_area_cache = mm->mmap_base;
	}

 again:
	/* either no address requested or can't fit in requested address hole */
	addr = mm->free_area_cache;

	/* make sure it can fit in the remaining address space */
	if (addr > len) {
		unsigned long tmp_addr = align_addr(addr - len, filp,
						    ALIGN_TOPDOWN);

		vma = find_vma(mm, tmp_addr);
		if ((!vma || tmp_addr + len <= vma->vm_start) &&
		    (tmp_addr >= mmap_min_addr))
			/* remember the address as a hint for next time */
			return mm->free_area_cache = tmp_addr;
	}

	if (mm->mmap_base < len)
		goto bottomup;

	if (likely(!unmap_factor))
		addr = mm->mmap_base-len;

	do {
		addr = align_addr(addr, filp, ALIGN_TOPDOWN);

		/*
		 * Lookup failure means no vma is above this address,
		 * else if new region fits below vma->vm_start,
		 * return with success:
		 */
		vma = find_vma(mm, addr);
		if (!vma || addr+len <= vma->vm_start) {
			/* we hit the bottom, stop this search */
			if (addr < mmap_min_addr)
				break;
			/* remember the address as a hint for next time */
			return mm->free_area_cache = addr;
		}

		/* remember the largest hole we saw so far */
		if (!unmap_factor &&
				addr + mm->cached_hole_size < vma->vm_start)
			mm->cached_hole_size = vma->vm_start - addr;

		/* try just below the current vma->vm_start */
		addr = vma->vm_start-len;
	} while (len < vma->vm_start);

	/*
	 * Using the next-fit algorithm, it is possible we started
	 * searching below usable address space holes. Go back to the
	 * top and start over.
	 */
	if (unmap_factor && firsttime) {
		mm->free_area_cache = mm->mmap_base;
		mm->cached_hole_size = 0;
		firsttime = 0;
		goto again;
	}

bottomup:
	/*
	 * A failed mmap() very likely causes application failure,
	 * so fall back to the bottom-up function here. This scenario
	 * can happen with large stack limits and large mmap()
	 * allocations.
	 */
	if (likely(!unmap_factor))
		mm->cached_hole_size = ~0UL;
	mm->free_area_cache = TASK_UNMAPPED_BASE;
	addr = arch_get_unmapped_area(filp, addr0, len, pgoff, flags);
	/*
	 * Restore the topdown base:
	 */
	mm->free_area_cache = mm->mmap_base;
	if (likely(!unmap_factor))
		mm->cached_hole_size = ~0UL;

	return addr;
}


SYSCALL_DEFINE1(uname, struct new_utsname __user *, name)
{
	int err;
	down_read(&uts_sem);
	err = copy_to_user(name, utsname(), sizeof(*name));
	up_read(&uts_sem);
	if (personality(current->personality) == PER_LINUX32)
		err |= copy_to_user(&name->machine, "i686", 5);
	return err ? -EFAULT : 0;
}
