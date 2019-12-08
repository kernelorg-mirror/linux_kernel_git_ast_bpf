#ifndef _LINUX_LOCALLOCK_H
#define _LINUX_LOCALLOCK_H

#include <linux/percpu.h>
#include <linux/spinlock.h>

#define DEFINE_LOCAL_IRQ_LOCK(lvar)		__typeof__(const int) lvar
#define DECLARE_LOCAL_IRQ_LOCK(lvar)		extern __typeof__(const int) lvar

static inline void local_irq_lock_init(int lvar) { }

#define local_trylock(lvar)					\
	({							\
		preempt_disable();				\
		1;						\
	})

#define __local_lock(lvar)			do { } while (0)
#define __local_unlock(lvar)			do { } while (0)
#define local_lock(lvar)			preempt_disable()
#define local_unlock(lvar)			preempt_enable()
#define local_lock_irq(lvar)			local_irq_disable()
#define local_unlock_irq(lvar)			local_irq_enable()
#define local_lock_irqsave(lvar, flags)		local_irq_save(flags)
#define local_unlock_irqrestore(lvar, flags)	local_irq_restore(flags)

#define local_spin_trylock_irq(lvar, lock)	spin_trylock_irq(lock)
#define local_spin_lock_irq(lvar, lock)		spin_lock_irq(lock)
#define local_spin_unlock_irq(lvar, lock)	spin_unlock_irq(lock)
#define local_spin_lock_irqsave(lvar, lock, flags)	\
	spin_lock_irqsave(lock, flags)
#define local_spin_unlock_irqrestore(lvar, lock, flags)	\
	spin_unlock_irqrestore(lock, flags)

#define get_locked_var(lvar, var)		get_cpu_var(var)
#define put_locked_var(lvar, var)		put_cpu_var(var)

#define local_lock_cpu(lvar)			get_cpu()
#define local_unlock_cpu(lvar)			put_cpu()

#endif
