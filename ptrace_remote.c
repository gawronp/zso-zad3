#include <asm/syscalls.h>
#include <asm/page.h>
#include <asm/mman.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/ptrace_remote.h>
#include <linux/profile.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/syscalls.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/fdtable.h>

static int remote_mmap(struct ptrace_remote_task *task_data);
static int remote_munmap(struct ptrace_remote_task *task_data);
static int remote_mremap(struct ptrace_remote_task *task_data);
static int remote_mprotect(struct ptrace_remote_task *task_data);
static int remote_dup(struct ptrace_remote_task *task_data);
static int remote_dup2(struct ptrace_remote_task *task_data);
static void dup_from_remote(struct ptrace_remote_task *task_data);
static int remote_close(struct ptrace_remote_task *task_data);

static void remote_task_function(void)
{
	struct ptrace_remote_task *defered_task = current->ptrace_defered_task;
	switch (defered_task->request) {
	case PTRACE_REMOTE_MMAP:
		defered_task->retval = remote_mmap(defered_task);
		break;
	case PTRACE_REMOTE_MUNMAP:
		defered_task->retval = remote_munmap(defered_task);
		break;
	case PTRACE_REMOTE_MREMAP:
		defered_task->retval = remote_mremap(defered_task);
		break;
	case PTRACE_REMOTE_MPROTECT:
		defered_task->retval = remote_mprotect(defered_task);
		break;
	case PTRACE_DUP_TO_REMOTE:
		defered_task->retval = remote_dup(defered_task);
		break;
	case PTRACE_DUP2_TO_REMOTE:
		defered_task->retval = remote_dup2(defered_task);
		break;
	case PTRACE_DUP_FROM_REMOTE:
		dup_from_remote(defered_task);
		break;
	case PTRACE_REMOTE_CLOSE:
		defered_task->retval = remote_close(defered_task);
		break;
	default:
		BUG_ON("remote_task_function called with unknown request code - this should never happen!\n");
	}
	set_current_state(defered_task->child_orig_state);
	complete(&defered_task->remote_completion);
}

int ptrace_request_remote(struct task_struct *child, long request, unsigned long addr, unsigned long data)
{
	int ret = 0;

	child->ptrace_defered_task = kzalloc(sizeof(struct ptrace_remote_task), GFP_KERNEL);
	if (unlikely(!child->ptrace_defered_task))
		return -ENOMEM;

	child->ptrace_defered_task->request = request;
	child->ptrace_defered_task->defered_fun = remote_task_function;
	init_completion(&child->ptrace_defered_task->remote_completion);

	switch (request) {
	case PTRACE_REMOTE_MMAP:
		child->ptrace_defered_task->data_from_user = kzalloc(sizeof(struct ptrace_remote_mmap), GFP_KERNEL);
		if (unlikely(!child->ptrace_defered_task->data_from_user)) {
			ret = -ENOMEM;
			break;
		}

		if (copy_from_user(child->ptrace_defered_task->data_from_user,
				(void *) data,
				sizeof(struct ptrace_remote_mmap))) {
			ret = -EFAULT;
			break;
		}

		if (((struct ptrace_remote_mmap *) child->ptrace_defered_task->data_from_user)->addr % PAGE_SIZE) {
			ret = -EINVAL;
			break;
        	}

		if (!((MAP_SHARED
				& ((struct ptrace_remote_mmap *) child->ptrace_defered_task->data_from_user)->flags)
			^ (MAP_PRIVATE
				& ((struct ptrace_remote_mmap *) child->ptrace_defered_task->data_from_user)->flags))) {
			ret = -EINVAL;
			break;
        	}

		if (MAP_ANONYMOUS & ((struct ptrace_remote_mmap *) child->ptrace_defered_task->data_from_user)->flags) {
			child->ptrace_defered_task->file_ptr = NULL;
		} else {
			child->ptrace_defered_task->file_ptr =
				fget(((struct ptrace_remote_mmap *) child->ptrace_defered_task->data_from_user)->fd);
			if (!child->ptrace_defered_task->file_ptr) {
				ret = -EBADF;
				break;
            		}
		}

		spin_lock_irq(&child->sighand->siglock);
		child->ptrace_defered_task->child_orig_state = child->state;
		wake_up_state(child, child->state);
		spin_unlock_irq(&child->sighand->siglock);

		wait_for_completion(&child->ptrace_defered_task->remote_completion);

		// copy struct back, so user can access modified "addr"
		if (copy_to_user((void *) data,	child->ptrace_defered_task->data_from_user,
				sizeof(struct ptrace_remote_mmap))) {
			ret = -EFAULT;
			break;
		}

		ret = child->ptrace_defered_task->retval;
		break;

	case PTRACE_REMOTE_MUNMAP:
		child->ptrace_defered_task->data_from_user = kzalloc(sizeof(struct ptrace_remote_munmap), GFP_KERNEL);
		if (unlikely(!child->ptrace_defered_task->data_from_user)) {
			ret = -ENOMEM;
			break;
		}

		if (copy_from_user(child->ptrace_defered_task->data_from_user, (void *) data,
				sizeof(struct ptrace_remote_munmap))) {
			ret = -EFAULT;
			break;
	        }

		spin_lock_irq(&child->sighand->siglock);
		child->ptrace_defered_task->child_orig_state = child->state;
		wake_up_state(child, child->state);
		spin_unlock_irq(&child->sighand->siglock);

		wait_for_completion(&child->ptrace_defered_task->remote_completion);
		ret = child->ptrace_defered_task->retval;
		break;

	case PTRACE_REMOTE_MREMAP:
		child->ptrace_defered_task->data_from_user = kzalloc(sizeof(struct ptrace_remote_mremap), GFP_KERNEL);
		if (unlikely(!child->ptrace_defered_task->data_from_user)) {
			ret = -ENOMEM;
			break;
	        }

		if (copy_from_user(child->ptrace_defered_task->data_from_user, (void *) data,
				sizeof(struct ptrace_remote_mremap))) {
			ret = -EFAULT;
			break;
	        }

		spin_lock_irq(&child->sighand->siglock);
		child->ptrace_defered_task->child_orig_state = child->state;
		wake_up_state(child, child->state);
		spin_unlock_irq(&child->sighand->siglock);

		wait_for_completion(&child->ptrace_defered_task->remote_completion);

		// copy struct back, so user can access modified "new_addr"
		if (copy_to_user((void *) data,	child->ptrace_defered_task->data_from_user,
				sizeof(struct ptrace_remote_mremap))) {
			ret = -EFAULT;
			break;
		}

		ret = child->ptrace_defered_task->retval;
		break;

	case PTRACE_REMOTE_MPROTECT:
		child->ptrace_defered_task->data_from_user = kzalloc(sizeof(struct ptrace_remote_mprotect), GFP_KERNEL);
		if (unlikely(!child->ptrace_defered_task->data_from_user)) {
			ret = -ENOMEM;
			break;
	        }

		if (unlikely(!child->ptrace_defered_task->data_from_user)) {
			kfree(child->ptrace_defered_task);
			return -ENOMEM;
	        }

		if (copy_from_user(child->ptrace_defered_task->data_from_user, (void *) data,
				sizeof(struct ptrace_remote_mprotect))) {
			ret = -EFAULT;
			break;
        	}

		spin_lock_irq(&child->sighand->siglock);
		child->ptrace_defered_task->child_orig_state = child->state;
		wake_up_state(child, child->state);
		spin_unlock_irq(&child->sighand->siglock);

		wait_for_completion(&child->ptrace_defered_task->remote_completion);
		ret = child->ptrace_defered_task->retval;
		break;

	case PTRACE_DUP_TO_REMOTE:
		child->ptrace_defered_task->data_from_user = kzalloc(sizeof(struct ptrace_dup_to_remote), GFP_KERNEL);
		if (unlikely(!child->ptrace_defered_task->data_from_user)) {
			ret = -ENOMEM;
			break;
		}

		if (copy_from_user(child->ptrace_defered_task->data_from_user, (void *) data,
				sizeof(struct ptrace_dup_to_remote))) {
			ret = -EFAULT;
			break;
	        }

		if ((~((uint32_t) O_CLOEXEC))
				& ((struct ptrace_dup_to_remote *) child->ptrace_defered_task->data_from_user)->flags) {
			ret = -EINVAL;
			break;
        	}

		child->ptrace_defered_task->file_ptr = fget(
			((struct ptrace_dup_to_remote *) child->ptrace_defered_task->data_from_user)->local_fd);
		if (!child->ptrace_defered_task->file_ptr) {
			ret = -EBADF;
			break;
        	}

		spin_lock_irq(&child->sighand->siglock);
		child->ptrace_defered_task->child_orig_state = child->state;
		wake_up_state(child, child->state);
		spin_unlock_irq(&child->sighand->siglock);

		wait_for_completion(&child->ptrace_defered_task->remote_completion);
		ret = child->ptrace_defered_task->retval;
		break;

	case PTRACE_DUP2_TO_REMOTE:
		child->ptrace_defered_task->data_from_user = kzalloc(sizeof(struct ptrace_dup2_to_remote), GFP_KERNEL);
		if (unlikely(!child->ptrace_defered_task->data_from_user)) {
			ret = -ENOMEM;
			break;
        	}

		if (copy_from_user(child->ptrace_defered_task->data_from_user, (void *) data,
				sizeof(struct ptrace_dup2_to_remote))) {
			ret = -EFAULT;
			break;
	        }

		if ((~((uint32_t) O_CLOEXEC))
				& ((struct ptrace_dup2_to_remote *) child->ptrace_defered_task->data_from_user)->flags) {
			ret = -EINVAL;
			break;
		}

		child->ptrace_defered_task->file_ptr = fget(
			((struct ptrace_dup2_to_remote *) child->ptrace_defered_task->data_from_user)->local_fd);
		if (!child->ptrace_defered_task->file_ptr) {
			ret = -EBADF;
			break;
		}

		spin_lock_irq(&child->sighand->siglock);
		child->ptrace_defered_task->child_orig_state = child->state;
		wake_up_state(child, child->state);
		spin_unlock_irq(&child->sighand->siglock);

		wait_for_completion(&child->ptrace_defered_task->remote_completion);
		ret = child->ptrace_defered_task->retval;
		break;

	case PTRACE_DUP_FROM_REMOTE:
		child->ptrace_defered_task->data_from_user = kzalloc(sizeof(struct ptrace_dup_from_remote), GFP_KERNEL);
		if (unlikely(!child->ptrace_defered_task->data_from_user)) {
			ret = -ENOMEM;
			break;
		}

		if (copy_from_user(child->ptrace_defered_task->data_from_user, (void *) data,
				sizeof(struct ptrace_dup_from_remote))) {
			ret = -EFAULT;
			break;
		}

		if ((~((uint32_t) O_CLOEXEC))
				& ((struct ptrace_dup_from_remote*) child->ptrace_defered_task->data_from_user)->flags) {
			ret = -EINVAL;
			break;
		}

		spin_lock_irq(&child->sighand->siglock);
		child->ptrace_defered_task->child_orig_state = child->state;
		wake_up_state(child, child->state);
		spin_unlock_irq(&child->sighand->siglock);

		wait_for_completion(&child->ptrace_defered_task->remote_completion);
		if (!child->ptrace_defered_task->file_ptr) {
			ret = -EBADF;
			break;
		}

		ret = f_dupfd(0, child->ptrace_defered_task->file_ptr,
			((struct ptrace_dup_from_remote *)child->ptrace_defered_task->data_from_user)->flags);
		break;

	case PTRACE_REMOTE_CLOSE:
		child->ptrace_defered_task->data_from_user = kzalloc(sizeof(struct ptrace_remote_close), GFP_KERNEL);
		if (unlikely(!child->ptrace_defered_task->data_from_user)) {
			ret = -ENOMEM;
			break;
		}

		if (copy_from_user(child->ptrace_defered_task->data_from_user, (void *) data,
				sizeof(struct ptrace_remote_close))) {
			ret = -EFAULT;
			break;
		}

		spin_lock_irq(&child->sighand->siglock);
		child->ptrace_defered_task->child_orig_state = child->state;
		wake_up_state(child, child->state);
		spin_unlock_irq(&child->sighand->siglock);

		wait_for_completion(&child->ptrace_defered_task->remote_completion);
		ret = child->ptrace_defered_task->retval;
		break;
	}

	if (child->ptrace_defered_task->file_ptr)
		put_filp(child->ptrace_defered_task->file_ptr);

	if (child->ptrace_defered_task->data_from_user)
		kfree(child->ptrace_defered_task->data_from_user);

	kfree(child->ptrace_defered_task);
	child->ptrace_defered_task = NULL;

	return ret;
}

static int remote_mmap(struct ptrace_remote_task *task_data)
{
	uint64_t retval;
	unsigned long populate = 0;
	struct ptrace_remote_mmap *mmap_data = (struct ptrace_remote_mmap *) task_data->data_from_user;

	if (down_write_killable(&current->mm->mmap_sem))
		return -EINTR;

	retval = do_mmap(task_data->file_ptr, mmap_data->addr, mmap_data->length, mmap_data->prot,
		mmap_data->flags, 0, mmap_data->offset / PAGE_SIZE, &populate);

	up_write(&current->mm->mmap_sem);

	if (IS_ERR_VALUE(retval))
		return retval;

	mmap_data->addr = retval;

	if (populate > 0)
		mm_populate(retval, populate);

	return 0;
}

static int remote_munmap(struct ptrace_remote_task *task_data)
{
	return sys_munmap(((struct ptrace_remote_munmap * ) task_data->data_from_user)->addr,
		((struct ptrace_remote_munmap * ) task_data->data_from_user)->length);
}

static int remote_mremap(struct ptrace_remote_task *task_data)
{
	struct ptrace_remote_mremap *remap_data = (struct ptrace_remote_mremap *) task_data->data_from_user;

	uint64_t new_addr = sys_mremap(remap_data->old_addr, remap_data->old_size, remap_data->new_size,
		remap_data->flags, remap_data->new_addr);

	if (IS_ERR_VALUE(new_addr))
		return new_addr;

	remap_data->new_addr = new_addr;
	return 0;
}

static int remote_mprotect(struct ptrace_remote_task *task_data)
{
	return sys_mprotect(((struct ptrace_remote_mprotect *) task_data->data_from_user)->addr,
		((struct ptrace_remote_mprotect *) task_data->data_from_user)->length,
		((struct ptrace_remote_mprotect *) task_data->data_from_user)->prot);
}

static int remote_dup(struct ptrace_remote_task *task_data)
{
	return f_dupfd(0, task_data->file_ptr, ((struct ptrace_dup_to_remote *) task_data->data_from_user)->flags);
}

static int remote_dup2(struct ptrace_remote_task *task_data)
{
	return replace_fd(((struct ptrace_dup2_to_remote *) task_data->data_from_user)->remote_fd, task_data->file_ptr,
		((struct ptrace_dup2_to_remote *) task_data->data_from_user)->flags);
}

static void dup_from_remote(struct ptrace_remote_task *task_data)
{
	task_data->file_ptr = fget(((struct ptrace_dup_from_remote *) task_data->data_from_user)->remote_fd);
}

static int remote_close(struct ptrace_remote_task *task_data)
{
	return sys_close(((struct ptrace_remote_close *) task_data->data_from_user)->remote_fd);
}
