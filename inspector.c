#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/highmem.h>
#include <asm/pgtable.h>
#include <asm/msr.h>

#include "inspector.h"

static long ioctl_callback(struct file *flip, unsigned int ioctl, unsigned long arg);
int open_callback (struct inode *node, struct file *fd);

static const struct file_operations fops = {
  .owner = THIS_MODULE,
  .open = open_callback,
  .unlocked_ioctl = ioctl_callback,
};

static dev_t major;
static struct class *cl;
static struct cdev c_dev;

int read_kernel_memory(void *addr, unsigned long long len, char *buffer, size_t buf_len)
{
  size_t copy_len = 0;
  if (len > buf_len) {
    copy_len = buf_len;
  } else {
    copy_len = len;
  }

  // TODO: check mapped address
  memcpy(buffer, addr, len);

  return 0;
}

unsigned long long ioctl_inspect_msr(struct ioctl_inspect_mem_arg * __user arg)
{
  unsigned long long val = 0;
  int remaining = 0;
  int ret = 0;
  struct ioctl_inspect_mem_arg *argp = NULL;

  argp = memdup_user(arg, sizeof(struct ioctl_inspect_mem_arg));
  if (!argp) {
    ret = -EINVAL;
    goto finish;
  }

  val = native_read_msr(argp->val);
  remaining = copy_to_user(&arg->out_ull, &val, sizeof(val));

  if (remaining) {
    ret = -EINVAL;
    goto finish;
  }

finish:
  if (argp) {
    kfree(argp);
  }
 
  return 0;
}

int ioctl_inspect_memory(struct ioctl_inspect_mem_arg * __user arg)
{
  int ret = 0;
  char *kernel_buffer = NULL;
  struct ioctl_inspect_mem_arg *argp = NULL;
  unsigned long long addr = 0;
  unsigned long long len = 0;
  char *out_buf = NULL;
  size_t out_len = 0;

  argp = memdup_user(arg, sizeof(struct ioctl_inspect_mem_arg));
  if (!argp) {
    ret = -EINVAL;
    goto finish;
  }

  addr = argp->addr;
  len = argp->len;
  out_buf = argp->out_buf;
  out_len = argp->out_len;

  if (out_len > MAX_COPY_LEN) {
    ret = -EINVAL;
    goto finish;
  }

  kernel_buffer = kmalloc(out_len, GFP_KERNEL);
  if (!kernel_buffer) {
    ret = -EINVAL;
    goto finish;
  }

  ret = read_kernel_memory((void *)addr, len, kernel_buffer, out_len);
  if (ret) {
    goto finish;
  }

  ret = copy_to_user(out_buf, kernel_buffer, out_len);

  if (ret) {
    ret = -EINVAL;
    goto finish;
  }

finish:
  if (kernel_buffer) {
    kfree(kernel_buffer);
  }

  if (argp) {
    kfree(argp);
  }

  return ret;
}

static long ioctl_callback(struct file *flip, unsigned int ioctl, unsigned long arg)
{
  int ret = 0;
  switch (ioctl) {
    case INSPECT_MEMORY_IOCTL:
      ret = ioctl_inspect_memory((struct ioctl_inspect_mem_arg *)arg);
      break;
    case INSPECT_MSR_IOCTL:
      ret = ioctl_inspect_msr((struct ioctl_inspect_mem_arg *)arg);
      break;
    default:
      ret = -EINVAL;
  }

  return ret;
}

int open_callback (struct inode *node, struct file *fd)
{
  return 0;
}

static dev_t create_device(void)
{ 
  if (alloc_chrdev_region(&major, 0, 1, "tracer_dev") < 0)
  { 
    return 0;
  }

  if ((cl = class_create(THIS_MODULE, "chardrv")) == NULL)
  { 
    unregister_chrdev_region(major, 1);
    return 0;
  }

  if (device_create(cl, NULL, major, NULL, "tracer") == NULL)
  { 
    class_destroy(cl);
    unregister_chrdev_region(major, 1);
    return 0;
  }

  cdev_init(&c_dev, &fops);
  if (cdev_add(&c_dev, major, 1) == -1) {
    return 0;
  }
  
  return 1;
}

void delete_device(void)
{
  if (cl) {
    device_destroy(cl, major);
    cdev_del(&c_dev);
    class_destroy(cl);
    cl = 0;
  }
  if (major) {
    unregister_chrdev_region(major, 1);
  }
  major = 0;
}

int tracer_entry(void)
{
  if (!create_device()) {
    return 1;
  }

  return 0;
}

void tracer_exit(void)
{
  delete_device();
}

module_init(tracer_entry);
module_exit(tracer_exit);

MODULE_LICENSE("GPL");
