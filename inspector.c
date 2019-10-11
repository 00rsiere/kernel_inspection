#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/highmem.h>
#include <asm/pgtable.h>

#define MAX_COPY_LEN 0x1000

long ioctl_callback(struct file *flip, unsigned int ioctl, unsigned long arg);
int open_callback (struct inode *node, struct file *fd);

static const struct file_operations fops = {
  .owner = THIS_MODULE,
  .open = open_callback,
  .unlocked_ioctl = ioctl_callback,
};

struct ioctl_arg {
  unsigned long long addr;
  unsigned long long len;
  char *out_buf;
  size_t out_len;
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

long ioctl_callback(struct file *flip, unsigned int ioctl, unsigned long arg)
{
  int ret = 0;
  char *kernel_buffer = NULL;
  struct ioctl_arg __user *argp = NULL;
  unsigned long long addr = 0;
  unsigned long long len = 0;
  char *out_buf = NULL;
  size_t out_len = 0;

  if (out_len > MAX_COPY_LEN) {
    ret = -EINVAL;
    goto finish;
  }

  argp = memdup_user((struct ioctl_arg *)arg, sizeof(struct ioctl_arg));
  if (!argp) {
    ret = -EINVAL;
    goto finish;
  }

  addr = argp->addr;
  len = argp->len;
  out_buf = argp->out_buf;
  out_len = argp->out_len;

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

finish:
  if (kernel_buffer) {
    kfree(kernel_buffer);
  }

  if (argp) {
    kfree(argp);
  }
  return ret;
}

int open_callback (struct inode *node, struct file *fd)
{
  return 0;
}

static dev_t create_device(void)
{ 
  if (alloc_chrdev_region(&major, 0, 1, "tracer_dev") < 0)  //$cat /proc/devices
  { 
    return 0;
  }
  if ((cl = class_create(THIS_MODULE, "chardrv")) == NULL)    //$ls /sys/class
  { 
    unregister_chrdev_region(major, 1);
    return 0;
  }
  if (device_create(cl, NULL, major, NULL, "tracer") == NULL) //$ls /dev/
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
