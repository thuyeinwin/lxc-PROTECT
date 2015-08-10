#ifndef FILEIO_H_
#define FILEIO_H_

#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

struct file* file_open(const char* path, int flags, int rights);

int file_read(struct file* file, unsigned char* data, unsigned int size, unsigned long long offset);

int file_read_open(struct file* file, unsigned char* data, unsigned int size, unsigned long long offset);

int file_read_open_Docker(struct file* file, unsigned char* data, unsigned int size, unsigned long long offset);

void file_close(struct file* file);

char *strtok_r(char *s, const char *delim, char **last);

char * strtok(char *s, const char *delim);

char strAttr[100];

char strAttr1[100];

/* string to get Docker AppArmor context */

char strAttr2[100];

rwlock_t test_read_lock;

rwlock_t token_lock;

rwlock_t open_lock;


int file_read_open_Docker(struct file* file, unsigned char* data, unsigned int size, unsigned long long offset)
{

    mm_segment_t oldfs;
    int ret; int pos = 0;
  
  read_lock(&test_read_lock);
    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, strAttr2, sizeof(strAttr2), &pos);
   
    set_fs(oldfs);

    read_unlock(&test_read_lock);
    return ret;


}


int file_read_open(struct file* file, unsigned char* data, unsigned int size, unsigned long long offset) 
{
    mm_segment_t oldfs;
    int ret; int pos = 0;
  
  read_lock(&test_read_lock);
    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, strAttr1, sizeof(strAttr1), &pos);
   
    set_fs(oldfs);

    read_unlock(&test_read_lock);
    return ret;
}



struct file* file_open(const char* path, int flags, int rights)
{
    struct file* filp = NULL;
    mm_segment_t oldfs;
    int err = 0;


    filp = filp_open(path, flags, rights);

    if(IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

int file_read(struct file* file, unsigned char* data, unsigned int size, unsigned long long offset) 
{
    mm_segment_t oldfs;
    int ret; int pos = 0;
  
  read_lock(&test_read_lock);
    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, strAttr, sizeof(strAttr), &pos);
   
    set_fs(oldfs);

    read_unlock(&test_read_lock);
    return ret;
}




void file_close(struct file* file) 
{
    filp_close(file, NULL);
}


char *strtok_r(char *s, const char *delim, char **last)
{
    char *spanp;
    int c, sc;
    char *tok;

    if (s == NULL && (s = *last) == NULL)
    {
        return NULL;
    }

read_lock(&token_lock);
    /*
     * Skip (span) leading delimiters (s += strspn(s, delim), sort of).
     */
cont:
    c = *s++;
    for (spanp = (char *)delim; (sc = *spanp++) != 0; )
    {
        if (c == sc)
        {
            goto cont;
        }
    }

    if (c == 0)		/* no non-delimiter characters */
    {
        *last = NULL;
        return NULL;
    }
    tok = s - 1;

    /*
     * Scan token (scan for delimiters: s += strcspn(s, delim), sort of).
     * Note that delim must have one NUL; we stop if we see that, too.
     */
    for (;;)
    {
        c = *s++;
        spanp = (char *)delim;
        do
        {
            if ((sc = *spanp++) == c)
            {
                if (c == 0)
                {
                    s = NULL;
                }
                else
                {
                    char *w = s - 1;
                    *w = '\0';
                }
                *last = s;
                return tok;
            }
        }
        while (sc != 0);
    }
    /* NOTREACHED */

read_unlock(&token_lock);
}


char * strtok(char *s, const char *delim)
{
    static char *last;

    return strtok_r(s, delim, &last);
}






















#endif
