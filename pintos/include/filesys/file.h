#ifndef FILESYS_FILE_H
#define FILESYS_FILE_H

#include <list.h>

#include "filesys/off_t.h"
#include "lib/stdbool.h"

struct inode;
/* An open file. */
struct file {
  struct inode *inode; /* File's inode. */
  off_t pos;           /* Current position. */
  bool deny_write;     /* Has file_deny_write() been called? */
};
struct file_info {
  struct file_info *duplicated_file; /* fork 시에 첫 복제 file_info 올려놓는 곳*/
  struct file *file;                 /* fd가 가리키는 file */
  struct list dup_list;              /* dup 된 fd들의 list */
  int dup_count;      /* list_sie(dup_list) fork 하면서 차감하면서 마지막 dup 판단 */
  bool is_duplicated; /* 첫 복제임을 알기 위해서 */
  int stdtype;        /* 0: 표준 입력, 1: 표준 출력, 2: 일반 파일 */
};
struct dup_elem {
  int fd;
  struct list_elem elem; /* dup_list 용*/
};

/* Opening and closing files. */
struct file *file_open(struct inode *);
struct file *file_reopen(struct file *);
struct file *file_duplicate(struct file *file);
void file_close(struct file *);
struct inode *file_get_inode(struct file *);

/* Reading and writing. */
off_t file_read(struct file *, void *, off_t);
off_t file_read_at(struct file *, void *, off_t size, off_t start);
off_t file_write(struct file *, const void *, off_t);
off_t file_write_at(struct file *, const void *, off_t size, off_t start);

/* Preventing writes. */
void file_deny_write(struct file *);
void file_allow_write(struct file *);

/* File position. */
void file_seek(struct file *, off_t);
off_t file_tell(struct file *);
off_t file_length(struct file *);

struct file_info *init_std(int stdtype);
#endif /* filesys/file.h */
