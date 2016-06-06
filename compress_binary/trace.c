/*
this will log all addresses used by an application so it can be stripped + compressed
its wrote as 64bit unsigned integers (just like the memory itself)
needs to be sorted + uniqued for processing

*/
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/personality.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#ifdef __x86_64__
#include "xen-x86_64.h"
#elif defined(__i386__) 
#include "xen-x86_32.h"
#endif
#include "x86_emulate.h"



// these are the 'specialty' instructions that we can control if we wish to log the information that
// they read/write/etc
struct hack_x86_emulate_ops {
        void *read;
        void *insn_fetch;
        void *write;
        void *cmpxchg;
        void *rep_ins;
        void *rep_outs;
        void *rep_movs;
        void *read_segment;
        void *write_segment;
        void *read_io;
        void *write_io;
        void *read_cr;
        void *write_cr;
        void *read_dr;
        void *write_dr;
        void *read_msr;
        void *write_msr;
        void *wbinvd;
        void *cpuid;
        void *inject_hw_exception;
        void *inject_sw_interrupt;
        void *get_fpu;
        void *put_fpu;
        void *invlpg;
};


FILE *ofd = NULL;
int Gpid = 0;

struct hack_x86_emulate_ops emulate_ops;
struct x86_emulate_ctxt emulation_ctx;

static int emulated_read(enum x86_segment seg, 
#ifdef defined(__i386__)
uint32_t offset,
#else
uint64_t offset, 
#endif
void *p_data, unsigned int bytes, struct _x86_emulate_ctxt *ctxt) {
        int i = 0;
        char *buf = NULL;
#ifdef defined(__i386__)
        uint32_t *_instr = NULL;
        
        int space = bytes + (bytes % sizeof(uint32_t));
#else        
        uint64_t *_instr = NULL;
        
        int space = bytes + (bytes % sizeof(uint64_t));
#endif
        
#ifdef defined(__i386__)
	printf("2 %X [bytes %d]\n", offset, bytes);
#else
	printf("2 %llu [bytes %d]\n", offset, bytes);
#endif        
        
        buf = (char *)calloc(1, bytes);
        if (buf == NULL) {
                perror("calloc");
                exit(-1);
        }
        
#ifdef defined(__i386__)
        _instr = (unsigned long *)buf;
        // just in case it really needs the addresses for pointer arithmetic later in the instruction.. we must retrieve it
	for (i = 0; i < (space/sizeof(uint32_t)); i++) {
		*_instr++ = (uint32_t)ptrace(PTRACE_PEEKDATA, Gpid, (uint32_t)(offset + (i * sizeof(uint32_t))), NULL);
	}

        // log addresses
        for (i = 0; i < bytes; i++) {
                _instr = (uint32_t *)(offset + i);
                fwrite((void *)&_instr, sizeof(uint32_t), 1, ofd);
		printf("3 %X [%X %d]\n", _instr, offset, i);
        }

#else        
        _instr = (unsigned long int *)buf;
        // just in case it really needs the addresses for pointer arithmetic later in the instruction.. we must retrieve it
	for (i = 0; i < (space/sizeof(uint64_t)); i++) {
		*_instr++ = (uint64_t)ptrace(PTRACE_PEEKDATA, Gpid, (uint64_t)(offset + (i * sizeof(uint64_t))), NULL);
	}

        // log addresses
        for (i = 0; i < bytes; i++) {
                _instr = (uint64_t *)(offset + i);
                fwrite((void *)&_instr, sizeof(uint64_t), 1, ofd);
		printf("3 %llu [%llu %d]\n", _instr, offset, i);
        }
#endif        
        
        
        // copy to the appropriate user given location
        memcpy(p_data, buf, bytes);
        
        // free buffer
        free(buf);
        
        return X86EMUL_OKAY;
}

static int emulated_read_fetch(enum x86_segment seg, uint64_t offset, void *p_data, unsigned int bytes, struct _x86_emulate_ctxt *ctxt) {

printf("F %llu\n", offset);
	return emulated_read(seg, offset, p_data, bytes, ctxt);
}


// we do not care about writes since this is to compress an executable file
static int emulated_write(enum x86_segment seg, uint64_t offset, void *p_data, unsigned int bytes, struct _x86_emulate_ctxt *ctxt) {
	return X86EMUL_OKAY;
}


void ptrace_to_emulate_regs(struct user_regs_struct *Pregs, struct cpu_user_regs *Eregs) {
#ifdef __x86_64__
Eregs->rax = Pregs->rax;
Eregs->rbx = Pregs->rbx;
Eregs->rcx = Pregs->rcx;
Eregs->rdx = Pregs->rdx;
Eregs->rdi = Pregs->rdi;
Eregs->rip = Pregs->rip;
Eregs->rsp = Pregs->rsp;
Eregs->rbp = Pregs->rbp;
Eregs->cs = Pregs->cs;
Eregs->es = Pregs->es;
Eregs->ds = Pregs->ds;
Eregs->fs = Pregs->fs;
Eregs->gs = Pregs->gs;
Eregs->eflags = Pregs->eflags;
Eregs->r15 = Pregs->r15;
Eregs->r14 = Pregs->r14;
Eregs->r13 = Pregs->r13;
Eregs->r12 = Pregs->r12;
Eregs->r11 = Pregs->r11;
Eregs->r10 = Pregs->r10;
Eregs->r9 = Pregs->r9;
Eregs->r8 = Pregs->r8;
Eregs->rsi = Pregs->rsi;
#elif defined(__i386__) 
Eregs->eax = Pregs->eax;
Eregs->ebx = Pregs->ebx;
Eregs->ecx = Pregs->ecx;
Eregs->edx = Pregs->edx;
Eregs->eflags = Pregs->eflags;
Eregs->edi = Pregs->edi;
Eregs->esi = Pregs->esi;
Eregs->gs = Pregs->gs;
Eregs->fs = Pregs->fs;
Eregs->ds = Pregs->ds;
Eregs->es = Pregs->es;
Eregs->ebp = Pregs->ebp;
Eregs->esp = Pregs->esp;
Eregs->eip = Pregs->eip;
#endif
}


/*
if we wanna know every memory address that pops up for an instruction then
we have to truly emulate it and monitor the addreses it attempts to read/write
tonce logging these addresses, and testing all instructions necessary then
you can remove the rest and compress an address space to have the smallest
binary possible
itd be smart to add in code to retrieve code required after this as well
mmon texlive-base texlive-binaries
*/
void emulate_log(int pid) {
	char instr[32]; // peeks by 8 bytes at a time
	struct user_regs_struct regs;
	int i = 0;
#ifdef defined(__i386__) 
        uint32_t *_instr = (uint32_t *)&instr;
#else
	uint64_t *_instr = (uint64_t *)&instr;
#endif
        int r = 0;
	struct cpu_user_regs Eregs;

	Gpid = pid;
	
	// get registers (RIP)
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);

	// convert for emulator
	ptrace_to_emulate_regs(&regs, &Eregs);
	emulation_ctx.regs = &Eregs;

#ifdef defined(__i386__) 
        printf("1 %X - EIP\n", Eregs.eip);
#else
	printf("1 %llu - EIP\n", Eregs.rip);
#endif

#ifdef defined(__i386__) 
	// read 32 bytes from RIP 
	for (i = 0; i < 3; i++) {
		*_instr++ = (uint32_t)ptrace(PTRACE_PEEKDATA, pid,
		 	regs.eip + (i * sizeof(uint32_t)), NULL);
	}

#else
	// read 32 bytes from RIP 
	for (i = 0; i < (sizeof(instr)/sizeof(uint64_t)); i++) {
		*_instr++ = (uint64_t)ptrace(PTRACE_PEEKDATA, pid,
		 	regs.rip + (i * sizeof(uint64_t)), NULL);
	}
#endif

#ifdef defined(__i386__) 
        printf("B %X\n", Eregs.eip);
#else
	printf("B %llu\n", Eregs.rip);
#endif
	
        // emulate the instruction so that it logs the addresses used
        r = x86_emulate((struct x86_emulate_ctxt *)&emulation_ctx, (const struct x86_emulate_ops *)&emulate_ops);	

        return;
}



int main(int argc, char *argv[]) {
        long long counter = 0;  /*  machine instruction counter */
        int wait_val;           /*  child's return value        */
        int pid;                /*  child's process id          */
	char buf[1024];
	struct user_regs_struct regs;
	int personality_setting = 0;

        memset((void *)&emulate_ops, 0, sizeof(struct hack_x86_emulate_ops));

        emulate_ops.read = (void *)&emulated_read;
        emulate_ops.insn_fetch = (void *)&emulated_read_fetch;
	emulate_ops.write = (void *)&emulated_write;


	sprintf(buf, "%s.2.trace.%d.log", argv[2], getpid());
	ofd = fopen(buf, "wb");
	if (ofd == NULL) {
		fprintf(stderr, "cannot open %s.. exiting\n", buf);
		exit(-1);
	}


        switch (pid = fork()) {
        case -1:
                perror("fork");
                break;
        case 0: /*  child process starts        */
		personality_setting = personality(0xffffffff);
		personality(personality_setting|ADDR_NO_RANDOMIZE);
                ptrace(PTRACE_TRACEME, 0, 0, 0);
                /* 
                 *  must be called in order to allow the
                 *  control over the child process
                 */ 
                //execl("/bin/ls", "ls", NULL);
		execl(argv[1],argv[2], NULL);
                /*
                 *  executes the program and causes
                 *  the child to stop and send a signal 
                 *  to the parent, the parent can now
                 *  switch to PTRACE_SINGLESTEP   
                 */ 
                break;
                /*  child process ends  */
        default:/*  parent process starts       */
                wait(&wait_val); 

		ptrace(PTRACE_GETREGS, pid, NULL, &regs);

		//printf("%X\n", regs.rip);
		// we want to log our instruction address here..
		//fwrite((void *)&regs.rip, sizeof(uint64_t), 1, ofd);
                /*   
                 *   parent waits for child to stop at next 
                 *   instruction (execl()) 
                 */
                while (wait_val == 1407 ) {
                        counter++;
                        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) != 0)
                                perror("ptrace");
                        /* 
                         *   switch to singlestep tracing and 
                         *   release child
                         *   if unable call error.
                         */
                        wait(&wait_val);
                        /*   wait for next instruction to complete  */

		// call another function to grab rwegisters..
		// emulate & log the instructions memory addresses
                ptrace(PTRACE_GETREGS, pid, NULL, &regs);

#ifdef defined(__i386__)
                printf("0 %X\n", regs.eip);
#else
                printf("0 %llu\n", regs.rip);
#endif

		emulate_log(pid);

                // we want to log our instruction address here..
                fwrite((void *)&regs.rip, sizeof(uint64_t), 1, ofd);

            }
        }

        printf("Number of machine instructions : %lld\n", counter);

	fclose(ofd);
        return 0;
}
