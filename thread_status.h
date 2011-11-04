/*
 *  thread_status.h
 *  Ripped headers from OS X so we can compile this in Windows...
 *
 */

/*
 * Copyright (c) 1999-2010 Apple Inc.  All Rights Reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#define i386_THREAD_STATE               1
#define i386_FLOAT_STATE                2
#define i386_EXCEPTION_STATE            3

#define x86_THREAD_STATE32              1
#define x86_FLOAT_STATE32               2
#define x86_EXCEPTION_STATE32           3
#define x86_THREAD_STATE64              4
#define x86_FLOAT_STATE64               5
#define x86_EXCEPTION_STATE64           6
#define x86_THREAD_STATE                7
#define x86_FLOAT_STATE                 8
#define x86_EXCEPTION_STATE             9
#define x86_DEBUG_STATE32               10
#define x86_DEBUG_STATE64               11
#define x86_DEBUG_STATE                 12
#define THREAD_STATE_NONE               13

#define PPC_THREAD_STATE        1
#define PPC_FLOAT_STATE         2
#define PPC_EXCEPTION_STATE             3
#define PPC_VECTOR_STATE                4
#define PPC_THREAD_STATE64              5
#define PPC_EXCEPTION_STATE64   6

#define _STRUCT_X86_THREAD_STATE32      struct i386_thread_state
_STRUCT_X86_THREAD_STATE32
{
    unsigned int        eax;
    unsigned int        ebx;
    unsigned int        ecx;
    unsigned int        edx;
    unsigned int        edi;
    unsigned int        esi;
    unsigned int        ebp;
    unsigned int        esp;
    unsigned int        ss;
    unsigned int        eflags;
    unsigned int        eip;
    unsigned int        cs;
    unsigned int        ds;
    unsigned int        es;
    unsigned int        fs;
    unsigned int        gs;
};

#define _STRUCT_X86_THREAD_STATE64      struct x86_thread_state64
_STRUCT_X86_THREAD_STATE64
{
	uint64_t      rax;
	uint64_t      rbx;
	uint64_t      rcx;
	uint64_t      rdx;
	uint64_t      rdi;
	uint64_t      rsi;
	uint64_t      rbp;
	uint64_t      rsp;
	uint64_t      r8;
	uint64_t      r9;
	uint64_t      r10;
	uint64_t      r11;
	uint64_t      r12;
	uint64_t      r13;
	uint64_t      r14;
	uint64_t      r15;
	uint64_t      rip;
	uint64_t      rflags;
	uint64_t      cs;
	uint64_t      fs;
	uint64_t      gs;
};

typedef _STRUCT_X86_THREAD_STATE32 i386_thread_state_t;
#define i386_THREAD_STATE_COUNT ((mach_msg_type_number_t) \
( sizeof (i386_thread_state_t) / sizeof (int) ))

typedef _STRUCT_X86_THREAD_STATE32 x86_thread_state32_t;
#define x86_THREAD_STATE32_COUNT        ((mach_msg_type_number_t) \
( sizeof (x86_thread_state32_t) / sizeof (int) ))


#define I386_EXCEPTION_STATE_COUNT i386_EXCEPTION_STATE_COUNT


#define X86_DEBUG_STATE32_COUNT x86_DEBUG_STATE32_COUNT

typedef _STRUCT_X86_THREAD_STATE64 x86_thread_state64_t;
#define x86_THREAD_STATE64_COUNT        ((mach_msg_type_number_t) \
( sizeof (x86_thread_state64_t) / sizeof (int) ))


#define X86_EXCEPTION_STATE64_COUNT x86_EXCEPTION_STATE64_COUNT

#define X86_DEBUG_STATE64_COUNT x86_DEBUG_STATE64_COUNT

#define _STRUCT_PPC_THREAD_STATE        struct __darwin_ppc_thread_state
_STRUCT_PPC_THREAD_STATE
{
	unsigned int __srr0;    /* Instruction address register (PC) */
	unsigned int __srr1;    /* Machine state register (supervisor) */
	unsigned int __r0;
	unsigned int __r1;
	unsigned int __r2;
	unsigned int __r3;
	unsigned int __r4;
	unsigned int __r5;
	unsigned int __r6;
	unsigned int __r7;
	unsigned int __r8;
	unsigned int __r9;
	unsigned int __r10;
	unsigned int __r11;
	unsigned int __r12;
	unsigned int __r13;
	unsigned int __r14;
	unsigned int __r15;
	unsigned int __r16;
	unsigned int __r17;
	unsigned int __r18;
	unsigned int __r19;
	unsigned int __r20;
	unsigned int __r21;
	unsigned int __r22;
	unsigned int __r23;
	unsigned int __r24;
	unsigned int __r25;
	unsigned int __r26;
	unsigned int __r27;
	unsigned int __r28;
	unsigned int __r29;
	unsigned int __r30;
	unsigned int __r31;
	
	unsigned int __cr;      /* Condition register */
	unsigned int __xer;     /* User's integer exception register */
	unsigned int __lr;      /* Link register */
	unsigned int __ctr;     /* Count register */
	unsigned int __mq;      /* MQ register (601 only) */
	
	unsigned int __vrsave;  /* Vector Save Register */
};

typedef _STRUCT_PPC_THREAD_STATE        ppc_thread_state_t;

