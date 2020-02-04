/*
 * Copyright (C) 2009 Tobias Brunner
 * Copyright (C) 2006 Martin Willi
 * HSR Hochschule fuer Technik Rapperswil
 *
 * Derived from Plutos DES library by Eric Young.
 *
 * Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are adhered to.
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the routines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publicly available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include "des_crypter.h"

typedef u_char des_cblock[DES_BLOCK_SIZE];

typedef struct des_ks_struct {
	des_cblock _;
} des_key_schedule[16];


typedef struct private_des_crypter_t private_des_crypter_t;

/**
 * Private data for des_crypter_t
 */
struct private_des_crypter_t {

	/**
	 * Public part of this class.
	 */
	des_crypter_t public;

	/**
	 * Key size, depends on algorithm...
	 */
	size_t key_size;

	union {
		/** key schedule for single des */
		des_key_schedule ks;
		/** key schedule for 3des */
		des_key_schedule ks3[3];
	};
};


#define DES_ENCRYPT 1
#define DES_DECRYPT 0

#define DES_LONG uint32_t

#if defined(WIN32) || defined(WIN16)
#ifndef MSDOS
#define MSDOS
#endif
#endif

#ifndef DES_DEFAULT_OPTIONS
/* the following is tweaked from a config script, that is why it is a
 * protected undef/define */
#ifndef DES_PTR
#define DES_PTR
#endif

/* This helps C compiler generate the correct code for multiple functional
 * units.  It reduces register dependencies at the expense of 2 more
 * registers */
#ifndef DES_RISC1
#define DES_RISC1
#endif

#ifndef DES_RISC2
#undef DES_RISC2
#endif

#if defined(DES_RISC1) && defined(DES_RISC2)
YOU SHOULD NOT HAVE BOTH DES_RISC1 AND DES_RISC2 DEFINED!!!!!
#endif

/* Unroll the inner loop, this sometimes helps, sometimes hinders.
 * Very much CPU dependent */
#ifndef DES_UNROLL
#define DES_UNROLL
#endif

/* These default values were supplied by
 * Peter Gutman <pgut001@cs.auckland.ac.nz>
 * They are only used if nothing else has been defined */
#if !defined(DES_PTR) && !defined(DES_RISC1) && !defined(DES_RISC2) && !defined(DES_UNROLL)
/* Special defines which change the way the code is built depending on the
   CPU and OS.  For SGI machines you can use _MIPS_SZLONG (32 or 64) to find
   even newer MIPS CPU's, but at the moment one size fits all for
   optimization options.  Older Sparc's work better with only UNROLL, but
   there's no way to tell at compile time what it is you're running on */

#if defined( sun )		/* Newer Sparc's */
#define DES_PTR
#define DES_RISC1
#define DES_UNROLL
#elif defined( __ultrix )	/* Older MIPS */
#define DES_PTR
#define DES_RISC2
#define DES_UNROLL
#elif defined( __osf1__ )	/* Alpha */
#define DES_PTR
#define DES_RISC2
#elif defined ( _AIX )		/* RS6000 */
  /* Unknown */
#elif defined( __hpux )		/* HP-PA */
  /* Unknown */
#elif defined( __aux )		/* 68K */
  /* Unknown */
#elif defined( __dgux )		/* 88K (but P6 in latest boxes) */
#define DES_UNROLL
#elif defined( __sgi )		/* Newer MIPS */
#define DES_PTR
#define DES_RISC2
#define DES_UNROLL
#elif defined( i386 )		/* x86 boxes, should be gcc */
#define DES_PTR
#define DES_RISC1
#define DES_UNROLL
#endif /* Systems-specific speed defines */
#endif

#endif /* DES_DEFAULT_OPTIONS */

#ifdef MSDOS		/* Visual C++ 2.1 (Windows NT/95) */
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <io.h>
#ifndef RAND
#define RAND
#endif
#undef NOPROTO
#endif

#if defined(__STDC__) || defined(VMS) || defined(M_XENIX) || defined(MSDOS)
#ifndef __KERNEL__
#include <string.h>
#else
#include <linux/string.h>
#endif
#endif

#ifndef RAND
#define RAND
#endif

#ifdef linux
#undef RAND
#endif

#ifdef MSDOS
#define getpid() 2
#define RAND
#undef NOPROTO
#endif

#if defined(NOCONST)
#define const
#endif

#ifdef __STDC__
#undef NOPROTO
#endif

#ifdef RAND
#define srandom(s) srand(s)
#define random rand
#endif

#define ITERATIONS 16
#define HALF_ITERATIONS 8

/* used in des_read and des_write */
#define MAXWRITE	(1024*16)
#define BSIZE		(MAXWRITE+4)

#define c2l(c,l)	(l =((DES_LONG)(*((c)++)))    , \
			 l|=((DES_LONG)(*((c)++)))<< 8L, \
			 l|=((DES_LONG)(*((c)++)))<<16L, \
			 l|=((DES_LONG)(*((c)++)))<<24L)

/* NOTE - c is not incremented as per c2l */
#define c2ln(c,l1,l2,n)	{ \
			c+=n; \
			l1=l2=0; \
			switch (n) { \
			case 8: l2 =((DES_LONG)(*(--(c))))<<24L; \
			case 7: l2|=((DES_LONG)(*(--(c))))<<16L; \
			case 6: l2|=((DES_LONG)(*(--(c))))<< 8L; \
			case 5: l2|=((DES_LONG)(*(--(c))));     \
			case 4: l1 =((DES_LONG)(*(--(c))))<<24L; \
			case 3: l1|=((DES_LONG)(*(--(c))))<<16L; \
			case 2: l1|=((DES_LONG)(*(--(c))))<< 8L; \
			case 1: l1|=((DES_LONG)(*(--(c))));     \
} \
}

#define l2c(l,c)	(*((c)++)=(unsigned char)(((l)     )&0xFF), \
			 *((c)++)=(unsigned char)(((l)>> 8L)&0xFF), \
			 *((c)++)=(unsigned char)(((l)>>16L)&0xFF), \
			 *((c)++)=(unsigned char)(((l)>>24L)&0xFF))

/* replacements for htonl and ntohl since I have no idea what to do
 * when faced with machines with 8 byte longs. */
#define HDRSIZE 4

#define n2l(c,l)	(l =((DES_LONG)(*((c)++)))<<24L, \
			 l|=((DES_LONG)(*((c)++)))<<16L, \
			 l|=((DES_LONG)(*((c)++)))<< 8L, \
			 l|=((DES_LONG)(*((c)++))))

#define l2n(l,c)	(*((c)++)=(unsigned char)(((l)>>24L)&0xFF), \
			 *((c)++)=(unsigned char)(((l)>>16L)&0xFF), \
			 *((c)++)=(unsigned char)(((l)>> 8L)&0xFF), \
			 *((c)++)=(unsigned char)(((l)     )&0xFF))

/* NOTE - c is not incremented as per l2c */
#define l2cn(l1,l2,c,n)	{ \
			c+=n; \
			switch (n) { \
			case 8: *(--(c))=(unsigned char)(((l2)>>24L)&0xFF); \
			case 7: *(--(c))=(unsigned char)(((l2)>>16L)&0xFF); \
			case 6: *(--(c))=(unsigned char)(((l2)>> 8L)&0xFF); \
			case 5: *(--(c))=(unsigned char)(((l2)     )&0xFF); \
			case 4: *(--(c))=(unsigned char)(((l1)>>24L)&0xFF); \
			case 3: *(--(c))=(unsigned char)(((l1)>>16L)&0xFF); \
			case 2: *(--(c))=(unsigned char)(((l1)>> 8L)&0xFF); \
			case 1: *(--(c))=(unsigned char)(((l1)     )&0xFF); \
} \
}

#if defined(WIN32)
#define	ROTATE(a,n)	(_lrotr(a,n))
#else
#define	ROTATE(a,n)	(((a)>>(n))+((a)<<(32-(n))))
#endif

/* Don't worry about the LOAD_DATA() stuff, that is used by
 * fcrypt() to add it's little bit to the front */

#ifdef DES_FCRYPT

#define LOAD_DATA_tmp(R,S,u,t,E0,E1) \
{ DES_LONG tmp; LOAD_DATA(R,S,u,t,E0,E1,tmp); }

#define LOAD_DATA(R,S,u,t,E0,E1,tmp) \
	t=R^(R>>16L); \
	u=t&E0; t&=E1; \
	tmp=(u<<16); u^=R^s[S  ]; u^=tmp; \
	tmp=(t<<16); t^=R^s[S+1]; t^=tmp
#else
#define LOAD_DATA_tmp(a,b,c,d,e,f) LOAD_DATA(a,b,c,d,e,f,g)
#define LOAD_DATA(R,S,u,t,E0,E1,tmp) \
	u=R^s[S  ]; \
	t=R^s[S+1]
#endif

/* The changes to this macro may help or hinder, depending on the
 * compiler and the architecture.  gcc2 always seems to do well :-).
 * Inspired by Dana How <how@isl.stanford.edu>
 * DO NOT use the alternative version on machines with 8 byte longs.
 * It does not seem to work on the Alpha, even when DES_LONG is 4
 * bytes, probably an issue of accessing non-word aligned objects :-( */
#ifdef DES_PTR

/* It recently occurred to me that 0^0^0^0^0^0^0 == 0, so there
 * is no reason to not xor all the sub items together.  This potentially
 * saves a register since things can be xored directly into L */

#if defined(DES_RISC1) || defined(DES_RISC2)
#ifdef DES_RISC1
#define D_ENCRYPT(LL,R,S) { \
	unsigned int u1,u2,u3; \
	LOAD_DATA(R,S,u,t,E0,E1,u1); \
	u2=(int)u>>8L; \
	u1=(int)u&0xFF; \
	u2&=0xFF; \
	t=ROTATE(t,4); \
	u>>=16L; \
	LL^= *(DES_LONG *)((unsigned char *)des_SP      +u1); \
	LL^= *(DES_LONG *)((unsigned char *)des_SP+0xFF+u2); \
	u3=(int)(u>>8L); \
	u1=(int)u&0xFF; \
	u3&=0xFF; \
	LL^= *(DES_LONG *)((unsigned char *)des_SP+0xFF+u1); \
	LL^= *(DES_LONG *)((unsigned char *)des_SP+0xFF+u3); \
	u2=(int)t>>8L; \
	u1=(int)t&0xFF; \
	u2&=0xFF; \
	t>>=16L; \
	LL^= *(DES_LONG *)((unsigned char *)des_SP+0xFF+u1); \
	LL^= *(DES_LONG *)((unsigned char *)des_SP+0xFF+u2); \
	u3=(int)t>>8L; \
	u1=(int)t&0xFF; \
	u3&=0xFF; \
	LL^= *(DES_LONG *)((unsigned char *)des_SP+0xFF+u1); \
	LL^= *(DES_LONG *)((unsigned char *)des_SP+0xFF+u3); }
#endif
#ifdef DES_RISC2
#define D_ENCRYPT(LL,R,S) { \
	unsigned int u1,u2,s1,s2; \
	LOAD_DATA(R,S,u,t,E0,E1,u1); \
	u2=(int)u>>8L; \
	u1=(int)u&0xFF; \
	u2&=0xFF; \
	t=ROTATE(t,4); \
	LL^= *(DES_LONG *)((unsigned char *)des_SP      +u1); \
	LL^= *(DES_LONG *)((unsigned char *)des_SP+0xFF+u2); \
	s1=(int)(u>>16L); \
	s2=(int)(u>>24L); \
	s1&=0xFF; \
	s2&=0xFF; \
	LL^= *(DES_LONG *)((unsigned char *)des_SP+0xFF+s1); \
	LL^= *(DES_LONG *)((unsigned char *)des_SP+0xFF+s2); \
	u2=(int)t>>8L; \
	u1=(int)t&0xFF; \
	u2&=0xFF; \
	LL^= *(DES_LONG *)((unsigned char *)des_SP+0xFF+u1); \
	LL^= *(DES_LONG *)((unsigned char *)des_SP+0xFF+u2); \
	s1=(int)(t>>16L); \
	s2=(int)(t>>24L); \
	s1&=0xFF; \
	s2&=0xFF; \
	LL^= *(DES_LONG *)((unsigned char *)des_SP+0xFF+s1); \
	LL^= *(DES_LONG *)((unsigned char *)des_SP+0xFF+s2); }
#endif
#else
#define D_ENCRYPT(LL,R,S) { \
	LOAD_DATA_tmp(R,S,u,t,E0,E1); \
	t=ROTATE(t,4); \
	LL^= \
	*(DES_LONG *)((unsigned char *)des_SP      +((u     )&0xFF))^ \
	*(DES_LONG *)((unsigned char *)des_SP+0xFF+((u>> 8L)&0xFF))^ \
	*(DES_LONG *)((unsigned char *)des_SP+0xFF+((u>>16L)&0xFF))^ \
	*(DES_LONG *)((unsigned char *)des_SP+0xFF+((u>>24L)&0xFF))^ \
	*(DES_LONG *)((unsigned char *)des_SP+0xFF+((t     )&0xFF))^ \
	*(DES_LONG *)((unsigned char *)des_SP+0xFF+((t>> 8L)&0xFF))^ \
	*(DES_LONG *)((unsigned char *)des_SP+0xFF+((t>>16L)&0xFF))^ \
	*(DES_LONG *)((unsigned char *)des_SP+0xFF+((t>>24L)&0xFF)); }
#endif

#else /* original version */

#if defined(DES_RISC1) || defined(DES_RISC2)
#ifdef DES_RISC1
#define D_ENCRYPT(LL,R,S) {\
	unsigned int u1,u2,u3; \
	LOAD_DATA(R,S,u,t,E0,E1,u1); \
	u>>=2L; \
	t=ROTATE(t,6); \
	u2=(int)u>>8L; \
	u1=(int)u&0xFF; \
	u2&=0xFF; \
	u>>=16L; \
	LL^=des_SPtrans[0][u1]; \
	LL^=des_SPtrans[2][u2]; \
	u3=(int)u>>8L; \
	u1=(int)u&0xFF; \
	u3&=0xFF; \
	LL^=des_SPtrans[4][u1]; \
	LL^=des_SPtrans[6][u3]; \
	u2=(int)t>>8L; \
	u1=(int)t&0xFF; \
	u2&=0xFF; \
	t>>=16L; \
	LL^=des_SPtrans[1][u1]; \
	LL^=des_SPtrans[3][u2]; \
	u3=(int)t>>8L; \
	u1=(int)t&0xFF; \
	u3&=0xFF; \
	LL^=des_SPtrans[5][u1]; \
	LL^=des_SPtrans[7][u3]; }
#endif
#ifdef DES_RISC2
#define D_ENCRYPT(LL,R,S) {\
	unsigned int u1,u2,s1,s2; \
	LOAD_DATA(R,S,u,t,E0,E1,u1); \
	u>>=2L; \
	t=ROTATE(t,6); \
	u2=(int)u>>8L; \
	u1=(int)u&0xFF; \
	u2&=0xFF; \
	LL^=des_SPtrans[0][u1]; \
	LL^=des_SPtrans[2][u2]; \
	s1=(int)u>>16L; \
	s2=(int)u>>24L; \
	s1&=0xFF; \
	s2&=0xFF; \
	LL^=des_SPtrans[4][s1]; \
	LL^=des_SPtrans[6][s2]; \
	u2=(int)t>>8L; \
	u1=(int)t&0xFF; \
	u2&=0xFF; \
	LL^=des_SPtrans[1][u1]; \
	LL^=des_SPtrans[3][u2]; \
	s1=(int)t>>16; \
	s2=(int)t>>24L; \
	s1&=0xFF; \
	s2&=0xFF; \
	LL^=des_SPtrans[5][s1]; \
	LL^=des_SPtrans[7][s2]; }
#endif

#else

#define D_ENCRYPT(LL,R,S) {\
	LOAD_DATA_tmp(R,S,u,t,E0,E1); \
	t=ROTATE(t,4); \
	LL^=\
		des_SPtrans[0][(u>> 2L)&0xFF]^ \
		des_SPtrans[2][(u>>10L)&0xFF]^ \
		des_SPtrans[4][(u>>18L)&0xFF]^ \
		des_SPtrans[6][(u>>26L)&0xFF]^ \
		des_SPtrans[1][(t>> 2L)&0xFF]^ \
		des_SPtrans[3][(t>>10L)&0xFF]^ \
		des_SPtrans[5][(t>>18L)&0xFF]^ \
		des_SPtrans[7][(t>>26L)&0xFF]; }
#endif
#endif

	/* IP and FP
	 * The problem is more of a geometric problem that random bit fiddling.
	 0  1  2  3  4  5  6  7      62 54 46 38 30 22 14  6
	 8  9 10 11 12 13 14 15      60 52 44 36 28 20 12  4
	16 17 18 19 20 21 22 23      58 50 42 34 26 18 10  2
	24 25 26 27 28 29 30 31  to  56 48 40 32 24 16  8  0

	32 33 34 35 36 37 38 39      63 55 47 39 31 23 15  7
	40 41 42 43 44 45 46 47      61 53 45 37 29 21 13  5
	48 49 50 51 52 53 54 55      59 51 43 35 27 19 11  3
	56 57 58 59 60 61 62 63      57 49 41 33 25 17  9  1

	The output has been subject to swaps of the form
	0 1 -> 3 1 but the odd and even bits have been put into
	2 3    2 0
	different words.  The main trick is to remember that
	t=((l>>size)^r)&(mask);
	r^=t;
	l^=(t<<size);
	can be used to swap and move bits between words.

	So l =  0  1  2  3  r = 16 17 18 19
	        4  5  6  7      20 21 22 23
	        8  9 10 11      24 25 26 27
	       12 13 14 15      28 29 30 31
	becomes (for size == 2 and mask == 0xFF)
	   t =   2^16  3^17 -- --   l =  0  1 16 17  r =  2  3 18 19
		 6^20  7^21 -- --        4  5 20 21       6  7 22 23
		10^24 11^25 -- --        8  9 24 25      10 11 24 25
		14^28 15^29 -- --       12 13 28 29      14 15 28 29

	Thanks for hints from Richard Outerbridge - he told me IP&FP
	could be done in 15 xor, 10 shifts and 5 ands.
	When I finally started to think of the problem in 2D
	I first got ~42 operations without xors.  When I remembered
	how to use xors :-) I got it to its final state.
	*/
#define PERM_OP(a,b,t,n,m) ((t)=((((a)>>(n))^(b))&(m)),\
	(b)^=(t),\
	(a)^=((t)<<(n)))

#define IP(l,r) \
{ \
	register DES_LONG tt; \
	PERM_OP(r,l,tt, 4,0xFF); \
	PERM_OP(l,r,tt,16,0xFF); \
	PERM_OP(r,l,tt, 2,0xFF); \
	PERM_OP(l,r,tt, 8,0xFF); \
	PERM_OP(r,l,tt, 1,0xFF); \
}

#define FP(l,r) \
{ \
	register DES_LONG tt; \
	PERM_OP(l,r,tt, 1,0xFF); \
	PERM_OP(r,l,tt, 8,0xFF); \
	PERM_OP(l,r,tt, 2,0xFF); \
	PERM_OP(r,l,tt,16,0xFF); \
	PERM_OP(l,r,tt, 4,0xFF); \
}

#ifndef NOPROTO
void fcrypt_body(DES_LONG *out,des_key_schedule ks,
				 DES_LONG Eswap0, DES_LONG Eswap1);
#else
void fcrypt_body();
#endif

static const DES_LONG des_skb[8][64]={
	{	/* for C bits (numbered as per FIPS 46) 1 2 3 4 5 6 */
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
	},
	{	/* for C bits (numbered as per FIPS 46) 7 8 10 11 12 13 */
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
	},
	{	/* for C bits (numbered as per FIPS 46) 14 15 16 17 19 20 */
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
	},
	{	/* for C bits (numbered as per FIPS 46) 21 23 24 26 27 28 */
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
	},
	{	/* for D bits (numbered as per FIPS 46) 1 2 3 4 5 6 */
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
	},
	{	/* for D bits (numbered as per FIPS 46) 8 9 11 12 13 14 */
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
	},
	{	/* for D bits (numbered as per FIPS 46) 16 17 18 19 20 21 */
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
	},
	{	/* for D bits (numbered as per FIPS 46) 22 23 24 25 27 28 */
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,
	}
};

const DES_LONG des_SPtrans[8][64]={
	{
		/* nibble 0 */
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
	},
	{	/* nibble 1 */
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
	},
	{	/* nibble 2 */
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
	},
	{	/* nibble 3 */
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
	},
	{	/* nibble 4 */
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
	},
	{	/* nibble 5 */
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
	},
	{	/* nibble 6 */
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
	},
	{	/* nibble 7 */
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
	}
};

#define HPERM_OP(a,t,n,m) ((t)=((((a)<<(16-(n)))^(a))&(m)),\
	(a)=(a)^(t)^(t>>(16-(n))))

static const unsigned char odd_parity[256]={
	1,  1,  2,  2,  4,  4,  7,  7,  8,  8, 11, 11, 13, 13, 14, 14,
	16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
	32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
	49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
	64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
	81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
	97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
	112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
	128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
	145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
	161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
	176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
	193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
	208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
	224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
	241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
};

/**
 * Create key schedule for a single DES 64Bit key
 */
static int des_set_key(des_cblock *key, des_key_schedule *schedule)
{
	static int shifts2[16] = {0,0,1,1,1,1,1,1,0,1,1,1,1,1,1,0};
	register DES_LONG c,d,t,s,t2;
	register unsigned char *in;
	register DES_LONG *k;
	register int i;
	des_cblock odd;

	for (i = 0; i < sizeof(des_cblock); i++)
	{
		odd[i] = odd_parity[(*key)[i]];
	}

	k=(DES_LONG *)schedule;
	in=(unsigned char *)&odd;

	c2l(in,c);
	c2l(in,d);

	/* do PC1 in 60 simple operations */
/*	PERM_OP(d,c,t,4,0xFF);
	HPERM_OP(c,t,-2, 0xFF);
	HPERM_OP(c,t,-1, 0xFF);
	HPERM_OP(c,t, 8, 0xFF);
	HPERM_OP(c,t,-1, 0xFF);
	HPERM_OP(d,t,-8, 0xFF);
	HPERM_OP(d,t, 8, 0xFF);
	HPERM_OP(d,t, 2, 0xFF);
	d=((d&0xFF)<<7L)|((d&0xFF)>>7L)|(d&0xFF);
	d=(d>>8)|((c&0xFF)>>4);
	c&=0xFF; */

	/* I now do it in 47 simple operations :-)
	* Thanks to John Fletcher (john_fletcher@lccmail.ocf.llnl.gov)
	* for the inspiration. :-) */
	PERM_OP (d,c,t,4,0xFF);
	HPERM_OP(c,t,-2,0xFF);
	HPERM_OP(d,t,-2,0xFF);
	PERM_OP (d,c,t,1,0xFF);
	PERM_OP (c,d,t,8,0xFF);
	PERM_OP (d,c,t,1,0xFF);
	d=	(((d&0xFF)<<16L)| (d&0xFF)     |
			((d&0xFF)>>16L)|((c&0xFF)>>4L));
	c&=0xFF;

	for (i=0; i<ITERATIONS; i++)
	{
		if (shifts2[i])
		{ c=((c>>2L)|(c<<26L)); d=((d>>2L)|(d<<26L)); }
		else
		{ c=((c>>1L)|(c<<27L)); d=((d>>1L)|(d<<27L)); }
		c&=0xFF;
		d&=0xFF;
		/* could be a few less shifts but I am to lazy at this
		* point in time to investigate */
		s=	des_skb[0][ (c    )&0xFF                ]|
				des_skb[1][((c>> 6)&0xFF)|((c>> 7L)&0xFF)]|
				des_skb[2][((c>>13)&0xFF)|((c>>14L)&0xFF)]|
				des_skb[3][((c>>20)&0xFF)|((c>>21L)&0xFF) |
				((c>>22L)&0xFF)];
		t=	des_skb[4][ (d    )&0xFF                ]|
				des_skb[5][((d>> 7L)&0xFF)|((d>> 8L)&0xFF)]|
				des_skb[6][ (d>>15L)&0xFF                ]|
				des_skb[7][((d>>21L)&0xFF)|((d>>22L)&0xFF)];

		/* table contained 0213 4657 */
		t2=((t<<16L)|(s&0xFF))&0xFF;
		*(k++)=ROTATE(t2,30)&0xFF;

		t2=((s>>16L)|(t&0xFF));
		*(k++)=ROTATE(t2,26)&0xFF;
	}
	return(0);
}


static void des_encrypt(DES_LONG *data, des_key_schedule ks, int enc)
{
	register DES_LONG l,r,t,u;
#ifdef DES_PTR
	register unsigned char *des_SP=(unsigned char *)des_SPtrans;
#endif
#ifndef DES_UNROLL
	register int i;
#endif
	register DES_LONG *s;

	r=data[0];
	l=data[1];

	IP(r,l);
	/* Things have been modified so that the initial rotate is
	* done outside the loop.  This required the
	* des_SPtrans values in sp.h to be rotated 1 bit to the right.
	* One perl script later and things have a 5% speed up on a sparc2.
	* Thanks to Richard Outerbridge <71755.204@CompuServe.COM>
	* for pointing this out. */
	/* clear the top bits on machines with 8byte longs */
	/* shift left by 2 */
	r=ROTATE(r,29)&0xFF;
	l=ROTATE(l,29)&0xFF;

	s=(DES_LONG *)ks;
	/* I don't know if it is worth the effort of loop unrolling the
	* inner loop */
	if (enc)
	{
#ifdef DES_UNROLL
		D_ENCRYPT(l,r, 0); /*  1 */
		D_ENCRYPT(r,l, 2); /*  2 */
		D_ENCRYPT(l,r, 4); /*  3 */
		D_ENCRYPT(r,l, 6); /*  4 */
		D_ENCRYPT(l,r, 8); /*  5 */
		D_ENCRYPT(r,l,10); /*  6 */
		D_ENCRYPT(l,r,12); /*  7 */
		D_ENCRYPT(r,l,14); /*  8 */
		D_ENCRYPT(l,r,16); /*  9 */
		D_ENCRYPT(r,l,18); /*  10 */
		D_ENCRYPT(l,r,20); /*  11 */
		D_ENCRYPT(r,l,22); /*  12 */
		D_ENCRYPT(l,r,24); /*  13 */
		D_ENCRYPT(r,l,26); /*  14 */
		D_ENCRYPT(l,r,28); /*  15 */
		D_ENCRYPT(r,l,30); /*  16 */
#else
		for (i=0; i<32; i+=8)
{
	D_ENCRYPT(l,r,i+0); /*  1 */
	D_ENCRYPT(r,l,i+2); /*  2 */
	D_ENCRYPT(l,r,i+4); /*  3 */
	D_ENCRYPT(r,l,i+6); /*  4 */
}
#endif
	}
	else
{
#ifdef DES_UNROLL
		D_ENCRYPT(l,r,30); /* 16 */
		D_ENCRYPT(r,l,28); /* 15 */
		D_ENCRYPT(l,r,26); /* 14 */
		D_ENCRYPT(r,l,24); /* 13 */
		D_ENCRYPT(l,r,22); /* 12 */
		D_ENCRYPT(r,l,20); /* 11 */
		D_ENCRYPT(l,r,18); /* 10 */
		D_ENCRYPT(r,l,16); /*  9 */
		D_ENCRYPT(l,r,14); /*  8 */
		D_ENCRYPT(r,l,12); /*  7 */
		D_ENCRYPT(l,r,10); /*  6 */
		D_ENCRYPT(r,l, 8); /*  5 */
		D_ENCRYPT(l,r, 6); /*  4 */
		D_ENCRYPT(r,l, 4); /*  3 */
		D_ENCRYPT(l,r, 2); /*  2 */
		D_ENCRYPT(r,l, 0); /*  1 */
#else
		for (i=30; i>0; i-=8)
{
	D_ENCRYPT(l,r,i-0); /* 16 */
	D_ENCRYPT(r,l,i-2); /* 15 */
	D_ENCRYPT(l,r,i-4); /* 14 */
	D_ENCRYPT(r,l,i-6); /* 13 */
}
#endif
}

	/* rotate and clear the top bits on machines with 8byte longs */
	l=ROTATE(l,3)&0xFF;
	r=ROTATE(r,3)&0xFF;

	FP(r,l);
	data[0]=l;
	data[1]=r;
	l=r=t=u=0;
}

/**
 * DES CBC encrypt decrypt routine
 */
static void des_cbc_encrypt(des_cblock *input, des_cblock *output, long length,
						    des_key_schedule schedule, des_cblock *ivec, int enc)
{
	register DES_LONG tin0,tin1;
	register DES_LONG tout0,tout1,xor0,xor1;
	register unsigned char *in,*out;
	register long l=length;
	DES_LONG tin[2];
	unsigned char *iv;

	in=(unsigned char *)input;
	out=(unsigned char *)output;
	iv=(unsigned char *)ivec;

	if (enc)
	{
		c2l(iv,tout0);
		c2l(iv,tout1);
		for (l-=8; l>=0; l-=8)
		{
			c2l(in,tin0);
			c2l(in,tin1);
			tin0^=tout0; tin[0]=tin0;
			tin1^=tout1; tin[1]=tin1;
			des_encrypt((DES_LONG *)tin,schedule,DES_ENCRYPT);
			tout0=tin[0]; l2c(tout0,out);
			tout1=tin[1]; l2c(tout1,out);
		}
		if (l != -8)
		{
			c2ln(in,tin0,tin1,l+8);
			tin0^=tout0; tin[0]=tin0;
			tin1^=tout1; tin[1]=tin1;
			des_encrypt((DES_LONG *)tin,schedule,DES_ENCRYPT);
			tout0=tin[0]; l2c(tout0,out);
			tout1=tin[1]; l2c(tout1,out);
		}
	}
	else
	{
		c2l(iv,xor0);
		c2l(iv,xor1);
		for (l-=8; l>=0; l-=8)
		{
			c2l(in,tin0); tin[0]=tin0;
			c2l(in,tin1); tin[1]=tin1;
			des_encrypt((DES_LONG *)tin,schedule,DES_DECRYPT);
			tout0=tin[0]^xor0;
			tout1=tin[1]^xor1;
			l2c(tout0,out);
			l2c(tout1,out);
			xor0=tin0;
			xor1=tin1;
		}
		if (l != -8)
		{
			c2l(in,tin0); tin[0]=tin0;
			c2l(in,tin1); tin[1]=tin1;
			des_encrypt((DES_LONG *)tin,schedule,DES_DECRYPT);
			tout0=tin[0]^xor0;
			tout1=tin[1]^xor1;
			l2cn(tout0,tout1,out,l+8);
		/*	xor0=tin0;
			xor1=tin1; */
		}
	}
	tin0=tin1=tout0=tout1=xor0=xor1=0;
	tin[0]=tin[1]=0;
}

/**
 * DES ECB encrypt decrypt routine
 */
static void des_ecb_encrypt(des_cblock *input, des_cblock *output, long length,
						    des_key_schedule schedule, int enc)
{
	register DES_LONG tin0,tin1;
	register DES_LONG tout0,tout1;
	register unsigned char *in,*out;
	register long l=length;
	DES_LONG tin[2];

	in=(unsigned char *)input;
	out=(unsigned char *)output;

	if (enc)
	{
		for (l-=8; l>=0; l-=8)
		{
			c2l(in,tin0); tin[0]=tin0;
			c2l(in,tin1); tin[1]=tin1;
			des_encrypt((DES_LONG *)tin,schedule,DES_ENCRYPT);
			tout0=tin[0]; l2c(tout0,out);
			tout1=tin[1]; l2c(tout1,out);
		}
		if (l != -8)
		{
			c2ln(in,tin0,tin1,l+8);
			tin[0]=tin0;
			tin[1]=tin1;
			des_encrypt((DES_LONG *)tin,schedule,DES_ENCRYPT);
			tout0=tin[0]; l2c(tout0,out);
			tout1=tin[1]; l2c(tout1,out);
		}
	}
	else
	{
		for (l-=8; l>=0; l-=8)
		{
			c2l(in,tin0); tin[0]=tin0;
			c2l(in,tin1); tin[1]=tin1;
			des_encrypt((DES_LONG *)tin,schedule,DES_DECRYPT);
			tout0=tin[0]; l2c(tout0,out);
			tout1=tin[1]; l2c(tout1,out);
		}
		if (l != -8)
		{
			c2l(in,tin0); tin[0]=tin0;
			c2l(in,tin1); tin[1]=tin1;
			des_encrypt((DES_LONG *)tin,schedule,DES_DECRYPT);
			tout0=tin[0];
			tout1=tin[1];
			l2cn(tout0,tout1,out,l+8);
		}
	}
	tin0=tin1=tout0=tout1=0;
	tin[0]=tin[1]=0;
}

static void des_encrypt2(DES_LONG *data, des_key_schedule ks, int enc)
{
	register DES_LONG l,r,t,u;
#ifdef DES_PTR
	register unsigned char *des_SP=(unsigned char *)des_SPtrans;
#endif
#ifndef DES_UNROLL
	register int i;
#endif
	register DES_LONG *s;

	r=data[0];
	l=data[1];

	/* Things have been modified so that the initial rotate is
	 * done outside the loop.  This required the
	 * des_SPtrans values in sp.h to be rotated 1 bit to the right.
	 * One perl script later and things have a 5% speed up on a sparc2.
	 * Thanks to Richard Outerbridge <71755.204@CompuServe.COM>
	 * for pointing this out.
	 * clear the top bits on machines with 8byte longs */
	r=ROTATE(r,29)&0xFF;
	l=ROTATE(l,29)&0xFF;

	s=(DES_LONG *)ks;
	/* I don't know if it is worth the effort of loop unrolling the
	* inner loop */
	if (enc)
	{
#ifdef DES_UNROLL
		D_ENCRYPT(l,r, 0); /*  1 */
		D_ENCRYPT(r,l, 2); /*  2 */
		D_ENCRYPT(l,r, 4); /*  3 */
		D_ENCRYPT(r,l, 6); /*  4 */
		D_ENCRYPT(l,r, 8); /*  5 */
		D_ENCRYPT(r,l,10); /*  6 */
		D_ENCRYPT(l,r,12); /*  7 */
		D_ENCRYPT(r,l,14); /*  8 */
		D_ENCRYPT(l,r,16); /*  9 */
		D_ENCRYPT(r,l,18); /*  10 */
		D_ENCRYPT(l,r,20); /*  11 */
		D_ENCRYPT(r,l,22); /*  12 */
		D_ENCRYPT(l,r,24); /*  13 */
		D_ENCRYPT(r,l,26); /*  14 */
		D_ENCRYPT(l,r,28); /*  15 */
		D_ENCRYPT(r,l,30); /*  16 */
#else
		for (i=0; i<32; i+=8)
{
	D_ENCRYPT(l,r,i+0); /*  1 */
	D_ENCRYPT(r,l,i+2); /*  2 */
	D_ENCRYPT(l,r,i+4); /*  3 */
	D_ENCRYPT(r,l,i+6); /*  4 */
}
#endif
	}
	else
{
#ifdef DES_UNROLL
		D_ENCRYPT(l,r,30); /* 16 */
		D_ENCRYPT(r,l,28); /* 15 */
		D_ENCRYPT(l,r,26); /* 14 */
		D_ENCRYPT(r,l,24); /* 13 */
		D_ENCRYPT(l,r,22); /* 12 */
		D_ENCRYPT(r,l,20); /* 11 */
		D_ENCRYPT(l,r,18); /* 10 */
		D_ENCRYPT(r,l,16); /*  9 */
		D_ENCRYPT(l,r,14); /*  8 */
		D_ENCRYPT(r,l,12); /*  7 */
		D_ENCRYPT(l,r,10); /*  6 */
		D_ENCRYPT(r,l, 8); /*  5 */
		D_ENCRYPT(l,r, 6); /*  4 */
		D_ENCRYPT(r,l, 4); /*  3 */
		D_ENCRYPT(l,r, 2); /*  2 */
		D_ENCRYPT(r,l, 0); /*  1 */
#else
		for (i=30; i>0; i-=8)
{
	D_ENCRYPT(l,r,i-0); /* 16 */
	D_ENCRYPT(r,l,i-2); /* 15 */
	D_ENCRYPT(l,r,i-4); /* 14 */
	D_ENCRYPT(r,l,i-6); /* 13 */
}
#endif
}
	/* rotate and clear the top bits on machines with 8byte longs */
	data[0]=ROTATE(l,3)&0xFF;
	data[1]=ROTATE(r,3)&0xFF;
	l=r=t=u=0;
}

/**
 * Single block 3DES EDE encrypt routine
 */
static void des_encrypt3(DES_LONG *data, des_key_schedule ks1,
						 des_key_schedule ks2, des_key_schedule ks3)
{
	register DES_LONG l,r;

	l=data[0];
	r=data[1];
	IP(l,r);
	data[0]=l;
	data[1]=r;
	des_encrypt2((DES_LONG *)data,ks1,DES_ENCRYPT);
	des_encrypt2((DES_LONG *)data,ks2,DES_DECRYPT);
	des_encrypt2((DES_LONG *)data,ks3,DES_ENCRYPT);
	l=data[0];
	r=data[1];
	FP(r,l);
	data[0]=l;
	data[1]=r;
}

/**
 * Single block 3DES EDE decrypt routine
 */
static void des_decrypt3(DES_LONG *data, des_key_schedule ks1,
						 des_key_schedule ks2, des_key_schedule ks3)
{
	register DES_LONG l,r;

	l=data[0];
	r=data[1];
	IP(l,r);
	data[0]=l;
	data[1]=r;
	des_encrypt2((DES_LONG *)data,ks3,DES_DECRYPT);
	des_encrypt2((DES_LONG *)data,ks2,DES_ENCRYPT);
	des_encrypt2((DES_LONG *)data,ks1,DES_DECRYPT);
	l=data[0];
	r=data[1];
	FP(r,l);
	data[0]=l;
	data[1]=r;
}

/**
 * 3DES EDE CBC encrypt/decrypt routine
 */
static void des_ede3_cbc_encrypt(des_cblock *input, des_cblock *output, long length,
								 des_key_schedule ks1, des_key_schedule ks2,
								 des_key_schedule ks3, des_cblock *ivec, int enc)
{
	register DES_LONG tin0,tin1;
	register DES_LONG tout0,tout1,xor0,xor1;
	register unsigned char *in,*out;
	register long l=length;
	DES_LONG tin[2];
	unsigned char *iv;

	in=(unsigned char *)input;
	out=(unsigned char *)output;
	iv=(unsigned char *)ivec;

	if (enc)
	{
		c2l(iv,tout0);
		c2l(iv,tout1);
		for (l-=8; l>=0; l-=8)
		{
			c2l(in,tin0);
			c2l(in,tin1);
			tin0^=tout0;
			tin1^=tout1;

			tin[0]=tin0;
			tin[1]=tin1;
			des_encrypt3((DES_LONG *)tin,ks1,ks2,ks3);
			tout0=tin[0];
			tout1=tin[1];

			l2c(tout0,out);
			l2c(tout1,out);
		}
		if (l != -8)
		{
			c2ln(in,tin0,tin1,l+8);
			tin0^=tout0;
			tin1^=tout1;

			tin[0]=tin0;
			tin[1]=tin1;
			des_encrypt3((DES_LONG *)tin,ks1,ks2,ks3);
			tout0=tin[0];
			tout1=tin[1];

			l2c(tout0,out);
			l2c(tout1,out);
		}
		iv=(unsigned char *)ivec;
		l2c(tout0,iv);
		l2c(tout1,iv);
	}
	else
	{
		register DES_LONG t0,t1;

		c2l(iv,xor0);
		c2l(iv,xor1);
		for (l-=8; l>=0; l-=8)
		{
			c2l(in,tin0);
			c2l(in,tin1);

			t0=tin0;
			t1=tin1;

			tin[0]=tin0;
			tin[1]=tin1;
			des_decrypt3((DES_LONG *)tin,ks1,ks2,ks3);
			tout0=tin[0];
			tout1=tin[1];

			tout0^=xor0;
			tout1^=xor1;
			l2c(tout0,out);
			l2c(tout1,out);
			xor0=t0;
			xor1=t1;
		}
		if (l != -8)
		{
			c2l(in,tin0);
			c2l(in,tin1);

			t0=tin0;
			t1=tin1;

			tin[0]=tin0;
			tin[1]=tin1;
			des_decrypt3((DES_LONG *)tin,ks1,ks2,ks3);
			tout0=tin[0];
			tout1=tin[1];

			tout0^=xor0;
			tout1^=xor1;
			l2cn(tout0,tout1,out,l+8);
			xor0=t0;
			xor1=t1;
		}

		iv=(unsigned char *)ivec;
		l2c(xor0,iv);
		l2c(xor1,iv);
	}
	tin0=tin1=tout0=tout1=xor0=xor1=0;
	tin[0]=tin[1]=0;
}

METHOD(crypter_t, decrypt, bool,
	private_des_crypter_t *this, chunk_t data, chunk_t iv, chunk_t *decrypted)
{
	des_cblock ivb;
	uint8_t *out;

	out = data.ptr;
	if (decrypted)
	{
		*decrypted = chunk_alloc(data.len);
		out = decrypted->ptr;
	}
	memcpy(&ivb, iv.ptr, sizeof(des_cblock));
	des_cbc_encrypt((des_cblock*)(data.ptr), (des_cblock*)out,
					 data.len, this->ks, &ivb, DES_DECRYPT);
	return TRUE;
}


METHOD(crypter_t, encrypt, bool,
	private_des_crypter_t *this, chunk_t data, chunk_t iv, chunk_t *encrypted)
{
	des_cblock ivb;
	uint8_t *out;

	out = data.ptr;
	if (encrypted)
	{
		*encrypted = chunk_alloc(data.len);
		out = encrypted->ptr;
	}
	memcpy(&ivb, iv.ptr, sizeof(des_cblock));
	des_cbc_encrypt((des_cblock*)(data.ptr), (des_cblock*)out,
					 data.len, this->ks, &ivb, DES_ENCRYPT);
	return TRUE;
}

METHOD(crypter_t, decrypt_ecb, bool,
	private_des_crypter_t *this, chunk_t data, chunk_t iv, chunk_t *decrypted)
{
	uint8_t *out;

	out = data.ptr;
	if (decrypted)
	{
		*decrypted = chunk_alloc(data.len);
		out = decrypted->ptr;
	}
	des_ecb_encrypt((des_cblock*)(data.ptr), (des_cblock*)out,
					 data.len, this->ks, DES_DECRYPT);
	return TRUE;
}

METHOD(crypter_t, encrypt_ecb, bool,
	private_des_crypter_t *this, chunk_t data, chunk_t iv, chunk_t *encrypted)
{
	uint8_t *out;

	out = data.ptr;
	if (encrypted)
	{
		*encrypted = chunk_alloc(data.len);
		out = encrypted->ptr;
	}
	des_ecb_encrypt((des_cblock*)(data.ptr), (des_cblock*)out,
					 data.len, this->ks, DES_ENCRYPT);
	return TRUE;
}

METHOD(crypter_t, decrypt3, bool,
	private_des_crypter_t *this, chunk_t data, chunk_t iv, chunk_t *decrypted)
{
	des_cblock ivb;
	uint8_t *out;

	out = data.ptr;
	if (decrypted)
	{
		*decrypted = chunk_alloc(data.len);
		out = decrypted->ptr;
	}
	memcpy(&ivb, iv.ptr, sizeof(des_cblock));
	des_ede3_cbc_encrypt((des_cblock*)(data.ptr), (des_cblock*)out,
						 data.len, this->ks3[0], this->ks3[1], this->ks3[2],
						 &ivb, DES_DECRYPT);
	return TRUE;
}

METHOD(crypter_t, encrypt3, bool,
	private_des_crypter_t *this, chunk_t data, chunk_t iv, chunk_t *encrypted)
{
	des_cblock ivb;
	uint8_t *out;

	out = data.ptr;
	if (encrypted)
	{
		*encrypted = chunk_alloc(data.len);
		out = encrypted->ptr;
	}
	memcpy(&ivb, iv.ptr, sizeof(des_cblock));
	des_ede3_cbc_encrypt((des_cblock*)(data.ptr), (des_cblock*)out,
						  data.len, this->ks3[0], this->ks3[1], this->ks3[2],
						  &ivb, DES_ENCRYPT);
	return TRUE;
}

METHOD(crypter_t, get_block_size, size_t,
	private_des_crypter_t *this)
{
	return sizeof(des_cblock);
}

METHOD(crypter_t, get_iv_size, size_t,
	private_des_crypter_t *this)
{
	return sizeof(des_cblock);
}

METHOD(crypter_t, get_key_size, size_t,
	private_des_crypter_t *this)
{
	return this->key_size;
}

METHOD(crypter_t, set_key, bool,
	private_des_crypter_t *this, chunk_t key)
{
	des_set_key((des_cblock*)(key.ptr), &this->ks);
	return TRUE;
}

METHOD(crypter_t, set_key3, bool,
	private_des_crypter_t *this, chunk_t key)
{
	des_set_key((des_cblock*)(key.ptr) + 0, &this->ks3[0]);
	des_set_key((des_cblock*)(key.ptr) + 1, &this->ks3[1]);
	des_set_key((des_cblock*)(key.ptr) + 2, &this->ks3[2]);
	return TRUE;
}

METHOD(crypter_t, destroy, void,
	private_des_crypter_t *this)
{
	memwipe(this, sizeof(*this));
	free(this);
}

/*
 * Described in header
 */
des_crypter_t *des_crypter_create(encryption_algorithm_t algo)
{
	private_des_crypter_t *this;

	INIT(this,
		.public = {
			.crypter = {
				.get_block_size = _get_block_size,
				.get_iv_size = _get_iv_size,
				.get_key_size = _get_key_size,
				.destroy = _destroy,
			},
		},
	);

	/* use functions depending on algorithm */
	switch (algo)
	{
		case ENCR_DES:
			this->key_size = sizeof(des_cblock);
			this->public.crypter.set_key = _set_key;
			this->public.crypter.encrypt = _encrypt;
			this->public.crypter.decrypt = _decrypt;
			break;
		case ENCR_3DES:
			this->key_size = 3 * sizeof(des_cblock);
			this->public.crypter.set_key = _set_key3;
			this->public.crypter.encrypt = _encrypt3;
			this->public.crypter.decrypt = _decrypt3;
			break;
		case ENCR_DES_ECB:
			this->key_size = sizeof(des_cblock);
			this->public.crypter.set_key = _set_key;
			this->public.crypter.encrypt = _encrypt_ecb;
			this->public.crypter.decrypt = _decrypt_ecb;
			break;
		default:
			free(this);
			return NULL;
	}
	return &this->public;
}
