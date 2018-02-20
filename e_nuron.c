/* engines/e_hw_pmm.c */
/*
 * Written by _Joerij_Zagoel_.
 */
/* ====================================================================
 * Copyright (c) 2000-2001 _Joerij_Zagoel_.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by _Joerij_Zagoel_"
 *
 * 5. Products derived from this software must inform _Joerij_Zagoel_ 
 *    of their existence.  
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by _Joerij_Zagoel_"
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR 
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE Author OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/dso.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
# include <openssl/dsa.h>
#endif
#ifndef OPENSSL_NO_DH
# include <openssl/dh.h>
#endif
#include <openssl/bn.h>
#include "../crypto/bn/bn_lcl.h"

#ifndef OPENSSL_NO_HW
# ifndef OPENSSL_NO_HW_plpmm

#  define plpmm_LIB_NAME "pmm engine"
#  include "e_nuron_err.c"
//#  include "e_hw_pmm_err.c"

/* Constants used when creating the ENGINE */
static const char *engine_plpmm_id = "padlockPMM";
static const char *engine_plpmm_name = "padlock pmm hardware engine support";

/* *******************************************************************************
 * 
 * 
 * 
 * */
  
#include <time.h>
#include <sys/timeb.h>

static double Time_Fl(int s);
#define START   0
#define STOP    1

static double Time_Fl(int s)
{
    static clock_t  tstart, tend;
    double duration = 0.0;

    if (s == START) {
        tstart=clock(); 
        return (0);
    } else {
        tend=clock();
        duration = (double)(tend - tstart) / CLOCKS_PER_SEC;
        return duration;
    }

}

#define timeFn(FN, STR) { double tm ; int num=100, i=num ; Time_Fl(START); \
                while (i--) FN ; tm=Time_Fl(STOP) ; printf( "\n %s duration :\t%6.6f milisecond \n", STR, 1000 * tm / num ); }

/* *******************************************************************************
 * 
 * 
 * 
 * */
 
// #define BN_mod_mul_montgomeryNNN BN_mod_mul_montgomery
 
int gbVerbose= 1 ; 
int gbIsNano= 0 ; 
int gbShouldOptimizeReloadBN1 = 1 ; 

long g_pmm_Ndigits = 0 ;
uint64_t g_pmm_NZero = 0;

static int g_pmm_mod_exp_mont_counter = 0 ; 
static int g_pmm_mont_mul_padlock_counter2 = 0 ; 
static int g_pmm_mod_exp_counter = 0 ;
static int g_pmm_mont_mul_padlock_counter = 0 ; 
static int g_pmm_bn1_counter = 0 ; 
static int g_pmm_bn1saved_counter = 0 ; 
static int g_pmm_bn1restored_counter = 0 ;
static int g_pmm_modChange_counter = 0 ; 
static int g_pmm_modLenChange_counter = 0 ; 
static int g_pmm_bnLess32_counter = 0 ; 

BIGNUM g_pmm_bn1RR ; 
 
 
typedef int TfnBNModExp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                       const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
static TfnBNModExp * g_original_fnBNMod_exp = NULL ;  
 
#define byteBuf2Hex(pBuf,len)    { int k ; for(k= len - 1 ; k >= 0 ;--k) printf("%.2x",(unsigned char)(((char*)pBuf)[k])); }
 


#define PMM_MAX_BITS 32768
#define PMM_MAX_WORDS (PMM_MAX_BITS / 32) // 
#define PMM_MAX_BYTES (PMM_MAX_WORDS * 4) // 

typedef struct  
{
	uint32_t  mZeroPrime;
	uint32_t* A;
	uint32_t* B;
	uint32_t* RES;
	uint32_t* M;
	uint32_t* scratch;
} PMM_CTX;

PMM_CTX pmm_ctx = {0};
PMM_CTX pmm_prev_ctx = {0};

typedef struct  
{
	BIGNUM* a;
	BIGNUM* b;
	BIGNUM* dst;
	BIGNUM* m;
	uint32_t  mZeroPrime;
} PMM_MMUL_CTX;

PMM_MMUL_CTX pmm_prev_mmul_ctx = {0};



static int pmm__bigIntGTE(uint32_t *A, uint32_t *B ,uint32_t LENGTH)
{
	int i;

    // so two extra bytes  b[LENGTH] and b[LENGTH+1] are also checked, in case of overflow.
	for (i = LENGTH + 1; i >= 0; i--) {
		if (A[i] > B[i]) return 1; //true
		if (A[i] < B[i]) return 0; //false
	}
	return 1;
}

static void pmm__bigIntSub(uint32_t *A, uint32_t *B, uint32_t LENGTH)
{
	uint32_t i,j;

	for (i = 0; i < LENGTH + 2; i++) {

		if (B[i] > A[i]) {
			j = i+1;
			A[j]--;
			while (A[j] == 0xFFFFFFFF)
				A[++j]--;
		}
		A[i] = A[i] - B[i];
	}
}

static uint32_t pmm__big_int_inv_mon( uint32_t *mod)/* */
{
	uint32_t i;
	uint64_t x = 2, y = 1;
	uint64_t mZero = (uint64_t)(mod[0]);

	for (i = 2; i <= 32; i++, x <<= 1) 
	{
		if (x < ((mZero * y) & ((x << 1) - 1))) 
		{
			y += x;
		}
	}
	return (uint32_t)(x - y);
}

uint32_t *pmm_a_temp_buf = NULL;
uint32_t *pmm_b_temp_buf = NULL;
uint32_t *pmm_res_temp_buf = NULL; // additional 16 bytes for case of overflow
uint32_t *pmm_m_temp_buf = NULL;
uint32_t *pmm_a_temp_bufAL = NULL; // 16byte alligned address
uint32_t *pmm_b_temp_bufAL = NULL;
uint32_t *pmm_res_temp_bufAL = NULL; // additional 16 bytes for case of overflow
uint32_t *pmm_m_temp_bufAL = NULL;
unsigned char *pmm_scratchBuf = NULL;
uint32_t g_pmm_NdigitsMax= 0 ; 



void padlock_pmm_free()
{
#define pmm_free_buf(a)     {if(a) {free(a) ; a= NULL ; }}
   
    pmm_free_buf(pmm_scratchBuf);
    pmm_free_buf(pmm_a_temp_bufAL);
    pmm_free_buf(pmm_b_temp_bufAL);
    pmm_free_buf(pmm_m_temp_bufAL);
    pmm_free_buf(pmm_res_temp_bufAL);
}

int padlock_pmm_init_internal(uint32_t ndigits, uint32_t* M)
{
    if ( ndigits * 4 < PMM_MAX_BYTES )
    {
        pmm_a_temp_bufAL = aligned_alloc(16, ndigits*4 + 16 );  // A  must be a multiple of 128 bits/16bytes  
        pmm_b_temp_bufAL = aligned_alloc(16, ndigits*4 + 16 );  // B
        pmm_res_temp_bufAL = aligned_alloc(16, ndigits*4 + 16 );  // T , + 16 = additional 16 bytes for case of overflow
        pmm_m_temp_bufAL = aligned_alloc(16, ndigits*4 + 16 );  // M
            
        pmm_scratchBuf = aligned_alloc(16, 4*8);  //(unsigned char*)malloc(4 * 8 + 15);
    }
    else 
        return 1 ; 
        
    if(!pmm_scratchBuf || !pmm_a_temp_bufAL || !pmm_b_temp_bufAL || !pmm_res_temp_bufAL || !pmm_m_temp_bufAL)
        goto err ; 
        
    /* PMM hardware require:
		1)the A, B, M, T in the mmCTX should be pointer to a buffer with MAX_BYTES bytes
		2)the buffer should be 16-byte aligned.
		*/
    pmm_ctx.A = pmm_a_temp_bufAL ;
	pmm_ctx.B = pmm_b_temp_bufAL;
	pmm_ctx.M = pmm_m_temp_bufAL ;
	pmm_ctx.RES = pmm_res_temp_bufAL;
    pmm_ctx.scratch = (uint32_t*)pmm_scratchBuf;
        
        
    memset(&pmm_prev_ctx, 0, sizeof(pmm_prev_ctx)) ; 
    
    memset(&pmm_prev_mmul_ctx, 0, sizeof(pmm_prev_mmul_ctx)) ; 
    
    
    return 0 ; 
    
err:
    padlock_pmm_free() ; 

    return 2 ;
}





int padlock_pmm_init(uint32_t ndigits)
{
    if ( ndigits > g_pmm_NdigitsMax) {
        padlock_pmm_free() ; 
        
        if( 0 == padlock_pmm_init_internal(ndigits, NULL)) 
            g_pmm_NdigitsMax= ndigits ; 
    }
    return 0 ; 
}

        
#define init_ctxM(pMctx) { if (pMctx->N.top >= g_MIN_NUMDIGITS_FOR_PMM && pMctx->N.top % 4 == 0) { \
        padlock_pmm_init(pMctx->N.top) ; pmm_ctx.mZeroPrime = pMctx->n0[0]; \
        memcpy((unsigned char*)pmm_ctx.M, (unsigned char*)pMctx->N.d, (pMctx->N.top * 4)); \
        memset((unsigned char*)(pmm_ctx.M + pMctx->N.top), 0, 8 ); }}
        // extra 8 bytes should be reset at the end, so that overflow detection would work correct = 2 x ( int of 4 bytes) 
 
     
        
////////////////////////////////////////////////////////////////

int padlock_pmmAL(PMM_CTX * ctx, uint32_t ndigits )
{
    if (1) {
        
        if ( ndigits < 8 ) 
            return 3 ; 
        
		int dummy = 0;
		int	nbits = ndigits << 5;
        
        //PMM_CTX ctx = &pmm_ctx ;

        memset((unsigned char*)ctx->RES, 0, (ndigits*4 + 16 ));

        //ctx->A= A ;  
        //ctx->B= B ; 
        // ctx->M= M ; shoudl be allocated set already
        // ctx->scratch    --- should be allocated already
        // ctx->mPrimeZero --- should be set already,  but it appears that it is not used at all ???
        
		//asm_pmm_op3(nbits, dummy,  &ctx);
        
        asm( "movl    %1, %%ecx             \n\t"
         "movl    %2, %%eax             \n\t"
         "movl    %3, %%esi             \n\t"
         ".byte  0xf3,0x0f,0xa6,0xc0    \n\t"
         "movl  %%edx, %0               \n\t" 
         : "=m" (dummy)
         : "m" (nbits), "m" (dummy), "m"  (ctx)
         : "memory", "eax", "ecx", "edx", "esi", "ebp" );
         
         // edx can be replaced by edi ???


        // NANO cpu does not need this check ,  EDEN does
        if ( ! gbIsNano ) if (pmm__bigIntGTE(ctx->RES, ctx->M, ndigits)) {
            //printf("\n org ctx.RES: ") ; byteBuf2Hex(ctx->RES, (ndigits +1) * 4 ) ;
            //printf("\n org ctx.M  : ") ; byteBuf2Hex(ctx->M, (ndigits +1)* 4 ) ;
            
			pmm__bigIntSub(ctx->RES, ctx->M, ndigits);
            
            //printf("\n new ctx.RES: ") ; byteBuf2Hex(ctx->RES, (ndigits +1) * 4) ;
            //printf("\n") ;
        }

        //memcpy((unsigned char*)dst, (unsigned char*)ctx->RES, (ndigits * 4));
        
        //ctx->A= pmm_a_temp_bufAL ;
        //ctx->B= pmm_b_temp_bufAL ;
	}
    
    return 0 ; 
    
}

//   binary: 0000 0000 1000 0000
#define PMM_BN_FLG_CLEAN     128
#define pmmIsBNclean(a) ( a->flags & PMM_BN_FLG_CLEAN )

unsigned long g_nocopyAT_counter= 0 ; 
unsigned long g_nocopyBT_counter= 0 ; 
unsigned long g_nocopyA_counter= 0 ; 
unsigned long g_nocopyB_counter= 0 ; 
unsigned long g_nocopyBA_counter= 0 ; 

int g_MIN_NUMDIGITS_FOR_PMM= 8 ;  // 8 eden; //24 nano

int pmm_mod_mul_montgomeryAL(BIGNUM *dst, const BIGNUM * a, const BIGNUM *b, BN_MONT_CTX *mont, BN_CTX *ctx)
{
    int ret= 0; 
    int AisSet= 0, BisSet=0 ; 
    
     
    if ( a->top < mont->N.top || b->top < mont->N.top ) {
        
        ret = BN_mod_mul_montgomery( dst, a, b, mont, ctx) ;
        if ( pmmIsBNclean(dst))
            dst->flags ^= PMM_BN_FLG_CLEAN;  // dirty
        g_pmm_bn1_counter++ ; 

    }
    else if ( mont->N.top < g_MIN_NUMDIGITS_FOR_PMM || mont->N.top % 4 != 0 ){  
        // Padlock pmm needs numbers of at least 256 bits  =  8 words * 4 = 32 bytes  * 8 = 256 bits
        // and number of bits mod 128 == 0 
        ret = BN_mod_mul_montgomery( dst, a, b, mont, ctx) ;
        if ( pmmIsBNclean(dst))
            dst->flags ^= PMM_BN_FLG_CLEAN;  // dirty
        g_pmm_bnLess32_counter++ ; 
    } 
    else
    { 
        
  
        if (bn_wexpand(dst, mont->N.top ) == NULL) return (0); 
        dst->top = mont->N.top ;
 
#define OPTIMIZE_PMMBUF_MEMCPY 
#ifdef OPTIMIZE_PMMBUF_MEMCPY
    
        // if  prev dst is clean, then dst can be reused as input in case a == dst'  or b == dst'  ( where x' is an x from previous run ) 
        if (  pmm_prev_mmul_ctx.dst && pmmIsBNclean(pmm_prev_mmul_ctx.dst) ) {  
            if ( a == pmm_prev_mmul_ctx.dst) { 
                pmm_ctx.A= pmm_prev_ctx.RES ; 
                //pmm_ctx.RES= pmm_prev_ctx.A ; 
                AisSet = 1 ; 
                g_nocopyAT_counter++ ; 
            }
            if ( b == pmm_prev_mmul_ctx.dst ) { 
                pmm_ctx.B= pmm_prev_ctx.RES ; 
                //pmm_ctx.RES= pmm_prev_ctx.B ; 
                BisSet = 1 ;
                g_nocopyBT_counter++ ; 
            }
        }
        // look for reuse of in case of a == b, or  a == a' or b == b'   ( where x' is an x from previous run ) 
        
        // a == a' and a' is clean
        if (  a != pmm_prev_mmul_ctx.dst) if ( !AisSet && a == pmm_prev_mmul_ctx.a && pmmIsBNclean(pmm_prev_mmul_ctx.a) ) { // should also check pmm_prev_mmul_ctx.a == NULL , but not really
            pmm_ctx.A= pmm_prev_ctx.A ; 
            AisSet = 1 ; 
            g_nocopyA_counter++ ; 
            //if ( pmm_ctx.RES == pmm_ctx.A ) // can happen when a' == b'  and  dst' == b
                //pmm_ctx.RES= pmm_a_temp_bufAL ; 
        }
        
        if ( !AisSet ) {
            memcpy((unsigned char*)pmm_ctx.A, (unsigned char*)a->d, (a->top * 4));  // a->top should be equal to mont->N.top, which is checked earlier
            AisSet= 1; 
        }
        
        // b == b' and b' is clean
        if (  b != pmm_prev_mmul_ctx.dst) if ( !BisSet && b == pmm_prev_mmul_ctx.b && pmmIsBNclean(pmm_prev_mmul_ctx.b) ) { // should also check pmm_prev_mmul_ctx.b == NULL , but not really
            pmm_ctx.B= pmm_prev_ctx.B ;
            BisSet = 1 ;
            g_nocopyB_counter++ ; 
            //if ( pmm_ctx.RES == pmm_ctx.B ) // can happen when a' == b'  and  dst' == a
                //pmm_ctx.RES= pmm_b_temp_bufAL ; 
        }
                
        
        if ( !BisSet ) { 
            if (  b == a ) { 
                pmm_ctx.B= pmm_ctx.A ; 
                g_nocopyBA_counter++ ; 
            }
            else 
                memcpy((unsigned char*)pmm_ctx.B, (unsigned char*)b->d, (b->top * 4));  // a->top should be equal to mont->N.top, which is checked earlier
                
            BisSet= 1; 
        }
     
        // pmm_ctx.RES == pmm_res_temp_bufAL ; 
        if ( pmm_ctx.RES == pmm_ctx.A || pmm_ctx.RES == pmm_ctx.B ) 
            pmm_ctx.RES = pmm_a_temp_bufAL ; 
        
        if ( pmm_ctx.RES == pmm_ctx.A || pmm_ctx.RES == pmm_ctx.B ) 
            pmm_ctx.RES = pmm_b_temp_bufAL ;

#else
        memcpy((unsigned char*)pmm_ctx.A, (unsigned char*)a->d, (a->top * 4));  // a->top should be equal to mont->N.top, which is checked earlier
        memcpy((unsigned char*)pmm_ctx.B, (unsigned char*)b->d, (b->top * 4));  // a->top should be equal to mont->N.top, which is checked earlier
                
#endif 
        // pmm_ctx.RES must not be == pmm_ctx.A or pmm_ctx.B
        if ( pmm_ctx.RES == pmm_ctx.A || pmm_ctx.RES == pmm_ctx.B ) { 
            printf("pmm_mod_mul_montgomeryAL: RES must not be == A or B\n") ; 
            ret = 2 ; 
        }
        else if ( 0 == padlock_pmmAL( &pmm_ctx, mont->N.top)) { 
            ret= 1 ; 
            memcpy((unsigned char*)dst->d, (unsigned char*)pmm_ctx.RES, (mont->N.top * 4));
        }
        
        dst->flags |= PMM_BN_FLG_CLEAN;
        
        pmm_prev_ctx.A = pmm_ctx.A ; 
        pmm_prev_ctx.B = pmm_ctx.B ; 
        pmm_prev_ctx.RES = pmm_ctx.RES ; 
        
        g_pmm_mont_mul_padlock_counter++ ; 
        
        pmm_ctx.A = pmm_a_temp_bufAL ; 
        pmm_ctx.B = pmm_b_temp_bufAL ; 
        pmm_ctx.RES = pmm_res_temp_bufAL ; 
        
        pmm_prev_mmul_ctx.dst= dst ; 
        pmm_prev_mmul_ctx.a = a; 
        pmm_prev_mmul_ctx.b = b; 
        
        
    }
    
    return ret ; 
}


/*
 * This method was liberated and adapted from crypto/bn/bn_exp.c
 */

int pmm_BN_mod_exp_montAL(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
/* maximum precomputation table size for *variable* sliding windows */
#define TABLE_SIZE      32

    int i, j, bits, ret = 0, wstart, wend, window, wvalue;
    int start = 1;
    BIGNUM *d, *r;
    const BIGNUM *aa;
    /* Table of variables obtained from 'ctx' */
    BIGNUM *val[TABLE_SIZE];
    BN_MONT_CTX *mont = NULL;

    bn_check_top(a);
    bn_check_top(p);
    bn_check_top(m);

/*    if ( p->top < a->top )
        printf(" p.len < a.len p.len= %d p[0]= %d \n", p->top, *(p->d)) ;
    else 
        printf(" p.len= %d p[0]= %d \n", p->top, *(p->d)) ;
*/        
    if (a->top == 1 && !a->neg ) 
        printf("BNerr(BN_F_BN_MOD_EXP_MONT, BN_R_CALLED_WITH_SINGLE_DIGIT_A)\n") ; 
    if (!BN_is_odd(m)) {
        //BNerr(BN_F_BN_MOD_EXP_MONT, BN_R_CALLED_WITH_EVEN_MODULUS);
        printf ("BNerr(BN_F_BN_MOD_EXP_MONT, BN_R_CALLED_WITH_EVEN_MODULUS)") ; 
        return (0);
    }
    bits = BN_num_bits(p);
    if (bits == 0) {
        /* x**0 mod 1 is still zero. */
        if (BN_is_one(m)) {
            ret = 1;
            BN_zero(rr);
        } else {
            ret = BN_one(rr);
        }
        return ret;
    }

    memset(&pmm_prev_ctx, 0, sizeof(pmm_prev_ctx)) ; // todo:  move to init_ctxM
    memset(&pmm_prev_mmul_ctx, 0, sizeof(pmm_prev_mmul_ctx)) ; 

    BN_CTX_start(ctx);
    d = BN_CTX_get(ctx); 
    r = BN_CTX_get(ctx);
    val[0] = BN_CTX_get(ctx);
    if (!d || !r || !val[0])
        goto err;

    /*
     * If this is not done, things will break in the montgomery part
     */

    if (in_mont != NULL)
        mont = in_mont;
    else {
        if ((mont = BN_MONT_CTX_new()) == NULL)
            goto err;
        if (!BN_MONT_CTX_set(mont, m, ctx))
            goto err;
    }
                   
    ////////////////////////////////////////////////////////
    int bShouldReloadBN1 = 0 ; 
    if ( m->top != g_pmm_Ndigits) { 
        g_pmm_Ndigits= m->top ; 
        //printf(" new m[%d]digits \n ", g_pmm_Ndigits ) ; 
        init_ctxM(mont); // m) ; 
        g_pmm_NZero = (uint64_t)(m->d[0]) ; 
        g_pmm_modLenChange_counter++ ; 
        bShouldReloadBN1= 1 ; 
    }
    else if ( g_pmm_NZero != (uint64_t)(m->d[0])) { // update mZeroPrime and the rest
        g_pmm_NZero = (uint64_t)(m->d[0]) ; 
        //printf(" new m.d[0] \n" ) ;
        init_ctxM(mont); //m); 
        g_pmm_modChange_counter++ ; 
        bShouldReloadBN1= 1 ; 
    }
    // else theoretically is possible that m-modulus has changed, but not at position m->d[0], so what then ????
        
    /////////////////////////////////////////////
    

    if (a->neg || BN_ucmp(a, m) >= 0) {
        if (!BN_nnmod(val[0], a, m, ctx))
            goto err;
        aa = val[0];
    } else
        aa = a;
    if (BN_is_zero(aa)) {
        BN_zero(rr);
        ret = 1;
        goto err;
    }
    
    // RR -> 16AL
    // aa -> 16AL
    pmm_mod_mul_montgomeryAL(val[0], aa, &((mont)->RR), mont, ctx)  ;

    //char * aas= BN_bn2hex(aa) ; char * val0s= BN_bn2hex(val[0]) ;
    //printf( "\n\t aas= %s \n\t val0s= %s \n", aas, val0s ); 
    //OPENSSL_free(aas); OPENSSL_free(val0s);

    
    window = BN_window_bits_for_exponent_size(bits);
    if (window > 1) {
        if (!pmm_mod_mul_montgomeryAL(d, val[0], val[0], mont, ctx))
            goto err;           /* 2 */
        j = 1 << (window - 1);
        for (i = 1; i < j; i++) {
            if (((val[i] = BN_CTX_get(ctx)) == NULL) ||
                !pmm_mod_mul_montgomeryAL(val[i], val[i - 1], d, mont, ctx))
                goto err;
        }
    }

    start = 1;                  /* This is used to avoid multiplication etc
                                 * when there is only the value '1' in the
                                 * buffer. */
    wvalue = 0;                 /* The 'value' of the window */
    wstart = bits - 1;          /* The top bit of the window */
    wend = 0;                   /* The bottom bit of the window */

#if 1
    if ( gbShouldOptimizeReloadBN1 ) { 
        if (BN_is_zero(&g_pmm_bn1RR) || bShouldReloadBN1 ) {  
            pmm_mod_mul_montgomeryAL(r, BN_value_one(), &((mont)->RR), mont, ctx)  ;
            if (!BN_copy( &g_pmm_bn1RR, r ) )  // save for reuse later  
                goto err; 
            g_pmm_bn1saved_counter++ ; 
        }
        else { 
            if (!BN_copy(r, &g_pmm_bn1RR ) )  // reuse previosly saved value 
                goto err; 
            g_pmm_bn1restored_counter++ ; 
        }
    }
    else
        pmm_mod_mul_montgomeryAL(r, BN_value_one(), &((mont)->RR), mont, ctx)  ;
#endif

    //if (!BN_to_montgomery(r, BN_value_one(), mont, ctx))

    //printf("--------------------------------------------\n") ; 

   
    for (;;) {
        if (BN_is_bit_set(p, wstart) == 0) {
            if (!start) {
                if (!pmm_mod_mul_montgomeryAL(r, r, r, mont, ctx))
                    goto err;
            }
            if (wstart == 0)
                break;
            wstart--;
            continue;
        }
        /*
         * We now have wstart on a 'set' bit, we now need to work out how bit
         * a window to do.  To do this we need to scan forward until the last
         * set bit before the end of the window
         */
        j = wstart;
        wvalue = 1;
        wend = 0;
        for (i = 1; i < window; i++) {
            if (wstart - i < 0)
                break;
            if (BN_is_bit_set(p, wstart - i)) {
                wvalue <<= (i - wend);
                wvalue |= 1;
                wend = i;
            }
        }

        /* wend is the size of the current window */
        j = wend + 1;
        /* add the 'bytes above' */
        if (!start)
            for (i = 0; i < j; i++) {
                if (!pmm_mod_mul_montgomeryAL(r, r, r, mont, ctx))
                    goto err;
            }

        /* wvalue will be an odd number < 2^window */
        if (!pmm_mod_mul_montgomeryAL(r, r, val[wvalue >> 1], mont, ctx))
            goto err;

        /* move the 'window' down further */
        wstart -= wend + 1;
        wvalue = 0;
        start = 0;
        if (wstart < 0)
            break;
    }
    if (!BN_from_montgomery(rr, r, mont, ctx)) // 
        goto err;

    
    ret = 1;
 
    goto ok; 
 err:
    printf("ERROR in pmm_BN_mod_exp_montAL \n") ; 
    printf("\n\t\t a:[%d]: ", a->top) ;
    byteBuf2Hex(a->d, a->top * 4) ;
    printf("\n\t\t p:[%d]: ", p->top) ;
    byteBuf2Hex(p->d, p->top * 4) ;
    printf("\n\t\t m:[%d]: ", m->top) ;
    byteBuf2Hex(m->d, m->top * 4) ;
    printf("\n") ; 
    
    exit(0) ; 
        
 ok:
    if ((in_mont == NULL) && (mont != NULL))
        BN_MONT_CTX_free(mont);
    BN_CTX_end(ctx);
    bn_check_top(rr);
    
    
    
    return (ret);
}

////////////////+++++++++++++++++++++++++++++++++++++++++

////////////////+++++++++++++++++++++++++++++++++++++++++

static int pmm_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                         const BIGNUM *m, BN_CTX *ctx)
{
    
    
    // let op , not called by RSA    
        
    pmm_BN_mod_exp_montAL(r, a, p, m, ctx, NULL) ;
    
    //BN_mod_exp_mont(r, a, p, m, ctx, NULL) ; 
    
    //BN_mod_exp(r, a, p, m, ctx) ; 
    
   
    return 1 ; 
    

}


#  ifndef OPENSSL_NO_RSA
static int plpmm_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa,
                             BN_CTX *ctx)
{
    g_pmm_mod_exp_counter++ ; 
    return pmm_mod_exp(r0, I, rsa->d, rsa->n, ctx);
    //return 0 ; 
}
#  endif

#  ifndef OPENSSL_NO_DSA
/*
 * This method was liberated and adapted from crypto/bn/bn_exp2.c
 */
static int plpmm_dsa_mod_exp(DSA *dsa, BIGNUM *rr, BIGNUM *a1,
                             BIGNUM *p1, BIGNUM *a2, BIGNUM *p2, BIGNUM *m,
                             BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
    //printf("[dsa pub (a1[%d] ^p1[%d] , a2[%d] ^p2[%d] ) mod m[%d] ] \n", a1->top, p1->top, a2->top, p2->top, m->top ) ;
    
    int i, j, bits, b, bits1, bits2, ret =
        0, wpos1, wpos2, window1, window2, wvalue1, wvalue2;
    int r_is_one = 1;
    BIGNUM *d, *r;
    const BIGNUM *a_mod_m;
    /* Tables of variables obtained from 'ctx' */
    BIGNUM *val1[TABLE_SIZE], *val2[TABLE_SIZE];
    BN_MONT_CTX *mont = NULL;

    bn_check_top(a1);
    bn_check_top(p1);
    bn_check_top(a2);
    bn_check_top(p2);
    bn_check_top(m);

    if (!(m->d[0] & 1)) {
        BNerr(BN_F_BN_MOD_EXP2_MONT, BN_R_CALLED_WITH_EVEN_MODULUS);
        return (0);
    }
    bits1 = BN_num_bits(p1);
    bits2 = BN_num_bits(p2);
    if ((bits1 == 0) && (bits2 == 0)) {
        ret = BN_one(rr);
        return ret;
    }

    bits = (bits1 > bits2) ? bits1 : bits2;

    BN_CTX_start(ctx);
    d = BN_CTX_get(ctx);
    r = BN_CTX_get(ctx);
    val1[0] = BN_CTX_get(ctx);
    val2[0] = BN_CTX_get(ctx);
    if (!d || !r || !val1[0] || !val2[0])
        goto err;

    if (in_mont != NULL)
        mont = in_mont;
    else {
        if ((mont = BN_MONT_CTX_new()) == NULL)
            goto err;
        if (!BN_MONT_CTX_set(mont, m, ctx))
            goto err;
    }

    window1 = BN_window_bits_for_exponent_size(bits1);
    window2 = BN_window_bits_for_exponent_size(bits2);

    /*
     * Build table for a1:   val1[i] := a1^(2*i + 1) mod m  for i = 0 .. 2^(window1-1)
     */
    if (a1->neg || BN_ucmp(a1, m) >= 0) {
        if (!BN_mod(val1[0], a1, m, ctx))
            goto err;
        a_mod_m = val1[0];
    } else
        a_mod_m = a1;
    if (BN_is_zero(a_mod_m)) {
        BN_zero(rr);
        ret = 1;
        goto err;
    }

    memset(&pmm_prev_ctx, 0, sizeof(pmm_prev_ctx)) ; 
    memset(&pmm_prev_mmul_ctx, 0, sizeof(pmm_prev_mmul_ctx)) ; 
                        
    ////////////////////////////////////////////////////////
    int bShouldReloadBN1 = 0 ; 
    if ( m->top != g_pmm_Ndigits) { 
        g_pmm_Ndigits= m->top ; 
        //printf(" %d ", g_pmm_Ndigits ) ; 
        init_ctxM(mont); // m) ; 
        g_pmm_NZero = (uint64_t)(m->d[0]) ; 
        g_pmm_modLenChange_counter++ ; 
        bShouldReloadBN1= 1 ; 
    }
    else if ( g_pmm_NZero != (uint64_t)(m->d[0])) { 
        g_pmm_NZero = (uint64_t)(m->d[0]) ; 
        //printf("." ) ;
        init_ctxM(mont); // m) ; 
        g_pmm_modChange_counter++ ; 
        bShouldReloadBN1= 1 ; 
    }
    // else theoretically is possible that m-modulus has changed, but not at position m->d[0], so what then ????
        
    /////////////////////////////////////////////
    

    //  if (!BN_to_montgomery(val1[0], a_mod_m, mont, ctx))
    if (!pmm_mod_mul_montgomeryAL(val1[0], a_mod_m, &((mont)->RR), mont, ctx))  
        goto err;
    if (window1 > 1) {
        if (!pmm_mod_mul_montgomeryAL(d, val1[0], val1[0], mont, ctx))
            goto err;

        j = 1 << (window1 - 1);
        for (i = 1; i < j; i++) {
            if (((val1[i] = BN_CTX_get(ctx)) == NULL) ||
                !pmm_mod_mul_montgomeryAL(val1[i], val1[i - 1], d, mont, ctx))
                goto err;
        }
    }

    /*
     * Build table for a2:   val2[i] := a2^(2*i + 1) mod m  for i = 0 .. 2^(window2-1)
     */
    if (a2->neg || BN_ucmp(a2, m) >= 0) {
        if (!BN_mod(val2[0], a2, m, ctx))
            goto err;
        a_mod_m = val2[0];
    } else
        a_mod_m = a2;
    if (BN_is_zero(a_mod_m)) {
        BN_zero(rr);
        ret = 1;
        goto err;
    }
    //if (!BN_to_montgomery(val2[0], a_mod_m, mont, ctx))
    if (!pmm_mod_mul_montgomeryAL(val2[0], a_mod_m, &((mont)->RR), mont, ctx))  
        goto err;
    if (window2 > 1) {
        if (!pmm_mod_mul_montgomeryAL(d, val2[0], val2[0], mont, ctx))
            goto err;

        j = 1 << (window2 - 1);
        for (i = 1; i < j; i++) {
            if (((val2[i] = BN_CTX_get(ctx)) == NULL) ||
                !pmm_mod_mul_montgomeryAL(val2[i], val2[i - 1], d, mont, ctx))
                goto err;
        }
    }

    /* Now compute the power product, using independent windows. */
    r_is_one = 1;
    wvalue1 = 0;                /* The 'value' of the first window */
    wvalue2 = 0;                /* The 'value' of the second window */
    wpos1 = 0;                  /* If wvalue1 > 0, the bottom bit of the
                                 * first window */
    wpos2 = 0;                  /* If wvalue2 > 0, the bottom bit of the
                                 * second window */

#if 1
    
    if ( gbShouldOptimizeReloadBN1 ) { 
        if (BN_is_zero(&g_pmm_bn1RR) || bShouldReloadBN1 ) {  
            pmm_mod_mul_montgomeryAL(r, BN_value_one(), &((mont)->RR), mont, ctx)  ;
            if (!BN_copy( &g_pmm_bn1RR, r ) )  // save for reuse later  
                goto err; 
            g_pmm_bn1saved_counter++ ; 
        }
        else { 
            if (!BN_copy(r, &g_pmm_bn1RR ) )  // reuse previosly saved value 
                goto err; 
            g_pmm_bn1restored_counter++ ; 
        }
    }
    else
        pmm_mod_mul_montgomeryAL(r, BN_value_one(), &((mont)->RR), mont, ctx) ;   
        //if (!BN_to_montgomery(r, BN_value_one(), mont, ctx))
        //    goto err;
#endif
        
    for (b = bits - 1; b >= 0; b--) {
        if (!r_is_one) {
            if (!pmm_mod_mul_montgomeryAL(r, r, r, mont, ctx))
                goto err;
        }

        if (!wvalue1)
            if (BN_is_bit_set(p1, b)) {
                /*
                 * consider bits b-window1+1 .. b for this window
                 */
                i = b - window1 + 1;
                while (!BN_is_bit_set(p1, i)) /* works for i<0 */
                    i++;
                wpos1 = i;
                wvalue1 = 1;
                for (i = b - 1; i >= wpos1; i--) {
                    wvalue1 <<= 1;
                    if (BN_is_bit_set(p1, i))
                        wvalue1++;
                }
            }

        if (!wvalue2)
            if (BN_is_bit_set(p2, b)) {
                /*
                 * consider bits b-window2+1 .. b for this window
                 */
                i = b - window2 + 1;
                while (!BN_is_bit_set(p2, i))
                    i++;
                wpos2 = i;
                wvalue2 = 1;
                for (i = b - 1; i >= wpos2; i--) {
                    wvalue2 <<= 1;
                    if (BN_is_bit_set(p2, i))
                        wvalue2++;
                }
            }

        if (wvalue1 && b == wpos1) {
            /* wvalue1 is odd and < 2^window1 */
            if (!pmm_mod_mul_montgomeryAL(r, r, val1[wvalue1 >> 1], mont, ctx))
                goto err;
            wvalue1 = 0;
            r_is_one = 0;
        }

        if (wvalue2 && b == wpos2) {
            /* wvalue2 is odd and < 2^window2 */
            if (!pmm_mod_mul_montgomeryAL(r, r, val2[wvalue2 >> 1], mont, ctx))
                goto err;
            wvalue2 = 0;
            r_is_one = 0;
        }
    }
    if (!BN_from_montgomery(rr, r, mont, ctx))
        goto err;
    ret = 1;
 err:
    if ((in_mont == NULL) && (mont != NULL))
        BN_MONT_CTX_free(mont);
    BN_CTX_end(ctx);
    bn_check_top(rr);
    return (ret);
}

static int pmm_mod_exp_dsa(DSA *dsa, BIGNUM *r, BIGNUM *a,
                             const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
                             BN_MONT_CTX *m_ctx)
{
    //printf("[dsa priv a[%d] ^p[%d] mod m[%d] ] \n", a->top, p->top, m->top ) ; 
    return pmm_BN_mod_exp_montAL(r, a, p, m, ctx, m_ctx);
}
#  endif

/* This function is aliased to mod_exp (with the mont stuff dropped). */
#  ifndef OPENSSL_NO_RSA
static int pmm_mod_exp_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                              const BIGNUM *m, BN_CTX *ctx,
                              BN_MONT_CTX *m_ctx)
{
    g_pmm_mod_exp_mont_counter++ ; 
    
    //if ( m->top < 32 && g_original_fnBNMod_exp )
    //    return g_original_fnBNMod_exp(r, a, p, m, ctx, m_ctx) ;
    
   
    
#define pmm_mm_debug 0
# if (pmm_mm_debug)        
    
    //return BN_mod_mul_montgomery( d, a, b, mont, ctx) ;

    BIGNUM *aa, *bb, *dd ; 
    BN_CTX_start(ctx);
    aa = BN_CTX_get(ctx);
    bb = BN_CTX_get(ctx);
    dd = BN_CTX_get(ctx);
    
    BN_copy(aa, a) ;
    BN_copy(bb, p) ;
    BN_init(dd);
    //BN_zero(dd) ; 
     
    printf("\n a^P[%d] mod M[%d]", p->top, m->top) ; 
    timeFn( g_original_fnBNMod_exp(dd, aa, bb, m, ctx, m_ctx), "fnBNMod_exp" );
    
    
  timeFn(pmm_BN_mod_exp_montAL(r, a, p, m, ctx, m_ctx), "My_mod_exp")  ;


#else 

/*    if ( m->top < 24) { 
        if ( m->top == 16 && p->top == 1 )
            pmm_BN_mod_exp_montAL(r, a, p, m, ctx, m_ctx)  ;
        else 
            g_original_fnBNMod_exp(r, a, p, m, ctx, m_ctx) ; 
    }
    else */
        pmm_BN_mod_exp_montAL(r, a, p, m, ctx, m_ctx)  ;

#endif

    
    
    
        
#if (pmm_mm_debug)
    
    if ( BN_ucmp( r, dd ) != 0 ) { 
    
    char * as= BN_bn2hex(a) ; char * bs= BN_bn2hex(p) ; char * ms= BN_bn2hex(m) ; char * ds= BN_bn2hex(r) ;
    printf( "----------\n\t a= %s \n \t p= %s \n \t m= %s \n\t PMM ==== a^p= %s \n", as, bs, ms, ds ); 
    OPENSSL_free(as); OPENSSL_free(bs); OPENSSL_free(ds) ; OPENSSL_free(ms) ; 
    
    //printf("\n \t PMM 3 ==== a*p= ") ; 
    //byteBuf2Hex(d->d, d->top * 4) ; 
    //printf("\n") ; 
        
    printf("\n\t soft === a^p= ") ; 
    byteBuf2Hex(dd->d, dd->top * 4) ; 
    printf("\n") ; 
    
    BN_CTX_end(ctx);
    
    exit(0) ; 
    
    }
#endif
    
    return 1 ; // pmm_BN_mod_exp_montAL(r, a, p, m, ctx, m_ctx) ;
    //return pmm_BN_mod_exp_mont(r, a, p, m, ctx, m_ctx) ;
    /////return pmm_mod_exp(r, a, p, m, ctx);
    
    
}
#  endif

#  ifndef OPENSSL_NO_DH
/* This function is aliased to mod_exp (with the dh and mont dropped). */
static int pmm_mod_exp_dh(const DH *dh, BIGNUM *r,
                            const BIGNUM *a, const BIGNUM *p,
                            const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    return pmm_mod_exp(r, a, p, m, ctx);
}
#  endif

#  ifndef OPENSSL_NO_RSA

//static int RSA_eay_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx); 

static RSA_METHOD plpmm_rsa = {
    "plpmm RSA method",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,                       //plpmm_rsa_mod_exp,
    pmm_mod_exp_mont,
    NULL,
    NULL,
    0,
    NULL,
    NULL,
    NULL,
    NULL
};
#  endif

#  ifndef OPENSSL_NO_DSA
static DSA_METHOD plpmm_dsa = {
    "plpmm DSA method",
    NULL,                       /* dsa_do_sign */
    NULL,                       /* dsa_sign_setup */
    NULL,                       /* dsa_do_verify */
    plpmm_dsa_mod_exp,       //plpmm_dsa_mod_exp,          /* dsa_mod_exp */
    pmm_mod_exp_dsa,          /* bn_mod_exp */
    NULL,                       /* init */
    NULL,                       /* finish */
    0,                          /* flags */
    NULL,                       /* app_data */
    NULL,                       /* dsa_paramgen */
    NULL                        /* dsa_keygen */
};
#  endif

#  ifndef OPENSSL_NO_DH
static DH_METHOD plpmm_dh = {
    "plpmm DH method",
    NULL,
    NULL,
    pmm_mod_exp_dh,
    NULL,
    NULL,
    0,
    NULL,
    NULL
};
#  endif

/* *******************************************************************************
 * 
 * 
 * 
 * */
 
#  define PMM_MY_CMD_1              ENGINE_CMD_BASE
#  define PMM_MY_CMD_2           (ENGINE_CMD_BASE + 1)
#  define PMM_MY_CMD_3           (ENGINE_CMD_BASE + 2)

/* The definitions for control commands specific to this engine */
static const ENGINE_CMD_DEFN plpmm_cmd_defns[] = {
    {PMM_MY_CMD_1,
     "UNLOAD",
     "realease all hooks",
     ENGINE_CMD_FLAG_STRING},
     {PMM_MY_CMD_2,
     "INFO",
     "show info",
     ENGINE_CMD_FLAG_NO_INPUT},
    {0, NULL, NULL, 0}
};


static int plpmm_destroy(ENGINE *e)
{
    BN_free(&g_pmm_bn1RR);
    ERR_unload_PLPMM_strings();
    return 1;
}



static int plpmm_finish(ENGINE *e)
{

    padlock_pmm_free() ; 
    
    if ( gbVerbose ) { 
        printf ( " \n -------------------------------------------------------------------\n") ; 
        printf ( " \t\t mont_mul_padlock_counter %d, mont_nul_padlock_counter2 %d \n", g_pmm_mont_mul_padlock_counter, g_pmm_mont_mul_padlock_counter2 ) ; 
        printf ( " \t\t mod_exp_mont %d , mod_exp %d \n", g_pmm_mod_exp_mont_counter, g_pmm_mod_exp_counter ) ; 
        printf ( " \t\t bn1_counter  %d, bnLess32_counter %d \n", g_pmm_bn1_counter, g_pmm_bnLess32_counter ) ; 
        printf ( " \t\t bn1saves_counter %d , bn1restored_counter %d \n", g_pmm_bn1saved_counter, g_pmm_bn1restored_counter ) ; 
        printf ( " \t\t modChange_counter  %d, modLenChange_counter %d  \n", g_pmm_modChange_counter, g_pmm_modLenChange_counter ) ; 
        printf ( " \t\t nocopyAT_counter  %d , nocopyBT_counter %d \n", g_nocopyAT_counter, g_nocopyBT_counter ) ;
        printf ( " \t\t nocopyA_counter  %d , nocopyB_counter %d \n", g_nocopyA_counter, g_nocopyB_counter ) ; 
        printf ( " \t\t nocopyBA_counter  %d ,  \n", g_nocopyBA_counter ) ; 
        printf ( " \n -------------------------------------------------------------------\n") ; 
    }
    
    return 1;
}

// --------------------------------------------------------------------------------------------

/*
 * Helper function - check if a CPUID instruction is available on this CPU
 * reused from e_padlock.c
 */
static int padlock_insn_cpuid_available(void)
{
    int result = -1;

    /*
     * We're checking if the bit #21 of EFLAGS can be toggled. If yes =
     * CPUID is available.
     */
    asm volatile ("pushf\n"
                  "popl %%eax\n"
                  "xorl $0x200000, %%eax\n"
                  "movl %%eax, %%ecx\n"
                  "andl $0x200000, %%ecx\n"
                  "pushl %%eax\n"
                  "popf\n"
                  "pushf\n"
                  "popl %%eax\n"
                  "andl $0x200000, %%eax\n"
                  "xorl %%eax, %%ecx\n"
                  "movl %%ecx, %0\n":"=r" (result)::"eax", "ecx");

    return (result == 0);
}


#define     cpu_has_str(c, FLAG, descr)    ( printf("%s ", ((c & (FLAG)) == (FLAG) ? descr : "")))

    
    
#define X86_FEATURE_XSTORE	( 0x1 << 2)	/* on-CPU RNG present (xstore insn) */
#define X86_FEATURE_XSTORE_EN	(0x1 << 3)	/* on-CPU RNG enabled */
#define X86_FEATURE_XCRYPT	(0x1 << 6)	/* on-CPU crypto (xcrypt insn) */
#define X86_FEATURE_XCRYPT_EN	(0x1 << 7)	/* on-CPU crypto enabled */
#define X86_FEATURE_ACE2        (0x1 << 8)	/* Advanced Cryptography Engine v2 */
#define X86_FEATURE_ACE2_EN     (0x1 << 9)	/* ACE v2 enabled */
#define X86_FEATURE_PHE         (0x1 << 10)	/* PadLock Hash Engine */
#define X86_FEATURE_PHE_EN      (0x1 << 11)	/* PHE enabled */
#define X86_FEATURE_PMM         (0x1 << 12)	/* PadLock Montgomery Multiplier */
#define X86_FEATURE_PMM_EN      (0x1 << 13)	/* PadLock Montgomery Multiplier enabled */

/*
 * Load supported features of the CPU to see if the PadLock is available.
 * reused from e_padlock.c and extended for other flags
 */
static int padlock_available(void)
{
    char vendor_string[16];
    unsigned int eax, edx;

    /* First check if the CPUID instruction is available at all... */
    if (!padlock_insn_cpuid_available()) { 
        printf(" CPUID is not available on this cpu. \n") ; 
        return 0;
    }

    /* Are we running on the Centaur (VIA) CPU? */
    eax = 0x00000000;
    vendor_string[12] = 0;
    asm volatile ("pushl  %%ebx\n"
                  "cpuid\n"
                  "movl   %%ebx,(%%edi)\n"
                  "movl   %%edx,4(%%edi)\n"
                  "movl   %%ecx,8(%%edi)\n"
                  "popl   %%ebx":"+a" (eax):"D"(vendor_string):"ecx", "edx");
                  
    printf("CPU vendor string: %s \n", vendor_string) ; 
    
    if (strcmp(vendor_string, "CentaurHauls") == 0) { 

        /* Check for Centaur Extended Feature Flags presence */
        eax = 0xC0000000;
        asm volatile ("pushl %%ebx; cpuid; popl %%ebx":"+a" (eax)::"ecx", "edx");
        if (eax < 0xC0000001) { 
            printf("Extended Feature Flags are not present. \n") ; 
            return 0;
        }

        /* Read the Centaur Extended Feature Flags */
        eax = 0xC0000001;
        asm volatile ("pushl %%ebx; cpuid; popl %%ebx":"+a" (eax),
                      "=d"(edx)::"ecx");

        printf("Extended Feature Flags: 0x%.8X . \n", edx ) ;
        
        printf( "flags: \n") ;  
        cpu_has_str(edx, X86_FEATURE_XSTORE, "rng" ) ;
        cpu_has_str(edx, X86_FEATURE_XSTORE_EN, "rng_en" ) ;
        cpu_has_str(edx, X86_FEATURE_XCRYPT, "ace" ) ;
        cpu_has_str(edx, X86_FEATURE_XCRYPT, "ace_en" ) ;
        cpu_has_str(edx, X86_FEATURE_PHE, "phe" ) ;
        cpu_has_str(edx, X86_FEATURE_PHE_EN, "phe_en" ) ;
        
        cpu_has_str(edx, X86_FEATURE_ACE2, "ace2" ) ;
        cpu_has_str(edx, X86_FEATURE_ACE2_EN, "ace2_en" ) ;
        cpu_has_str(edx, X86_FEATURE_PMM, "pmm" ) ;
        cpu_has_str(edx, X86_FEATURE_PMM_EN, "pmm_en" ) ;
        printf( " \n") ;
        
        // is nano ? 
        eax = 0x01;
        asm volatile ("pushl %%ebx; cpuid; popl %%ebx":"+a" (eax)::"ecx", "edx");
        if ( (eax | 0x000f) == 0x06ff )
            printf(" is Nano cpu ") ; 
        else 
            printf(" is not Nano cpu ") ; 
        printf( " \n") ;
        
    }

    return 1;
}

static int plpmm_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    int to_return = 1;

    switch (cmd) {
        
    case PMM_MY_CMD_1 :
        
        printf("received cmd with arg: %s \n ", (const char *)p )  ; 
        ENGINE_set_RSA(e, NULL)  ; 
        ENGINE_set_DSA(e, NULL) ; 
        ENGINE_set_DH(e, NULL) ; 
        
        break ; 
        
    case PMM_MY_CMD_2 :
        
        printf("received cmd with arg: %s \n ", (const char *)p )  ; 
        printf ( " \n -------------------------------------------------------------------\n") ; 
        printf ( " \t Verbose: %d,\t IsNano: %d,\t shouldOptimizeReloadBN1: %d \n", gbVerbose, gbIsNano, gbShouldOptimizeReloadBN1 ) ; 
        printf ( " \t MIN_NUMDIGITS_FOR_PMM: %d, \n", g_MIN_NUMDIGITS_FOR_PMM ) ; 
        printf ( " \n -------------------------------------------------------------------\n") ; 
        printf ( " \t In [default-path]/openssl.cnf following switches can be set: \n" ) ; 
        printf ( " \t\t [ PLPMM ] \n" ) ; 
        printf ( " \t\t verbose= {true/false(default)} \n" ) ; 
        printf ( " \t\t enable= {true(default)/false} \n" ) ; 
        printf ( " \t\t isNano= {true/false(default)} \n" ) ; 
        printf ( " \t\t shouldOptimizeReloadBN1= {true(default)/false} \n" ) ; 
        printf ( " \n -------------------------------------------------------------------\n") ; 
        
        padlock_available() ; 
        
        break ; 
        
    default: /* The command isn't understood by this engine */
        PLPMMerr(PLPMM_F_PLPMM_CTRL, PLPMM_R_CTRL_COMMAND_NOT_IMPLEMENTED);
        printf(" not understood \n") ; 
        to_return = 0;
        break;
    }

    return to_return;
}

#include <stdlib.h>

static int plpmm_init(ENGINE *e) 
{
    int ret = 1; 
    
    
    g_pmm_mod_exp_mont_counter= 0 ; 
    g_pmm_mod_exp_counter= 0 ; 
    
    ///////////
    
    LHASH_OF(CONF_VALUE) *conf;
    long eline;
    char *p, *s, *s2;

    p = getenv("OPENSSL_CONF");
    if (p == NULL)
        p = getenv("SSLEAY_CONF");
        
    /*
    const char *t = X509_get_default_cert_area();
    size_t len;
    char *p;

    len = strlen(t) + strlen(OPENSSL_CONF) + 2;
    p = OPENSSL_malloc(len);
    if (p == NULL)
        return NULL;
    BUF_strlcpy(p, t, len);
#ifndef OPENSSL_SYS_VMS
    BUF_strlcat(p, "/", len);
#endif
    BUF_strlcat(p, OPENSSL_CONF, len);
     */
        

    conf = CONF_load(NULL, (p == NULL ? "openssl.cnf" : p ) , &eline);
    if (conf == NULL) {
        ERR_load_crypto_strings();
        printf("unable to load configuration %s, line %ld\n", p, eline);
        ERR_print_errors_fp(stderr);
    }
    else { 
        
        gbVerbose= 0 ; 
        s = CONF_get_string(conf, "PLPMM", "verbose");
        if ( s != NULL && strcmp( s, "true" ) == 0 ) {
            gbVerbose= 1 ; 
            printf ( "[PLPMM]verbose= true in %s \n \t use: openssl eninge %s -pre INFO     --- for more options \n", 
                        ( p==NULL ? "defaultCONF": p), engine_plpmm_id ) ; 
        }
        
        
        s = CONF_get_string(conf, "PLPMM", "enable");
        if ( gbVerbose ) printf("[PLPMM]enable= %s\n", (s == NULL) ? "default" : s);
        if ( s != NULL && strcmp( s, "false" ) == 0 ) {
            ret = 0 ; 
        }
        
        s = CONF_get_string(conf, "PLPMM", "isNano");
        if ( gbVerbose ) printf("[PLPMM]isNano= %s\n", (s == NULL) ? "default" : s);
        gbIsNano= 0 ; 
        g_MIN_NUMDIGITS_FOR_PMM= 8 ; // eden
        if ( s != NULL && strcmp( s, "true" ) == 0 ) {
            gbIsNano= 1 ; 
            g_MIN_NUMDIGITS_FOR_PMM= 24 ; // nano
        }
        
        gbShouldOptimizeReloadBN1= 1 ; 
        s = CONF_get_string(conf, "PLPMM", "shouldOptimizeReloadBN1");
        if ( gbVerbose ) printf("[PLPMM]shouldOptimizeReloadBN1= %s\n", (s == NULL) ? "default" : s);
        if ( s != NULL && strcmp( s, "false" ) == 0 ) {
            gbShouldOptimizeReloadBN1= 0 ; 
        }
        
/*        
        s = CONF_get_string(conf, "PLPMM", "plpmm-rsa-mod-exp");
        if ( gbVerbose ) printf("[PLPMM]plpmm-rsa-mod-exp= %s\n", (s == NULL) ? "default" : s);

#ifndef OPENSSL_NO_RSA         
        if ( s != NULL  && strcmp( s, "true" ) == 0 ) {
            if ( gbVerbose ) printf ( " \t plpmm [PLPMM]plpmm-rsa-mod-exp= true in %s \n", p) ; 
            plpmm_rsa.rsa_mod_exp = plpmm_rsa_mod_exp ; // else it should be set to RSA_eay_mod_exp
        }
#endif    
*/    
        //printf("---------------------------- DUMP ------------------------\n");
        //CONF_dump_fp(conf, stdout);

        if ( gbVerbose ) printf(" \t isEnabled: %d,\t isNano: %d,\t shouldOptimizeReloadBN1: %d \n", ret, gbIsNano, gbShouldOptimizeReloadBN1 ) ; 
        
        CONF_free(conf) ; 
    }
    ///////////
    
    if (p) OPENSSL_free(p);

    if ( ret == 0 )  return 0 ; 
    
    padlock_pmm_init(128) ; 

    BN_init(&g_pmm_bn1RR) ; 
    
    if ( gbVerbose ) printf ( "\t MIN_NUMDIGITS_FOR_PMM %d, \n", g_MIN_NUMDIGITS_FOR_PMM ) ; 
    
    
    return ret;
}






/*
 * This internal function is used by ENGINE_plpmm() and possibly by the
 * "dynamic" ENGINE support too
 */
static int bind_helper(ENGINE *e)
{
    
#  ifndef OPENSSL_NO_RSA
    const RSA_METHOD *meth1;
#  endif
#  ifndef OPENSSL_NO_DSA
    const DSA_METHOD *meth2;
#  endif
#  ifndef OPENSSL_NO_DH
    const DH_METHOD *meth3= DH_OpenSSL();
    memcpy(&plpmm_dh, meth3, sizeof(plpmm_dh)) ; 
    plpmm_dh.bn_mod_exp= pmm_mod_exp_dh ; 
#  endif
    if (!ENGINE_set_id(e, engine_plpmm_id) ||
        !ENGINE_set_name(e, engine_plpmm_name) ||
#  ifndef OPENSSL_NO_RSA
        !ENGINE_set_RSA(e, &plpmm_rsa) ||
#  endif
#  ifndef OPENSSL_NO_DSA
        !ENGINE_set_DSA(e, &plpmm_dsa) ||
#  endif
#  ifndef OPENSSL_NO_DH
        !ENGINE_set_DH(e, &plpmm_dh) ||
#  endif
        !ENGINE_set_destroy_function(e, plpmm_destroy) ||
        !ENGINE_set_init_function(e, plpmm_init) ||
        !ENGINE_set_finish_function(e, plpmm_finish) ||
        !ENGINE_set_ctrl_function(e, plpmm_ctrl) ||
        !ENGINE_set_cmd_defns(e, plpmm_cmd_defns))
        return 0;

#  ifndef OPENSSL_NO_RSA
    /*
     * We know that the "PKCS1_SSLeay()" functions hook properly to the
     * plpmm-specific mod_exp and mod_exp_crt so we use those functions. NB:
     * We don't use ENGINE_openssl() or anything "more generic" because
     * something like the RSAref code may not hook properly, and if you own
     * one of these cards then you have the right to do RSA operations on it
     * anyway!
     */
    meth1 = RSA_PKCS1_SSLeay();
    plpmm_rsa.rsa_pub_enc = meth1->rsa_pub_enc;
    plpmm_rsa.rsa_pub_dec = meth1->rsa_pub_dec;
    plpmm_rsa.rsa_priv_enc = meth1->rsa_priv_enc;
    plpmm_rsa.rsa_priv_dec = meth1->rsa_priv_dec;
    plpmm_rsa.rsa_mod_exp = meth1->rsa_mod_exp ; // should be  RSA_eay_mod_exp
    g_original_fnBNMod_exp = meth1->bn_mod_exp ; 
    
    
#  endif

#  ifndef OPENSSL_NO_DSA
    /*
     * Use the DSA_OpenSSL() method and just hook the mod_exp-ish bits.
     */
    meth2 = DSA_OpenSSL();
    plpmm_dsa.dsa_do_sign = meth2->dsa_do_sign;
    plpmm_dsa.dsa_sign_setup = meth2->dsa_sign_setup;
    plpmm_dsa.dsa_do_verify = meth2->dsa_do_verify;
#  endif

#  ifndef OPENSSL_NO_DH
    /* Much the same for Diffie-Hellman */
    //meth3 = DH_OpenSSL();
    //plpmm_dh.generate_key = meth3->generate_key;
    //plpmm_dh.compute_key = meth3->compute_key;
#  endif

    /* Ensure the plpmm error handling is set up */
    ERR_load_PLPMM_strings();
    return 1;
}

#  ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *engine_plpmm(void)
{
    ENGINE *ret = ENGINE_new();
    if (!ret)
        return NULL;
    if (!bind_helper(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void ENGINE_load_plpmm(void)
{
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = engine_plpmm();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}

void ENGINE_load_nuron(void)
{
   ENGINE_load_plpmm() ; 
}

#  else  // endif
//#  ifndef OPENSSL_NO_DYNAMIC_ENGINE

/*
 * This stuff is needed if this ENGINE is being compiled into a
 * self-contained shared-library.
 */

static int bind_fn(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_plpmm_id) != 0))
        return 0;
    if (!bind_helper(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
#  endif                        /* OPENSSL_NO_DYNAMIC_ENGINE */
# endif                         /* !OPENSSL_NO_HW_plpmm */
#endif                          /* !OPENSSL_NO_HW */
