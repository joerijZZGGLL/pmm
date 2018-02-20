# pmm

OpenSSL engine for VIA padlock_pmm

padlock_pmm is a hardware feature of VIA Nano&Eden cpu's, which implements a hardware accelerator for Montgomey Multiplication, as used in DH/RSA/DSA asymetric public-private encryption schemes. 

PadlockPMM is an openSSL engine implementation for VIA padlock_pmm hardware feature. 

It provides an EVP interface implementation for these methods: 

 	mod_exp_dh()
 	mod_exp_dsa()
 	mod_exp_mont()

ECDSA and ECDH are not currenctly supported by PadlockPMM engine.  

PadlockPMM consists of 3 files: 

 	e_hw_pmm.c
 	e_hw_pmm_err.h
 	e_hw_pmm_err.c

files should be placed in  openssl-..../engines/  folder. 
To make the integration in OpenSSL build system easier, I have chosen to replace an 
existing engine: e_nuron with the source code of PadlockPMM, so that build system would 
find and compile&link it without modifications to the Makefiles. 

So the files above should be renamed to: 
( update: not needed anymore, files are already uploaded with  e_nuron... names ) 

 	e_hw_pmm.c  ->  e_nuron.c
 	e_hw_pmm_err.h   ->   e_nuron_err.h
 	e_hw_pmm_err.c   ->   e_nuron_err.c

calling:  make   
in the openssl-.../ root-folder should do the trick. 

after building and installing ,  libnuron.so  can be renamed to libpadlockPMM.so 
on 32bit ubuntu/debian it is located in: /usr/lib/i386-linux-gnu/openssl-1.0.0/engines/

behaviour of padlockPMM can be controlled by entries in openssl.cnf file, 
usually located in : /usr/lib/ssl/openssl.cnf 

[PLPMM]
verbose= true/false        will print extra usage information 
enable= true/false         can be used to disable the engine
isNano= true/false         should be set to true if cpu is a Nano cpu,  and to false if it is an Eden or older. 

following cmd give some extra information of available options: 

 	openssl eninge padlockPMM -pre INFO     

--------------------------------------------------------------------------

compiled against openssl_1.0.1t 

on ubuntu 14.0x 32 bits

--------------------------------------------------------------------------
<pre> 
 
root@it:~# cat /proc/cpuinfo 
processor	: 0
vendor_id	: CentaurHauls
cpu family	: 6
model		: 13
model name	: VIA Eden Processor 1000MHz
stepping	: 0
cpu MHz		: 1000.154
cache size	: 128 KB
physical id	: 0
siblings	: 1
core id		: 0
cpu cores	: 1
apicid		: 0
initial apicid	: 0
fdiv_bug	: no
f00f_bug	: no
coma_bug	: no
fpu		: yes
fpu_exception	: yes
cpuid level	: 1
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 sep mtrr pge cmov pat clflush acpi mmx fxsr sse sse2 tm nx pni est tm2 xtpr rng rng_en ace ace_en ace2 ace2_en phe phe_en pmm pmm_en
bogomips	: 2000.30
clflush size	: 64
cache_alignment	: 64
address sizes	: 36 bits physical, 32 bits virtual
power management:



<B>WITH</B> padlock_pmm engine: 

root@it:~# ./openssl speed <B>rsa</B> -e padlockPMM
WARNING: can't open config file: /usr/local/ssl/openssl.cnf
Doing 512 bit private rsa's for 10s: 9119 512 bit private RSA's in 10.00s
Doing 512 bit public rsa's for 10s: 65660 512 bit public RSA's in 9.99s
Doing 1024 bit private rsa's for 10s: 2940 1024 bit private RSA's in 10.00s
Doing 1024 bit public rsa's for 10s: 39928 1024 bit public RSA's in 9.99s
Doing 2048 bit private rsa's for 10s: 631 2048 bit private RSA's in 10.00s
Doing 2048 bit public rsa's for 10s: 16264 2048 bit public RSA's in 9.99s
Doing 4096 bit private rsa's for 10s: 102 4096 bit private RSA's in 9.99s
Doing 4096 bit public rsa's for 10s: 5113 4096 bit public RSA's in 9.99s
OpenSSL 1.0.1t  3 May 2016
built on: Tue Aug  1 20:09:47 2017
options:bn(64,32) rc4(8x,mmx) des(ptr,risc1,16,long) aes(partial) idea(int) blowfish(idx) 
compiler: gcc -I. -I.. -I../include  -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -DXXXXXX -fPIC -DOPENSSL_PIC -DL_ENDIAN -DTERMIO -g -O2 -fstack-protector-strong -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2 -Wa,--noexecstack -march=i686 -Wa,--noexecstack -DL_ENDIAN -O3 -fomit-frame-pointer -Wall -DOPENSSL_BN_ASM_PART_WORDS -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DRMD160_ASM -DAES_ASM -DVPAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM
                  sign    verify    sign/s verify/s
rsa  512 bits 0.001097s 0.000152s    911.9   6572.6
rsa 1024 bits 0.003401s 0.000250s    294.0   3996.8
rsa 2048 bits 0.015848s 0.000614s     63.1   1628.0
rsa 4096 bits 0.097941s 0.001954s     10.2    511.8


<B>WITHOUT</B> pmm engine: 

root@it:~# openssl speed <B>rsa</B>
Doing 512 bit private rsa's for 10s: 7193 512 bit private RSA's in 10.00s
Doing 512 bit public rsa's for 10s: 79740 512 bit public RSA's in 10.00s
Doing 1024 bit private rsa's for 10s: 1310 1024 bit private RSA's in 10.00s
Doing 1024 bit public rsa's for 10s: 24731 1024 bit public RSA's in 9.99s
Doing 2048 bit private rsa's for 10s: 199 2048 bit private RSA's in 10.02s
Doing 2048 bit public rsa's for 10s: 6720 2048 bit public RSA's in 10.00s
Doing 4096 bit private rsa's for 10s: 28 4096 bit private RSA's in 10.24s
Doing 4096 bit public rsa's for 10s: 1740 4096 bit public RSA's in 10.00s
OpenSSL 1.0.1f 6 Jan 2014
built on: Mon Apr  7 21:20:02 UTC 2014
options:bn(64,32) rc4(8x,mmx) des(ptr,risc1,16,long) aes(partial) blowfish(idx)
compiler: cc -fPIC -DOPENSSL_PIC -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -DL_ENDIAN -DTERMIO -g -O2 -fstack-protector --param=ssp-buffer-size=4 -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2 -Wl,-Bsymbolic-functions -Wl,-z,relro -Wa,--noexecstack -Wall -DOPENSSL_BN_ASM_PART_WORDS -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DRMD160_ASM -DAES_ASM -DVPAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM
                  sign    verify    sign/s verify/s
rsa  512 bits 0.001390s 0.000125s    719.3   7974.0
rsa 1024 bits 0.007634s 0.000404s    131.0   2475.6
rsa 2048 bits 0.050352s 0.001488s     19.9    672.0
rsa 4096 bits 0.365714s 0.005747s      2.7    174.0


<B>WITH</B> padlock_pmm engine: 

root@it:~# ./openssl speed <B>dsa</B> -e padlockPMM
WARNING: can't open config file: /usr/local/ssl/openssl.cnf
Doing 512 bit sign dsa's for 10s: 12290 512 bit DSA signs in 10.00s
Doing 512 bit verify dsa's for 10s: 12243 512 bit DSA verify in 10.00s
Doing 1024 bit sign dsa's for 10s: 6356 1024 bit DSA signs in 9.99s
Doing 1024 bit verify dsa's for 10s: 5782 1024 bit DSA verify in 9.99s
Doing 2048 bit sign dsa's for 10s: 2265 2048 bit DSA signs in 10.00s
Doing 2048 bit verify dsa's for 10s: 1975 2048 bit DSA verify in 10.00s
OpenSSL 1.0.1t  3 May 2016
built on: Tue Aug  1 20:09:47 2017
options:bn(64,32) rc4(8x,mmx) des(ptr,risc1,16,long) aes(partial) idea(int) blowfish(idx) 
compiler: gcc -I. -I.. -I../include  -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -DXXXXXX -fPIC -DOPENSSL_PIC -DL_ENDIAN -DTERMIO -g -O2 -fstack-protector-strong -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2 -Wa,--noexecstack -march=i686 -Wa,--noexecstack -DL_ENDIAN -O3 -fomit-frame-pointer -Wall -DOPENSSL_BN_ASM_PART_WORDS -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DRMD160_ASM -DAES_ASM -DVPAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM
                  sign    verify    sign/s verify/s
dsa  512 bits 0.000814s 0.000817s   1229.0   1224.3
dsa 1024 bits 0.001572s 0.001728s    636.2    578.8
dsa 2048 bits 0.004415s 0.005063s    226.5    197.5


<B>WITHOUT</B> pmm engine: 

root@it:~# openssl speed <B>dsa</B>
Doing 512 bit sign dsa's for 10s: 7346 512 bit DSA signs in 10.00s
Doing 512 bit verify dsa's for 10s: 6930 512 bit DSA verify in 9.99s
Doing 1024 bit sign dsa's for 10s: 2427 1024 bit DSA signs in 10.00s
Doing 1024 bit verify dsa's for 10s: 2113 1024 bit DSA verify in 10.00s
Doing 2048 bit sign dsa's for 10s: 670 2048 bit DSA signs in 10.00s
Doing 2048 bit verify dsa's for 10s: 573 2048 bit DSA verify in 10.00s
OpenSSL 1.0.1f 6 Jan 2014
built on: Mon Apr  7 21:20:02 UTC 2014
options:bn(64,32) rc4(8x,mmx) des(ptr,risc1,16,long) aes(partial) blowfish(idx) 
compiler: cc -fPIC -DOPENSSL_PIC -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -DL_ENDIAN -DTERMIO -g -O2 -fstack-protector --param=ssp-buffer-size=4 -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2 -Wl,-Bsymbolic-functions -Wl,-z,relro -Wa,--noexecstack -Wall -DOPENSSL_BN_ASM_PART_WORDS -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DRMD160_ASM -DAES_ASM -DVPAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM
                  sign    verify    sign/s verify/s
dsa  512 bits 0.001361s 0.001442s    734.6    693.7
dsa 1024 bits 0.004120s 0.004733s    242.7    211.3
dsa 2048 bits 0.014925s 0.017452s     67.0     57.3

</pre> 
