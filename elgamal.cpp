#include<iostream>
#include<gmp.h>
#include<stdlib.h>
#include<time.h>
#include<string.h>
using namespace std;

mpz_t q,a,p;//全局参数：p为prime number;a为 primitive root of p;
mpz_t Xa,Ya;//Xa私钥;Ya公钥;
mpz_t M,K,C1,C2;//明文M;
mpz_t result;//解密后结果

int msize=128;//长度

gmp_randstate_t gmp_state;

//求出public key = {p,a,Ya}; private key Xa;
void key_generation(){

    mpz_urandomb(q,gmp_state,msize);//生成128bit的随机数
    mpz_nextprime(q,q);//生成素数q
    //p=2*q+1,构造一个素数p，使得p-1的因子只有1,2,q，p-1四个
    mpz_mul_ui(p,q,2);
    mpz_add_ui(p,p,1);
    //求生成元，1到p-1之间的随机数a不是单位元、阶不为2和q，
    //则其阶为p-1，进而证明得a为p的生成元
    mpz_t a_2,a_q;
    mpz_init(a_2);
    mpz_init(a_q);
    do{
        mpz_urandomm(a,gmp_state,p);//生成1到p-1的随机数
        mpz_powm_ui(a_2,a,2,p);//a_2=a^2 % p
        mpz_powm(a_q,a,q,p);//a_q=a^q % p
        if((mpz_cmp_ui(a,1)!=0)&&(mpz_cmp_ui(a_2,1)!=0)&&(mpz_cmp_ui(a_q,1)!=0))
        break;
    }while(1);
    mpz_urandomm(Xa,gmp_state,p);//生成私钥Xa
    mpz_powm(Ya,a,Xa,p);//生成公钥Ya,Ya=a^Xa % p

}

//输入明文，输出密文（C1，C2）
void elgamal_encrypt(const char* planttxt){
    mpz_t k;//随机数k
    mpz_init(k);
    mpz_urandomm(k,gmp_state,p);//生成随机数k
    mpz_set_str(M,planttxt,10);//明文M
    mpz_powm(K,Ya,k,p);//K= Ya^k % p
    mpz_powm(C1,a,k,p);//C1= a^k % p
    mpz_mul(C2,K,M);//C2= K*M
    mpz_mod(C2,C2,p);//C2= C2 % p
}

//输入密文（C1,C2），输出明文
void elgamal_decrypt(mpz_t tmp1,mpz_t tmp2){
    mpz_t tmpK;
    mpz_init(tmpK);
    mpz_powm(tmpK,tmp1,Xa,p);//tmpK= C1^Xa % p
    mpz_invert(tmpK,tmpK,p);//求tmpK逆元
    mpz_mul(result,tmp2,tmpK);//result= C2*tmpK^-1
    mpz_mod(result,result,p);//result= result % p
}

int main()
{
    string planttxt;
    mpz_init(q);//用于构造特殊素数
    mpz_init(a);//生成元a
    mpz_init(p);//全局素数p
    mpz_init(Xa);
    mpz_init(Ya);
    mpz_init(M);
    mpz_init(K);
    mpz_init(C1);
    mpz_init(C2);
    mpz_init(result);
    gmp_randinit_mt(gmp_state);//用于随机数生成
    //根据系统时间设置random的seed   
    gmp_randseed_ui(gmp_state,(unsigned int)(time(NULL)));

    cout<<"请输入密钥长度：";
    cin>>msize;
    cout<<endl;
    key_generation();//密钥生成
    cout<<"全局参数："<<endl;
    gmp_printf("{%Zd,\n%Zd,\n%Zd}\n\n",p,a,Ya);
    cout<<"请输入明文："<<endl;
    cin>>planttxt;
    cout<<endl;
    const char*pt=planttxt.c_str();
    elgamal_encrypt(pt);//elgamal加密
    gmp_printf("密文:\n(%Zd,\n%Zd)\n\n",C1,C2);
    elgamal_decrypt(C1,C2);//elgamal解密
    cout<<"解密后的明文："<<endl;
    gmp_printf("%Zd\n",result);
    mpz_clears(q,p,a);
    return 0;
}