#include <pbc/pbc.h>

int main(int argc, char **argv) {
    mpz_t z,V,M;
    element_t s,r,P,Ppub,Qid,dID,gID,gIDr,U,tem1;
    pairing_pp_t pp;

    pairing_t pairing;
    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing, param, count);


    //整数
    mpz_init(z);
    mpz_init(V);
    //初始化并给消息赋值
    mpz_init_set_str(M, "201806014", 0);
    gmp_printf ("M: %Zd\n", M);

    //在1和r之间的整数
    element_init_Zr(s, pairing);
    element_init_Zr(r, pairing);

    //循环群G1
    element_init_G1(P, pairing);
    element_init_G1(Ppub, pairing);
    element_init_G1(Qid, pairing);
    element_init_G1(dID, pairing);
    element_init_G1(U, pairing);

    //循环群GT
    element_init_GT(gID, pairing);
    element_init_GT(gIDr, pairing);
    element_init_GT(tem1, pairing);

    //Setup, system parameters generation
    printf("SETUP STAGE\n");
    element_random(P);
    element_random(s);
    element_mul_zn(Ppub, P, s);//Ppub=sP

    //Extract, key calculation
    printf("EXTRACT STAGE\n");
    element_from_hash(Qid, "A", 1);//Qid=H("A")
    element_mul_zn(dID, Qid, s);

    //Encrypt encrypt M with ID
    printf("Encrypt STAGE\n");
    element_random(r);
    element_mul_zn(U, P, r);
    pairing_pp_init(pp, Ppub, pairing);
    pairing_pp_apply(gID, Qid, pp); //gID=e(Qid,Ppub)
    pairing_pp_clear(pp);
    element_mul_zn(gIDr, gID, r); //gIDr=gID^r
    element_to_mpz(z,gIDr); //H(gIDr)
    gmp_printf("z: %Zd\n", z);
    mpz_xor(V,M,z); //V=M xor z
    element_printf("U: %B\n", gIDr);
    gmp_printf("V: %Zd\n", V);

    //Decrypt decrypt C = <U,V>
    printf("Decrypt STAGE\n");
    pairing_pp_init(pp, U, pairing);
    pairing_pp_apply(tem1,dID, pp);
    pairing_pp_clear(pp);
    element_to_mpz(z,tem1);
    mpz_xor(M,V,z);
    gmp_printf("M: %Zd\n", M);

    //释放内存
    mpz_clear(z);
    mpz_clear(V);
    mpz_clear(M);
    element_clear(s);
    element_clear(r);
    element_clear(P);
    element_clear(Ppub);
    element_clear(Qid);
    element_clear(dID);
    element_clear(gID);
    element_clear(gIDr);
    element_clear(U);
    element_clear(tem1);

    return 0;
}