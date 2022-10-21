#include <stdio.h>
#include "func.h"

int main(int argc, char* argv[])
{
    int p = 41, q = 67;
    int N = 0;
    int L = 0;
    int E = 0;
    char text[30] = { "Hello World!" };
    char cipher[30] = { 0 };

    //while (TURE)
    //{
    //    p = prime_rand();
    //    q = prime_rand();
    //    if (p != q)
    //        break;
    //}
    N = p * q;
    L = LCM(p, q);
    E = GCD(L);
    hexstr_to_bytes(cipher, strlen(text), text);

    printf("p = %d, q = %d\n", p, q);
    printf("N = %d\n", N);
    printf("L = %d\n", L);
    printf("E = %d\n", E);
    printf("cipher = %x\n", cipher);
    sayHi();
    system("pause");
    return 0;

}