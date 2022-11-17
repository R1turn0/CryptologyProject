#include "func.h"

__declspec(dllexport) int prime_rand()
{
    int flag = 1;
    int num = 0;
    int i = 0, j = 0;
    long long a[3] = { 31, 29, 12 };

    //srand(time(NULL));
    num = rand() % 100;
    if (num < 2)
        return prime_rand();
    if (num % 2 == 0 || num % 3 == 0 || num % 5 == 0)
        return prime_rand();
    for (i = 0; i < num; i++)
        for (j = 0; j < sizeof(a) / sizeof(a[0]); i++)
            a[j] *= a[j];
    for (j = 0; j < sizeof(a) / sizeof(a[0]); i++)
        a[j] -= a[j];
    for (j = 0; j < sizeof(a) / sizeof(a[0]); i++)
        if (a[j] % num != 0)
            return prime_rand();
    return num;

    //for (i = 2; i < num; i++)
    //{
    //    if (num % i == 0)
    //    {
    //        break;
    //    }
    //}
    //if (i >= num)
    //{
    //    return num;
    //}
    //else
    //{
    //    return prime_rand();
    //}
}

__declspec(dllexport) int LCM(int p, int q)// 最小公倍数
{
    int L = 0;
    int i = 0;

    p -= 1;
    q -= 1;
    for (i = 1; ; i++)
    {
        if (i % p == 0 && i % q == 0)
        {
            break; 
        }
    }
    return i;
}

__declspec(dllexport) int GCD(int L)// 最大公约数
{
    int tmp = 0;
    int E = rand();
    int n, m;
    if (E > L)
    {
        return GCD(L);
    }
    m = E;
    n = L;
    while (n % m)
    {
        tmp = n % m;
        n = m;
        m = tmp;
    }
    tmp = m;
    if (tmp != 1)
    {
        return GCD(L);
    }
    return E;
}

__declspec(dllexport) int hexstr_to_bytes(const char* hex, int count, char* data)
{
    unsigned char temp[2];
    int i, j;

    if (hex == NULL || data == NULL || (int)strlen(hex) > count * 2)
    {
        return 1;
    }
    for (i = 0; i != count; ++i)
    {
        for (j = 0; j != 2; ++j)
        {
            if (hex[2 * i + j] >= '0' && hex[2 * i + j] <= '9')
            {
                temp[j] = hex[2 * i + j] - '0';
            }
            else if (hex[2 * i + j] >= 'A' && hex[2 * i + j] <= 'F')
            {
                temp[j] = hex[2 * i + j] - 'A' + 10;
            }
            else if (hex[2 * i + j] >= 'a' && hex[2 * i + j] <= 'f')
            {
                temp[j] = hex[2 * i + j] - 'a' + 10;
            }
            else
            {
                return 1;
            }
        }

        data[i] = (temp[0] << 4) + temp[1];
    }
    return 0;
}

__declspec(dllexport) int sayHi(void)
{
    char* szinfo = NULL;
    if (szinfo)
    {
        printf("%x\n", szinfo);
        szinfo = NULL;
    }
    else
    {
        printf("Why didn't I say hi?\n");
    }
    return 0;
}