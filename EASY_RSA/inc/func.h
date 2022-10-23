#ifndef FUNC_H
#define FUNC_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TURE 1

__declspec(dllexport) int prime_rand();
__declspec(dllexport) int LCM(int, int);
__declspec(dllexport) int GCD(int);
__declspec(dllexport) int hexstr_to_bytes(const char* hex, int count, char* data);
__declspec(dllexport) int sayHi(void);

#endif // FUNC
