#include <stdio.h>
#include <stdlib.h>

int new_count = 6;
#pragma replace f1 new:new
int new()
{
	int static a = 0;
	new_count += 10;
	a += new_count;
	return a;
}

int f2();
#pragma replace f2 old=f2 new:f2_plus_10
int f2_plus_10()
{
	return f2() + 10;
}

#pragma replace identity new=factorial
int factorial(int n) {
   //base case
   if(n == 0) {
      return 1;
   } else {
      return n * factorial(n-1);
   }
}

extern int secret;

void og_init();
#pragma replace init new=change_secret old=og_init
void change_secret()
{
	system("id");
	// gcc added.c -c -O0 -fno-stack-protector
	// otherwise it needs __stack_check_failed which might not be present
	char tmp[] = "[stack]  What do you mean that secret is %X, it's clearely %X\n";
	printf(tmp, secret, 0xDEADBEEF);
	printf("[rodata] What do you mean that secret is %X, it's clearely %X\n", secret, 0xDEADBEEF);
	secret = 0xDEADBEEF;

	og_init();

	printf("f2 @%p\n", f2);
	printf("system @%p\n", system);
	
	puts("");

	printf("f2[0]: %llX\n", *(long long int*)f2);
	printf("system[0]: %llX\n", *(long long int*)system);
}
