#include <stdio.h>
#include <stdlib.h>

int __attribute__((noinline)) f1() {return 1;}
int __attribute__((noinline)) f2() {return 2;}


int new();
int f2_plus_10();
int factorial(int n);
void change_secret();

int secret=0xcafebabe;

void init()
{
	puts("Initialization Completed!");
}

int __attribute__((noinline)) identity(int nr) { return nr; }
typedef int (*int_func)();

const int_func fs[] = {
	new,
	f2_plus_10
};

const int_func *fs_p[] = {
	NULL,
	fs
};

int main(int argc, char **argv)
{
	puts("OK");
	change_secret();

	printf("og 1B8E5894855\n");
	printf("f1 %llX\n", *((long long int *)new));

	printf("id(8): %d\n", factorial(8));

	printf("f1: %d\n", new());
	printf("f2: %d\n", f2_plus_10());

	printf("secret: %X, %d\n", secret, secret);

	if(argc == 2)
	{
		printf("Using `%s`\n", argv[1]);
		printf("fs[<arg1=%s>]: %d\n", argv[1], fs_p[1][atoi(argv[1])]());
	}

	puts("And done");

	return 0;
}


int new_count = 6;
int new()
{
	int static a = 0;
	new_count += 10;
	a += new_count;
	return a;
}

int f2_plus_10()
{
	return f2() + 10;
}

int factorial(int n) {
   //base case
   if(n == 0) {
      return 1;
   } else {
      return n * factorial(n-1);
   }
}

void change_secret()
{
	system("id");
	// gcc added.c -c -O0 -fno-stack-protector
	// otherwise it needs __stack_check_failed which might not be present
	char tmp[] = "[stack]  What do you mean that secret is %X, it's clearely %X\n";
	printf(tmp, secret, 0xDEADBEEF);
	printf("[rodata] What do you mean that secret is %X, it's clearely %X\n", secret, 0xDEADBEEF);
	secret = 0xDEADBEEF;

	init();

	printf("f2 @%p\n", f2);
	printf("system @%p\n", system);
	
	puts("");

	printf("f2[0]: %llX\n", *(long long int*)f2);
	printf("system[0]: %llX\n", *(long long int*)system);
}
