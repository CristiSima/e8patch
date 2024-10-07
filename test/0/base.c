#include <stdio.h>
#include <stdlib.h>

int __attribute__((noinline)) f1() {return 1;}
int __attribute__((noinline)) f2() {return 2;}

int secret=0xcafebabe;

void init()
{
	puts("Initialization Completed!");
}

int __attribute__((noinline)) identity(int nr) { return nr; }
typedef int (*int_func)();

const int_func fs[] = {
	f1,
	f2
};

const int_func *fs_p[] = {
	NULL,
	fs
};

int main(int argc, char **argv)
{
	puts("OK");
	init();

	printf("og 1B8E5894855\n");
	printf("f1 %llX\n", *((long long int *)f1));

	printf("id(8): %d\n", identity(8));

	printf("f1: %d\n", f1());
	printf("f2: %d\n", f2());

	printf("secret: %X, %d\n", secret, secret);

	if(argc == 2)
	{
		printf("Using `%s`\n", argv[1]);
		printf("fs[<arg1=%s>]: %d\n", argv[1], fs_p[1][atoi(argv[1])]());
	}

	puts("And done");

	return 0;
}
