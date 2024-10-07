#include <stdio.h>

int f1() {return 1;}
int f2() {return 2;}

int new();
int f2_plus_10();

typedef int (*int_func)();

const int_func fs[] = {
  new,
  f2_plus_10
};

int main(int argc, char **argv)
{
  printf("f1: %d\n", new());
  printf("f2: %d\n", f2_plus_10());
  printf("\n");

  printf("fs[0]: %d\n",
          fs[0]());
  printf("fs[1]: %d\n",
          fs[1]());
}

int new_count = 6;
#pragma replace f1 new:new
int new()
{
	int static a=0;
	new_count+=10;
	a+=new_count;
	return a;
}

int f2();
#pragma replace f2 old=f2 new:f2_plus_10
int f2_plus_10()
{
	return f2() + 10;
}
