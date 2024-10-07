#include <stdio.h>

int __attribute__((noinline)) f1() {return 1;}
int __attribute__((noinline)) f2() {return 2;}

typedef int (*int_func)();

const int_func fs[] = {
  f1,
  f2
};

int main(int argc, char **argv)
{
  printf("f1: %d\n", f1());
  printf("f2: %d\n", f2());
  printf("\n");

  printf("fs[0]: %d\n",
          fs[0]());
  printf("fs[1]: %d\n",
          fs[1]());
}
