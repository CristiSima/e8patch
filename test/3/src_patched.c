#include <stdio.h>

int __attribute__((noinline)) f1() {return 1;}
#define P0 "A"
#define P1 P0  P0
#define P2 P1  P1
#define P3 P2  P2
#define P4 P3  P3
#define P5 P4  P4
#define P6 P5  P5
#define P7 P6  P6
#define P8 P7  P7
#define P9 P8  P8
#define PA P9  P9
#define PB PA  PA
#define PC PB  PB
#define PD PC  PC
#define PE PD  PD
#define PF PE  PE
#define PX PF  PF

#define P PE

int big_stack()
{
	char *p = P;
	return (int)p;
}
int __attribute__((noinline)) f2() {return 2;}

typedef int (*int_func)();

const int_func fs[] = {
  big_stack,
  f2
};

int main(int argc, char **argv)
{
  printf("f1: %d\n", big_stack());
  printf("f2: %d\n", f2());
  printf("\n");

  printf("fs[0]: %d\n",
          fs[0]());
  printf("fs[1]: %d\n",
          fs[1]());
}
