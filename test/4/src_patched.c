#include <stdio.h>

int __attribute__((noinline)) f1() {return 1;}
#define NOP1 asm("nop");
#define NOP2 NOP1 NOP1
#define NOP3 NOP2 NOP2
#define NOP4 NOP3 NOP3
#define NOP5 NOP4 NOP4
#define NOP6 NOP5 NOP5
#define NOP7 NOP6 NOP6
#define NOP8 NOP7 NOP7
#define NOP9 NOP8 NOP8
#define NOPA NOP9 NOP9
#define NOPB NOPA NOPA
#define NOPC NOPB NOPB
#define NOPD NOPC NOPC
#define NOPE NOPD NOPD
#define NOPF NOPE NOPE
#define NOPX NOPF NOPF

#define NOPN NOPX

#define P "123"

int big_stack()
{
	char p[] = P;
	NOPN;
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
