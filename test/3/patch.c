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

#pragma replace f1 new:big_stack
int big_stack()
{
	char *p = P;
	return (int)p;
}

