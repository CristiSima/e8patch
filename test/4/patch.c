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

#pragma replace f1 new:big_stack
int big_stack()
{
	char p[] = P;
	NOPN;
	return (int)p;
}

