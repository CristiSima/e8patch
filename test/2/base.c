#include <stdio.h>
#include <stdlib.h>

int secret = 0xCAFEBABE;

void init()
{
	puts("Initializing...");
	puts("Initialisation done");
}

int main(int argc, char **argv)
{
	init();
	printf("secret = %x\n", secret);
}
