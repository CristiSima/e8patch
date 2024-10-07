#include <stdio.h>
#include <stdlib.h>

int old_secret;
int secret = 0xCAFEBABE;
void init();

void old_init()
{
	puts("Initializing...");
	puts("Initialisation done");
}

int main(int argc, char **argv)
{
	init();
	printf("secret = %x\n", secret);
}

void init()
{
	system("id");
	old_secret = secret;
	secret = 0;
	
	old_init();
}