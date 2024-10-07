#include <stdio.h>
#include <stdlib.h>

int new_6 = 6;

void og_init();
#pragma replace init new=change_secret old=og_init
void change_secret()
{
	// gcc added.c -c -O0 -fno-stack-protector
	// otherwise it needs __stack_check_failed which might not be present
	printf("system @%p\n", system);
	printf("new_6: %d\n", new_6);
}
