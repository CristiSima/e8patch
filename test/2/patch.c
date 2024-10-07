#include <stdio.h>
#include <stdlib.h>

#pragma replace init new=init2 old=old_init
extern int secret;

void init2()
{
	system("id");

	secret = 0;

	old_init();
}