int new_count = 6;
#pragma replace f1 new:new
int new()
{
	int static a = 0;
	new_count += 10;
	a += new_count;
	return a;
}

int f2();
#pragma replace f2 old=f2 new:f2_plus_10
int f2_plus_10()
{
	return f2() + 10;
}
