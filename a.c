#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char* argv[])
{
	char* s = NULL;

	strlen(s);

	if ((s == NULL) || (strlen(s) == 0))
	{
		printf("aaaaa\n");
	}

	printf("bbbbb\n");
	return 0;
}
