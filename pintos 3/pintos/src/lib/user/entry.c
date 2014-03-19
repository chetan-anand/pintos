#include <syscall.h>

int main (int, char *[]);
void _start (int argc, char *argv[]);

void
_start (int argc, char *argv[]) 
{
  /*
  	Return value is perfect.
  */
  /*int return_value=main (argc,argv);
  printf("Return Value:%d",return_value);*/
  exit (main (argc,argv));
}
