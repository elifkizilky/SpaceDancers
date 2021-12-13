typedef string Path<1000>;


/* Specify the arguments */
struct parameters{
	int number1;
	int number2;
	Path path;
};

/* 
 * 1. Name the program and give it a unique number.
 * 2. Specify the version of the program.
 * 3. Specify the signature of the program.
*/
program PART_B_PROG{
	version PART_B_VERS{
		/* Takes a parameters structure and gives the string result. */
		string part_b(parameters)=1;
	}=1;
}=0x12345678;