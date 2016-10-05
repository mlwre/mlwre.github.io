#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int RecorreArray_401000(char *a1){
  char *i; // eax@1
  for (i = a1; *i; ++i )
    ;
  return i - a1;
}

/**/
FILE *DecodeFile_40152A(char *Filename, char  *a2)
{
  
  FILE *result; // eax@1
  unsigned int i; // [sp+4h] [bp-14h]@2
  unsigned int v4; // [sp+8h] [bp-10h]@2
  unsigned int Size; // [sp+Ch] [bp-Ch]@2
  void *DstBuf; // [sp+10h] [bp-8h]@2
  FILE *File,*dresult; // [sp+14h] [bp-4h]@2

  result = fopen(Filename, "rb");
  dresult = fopen("decrypt.raw","ab");

  if ( result )
  {
    File = result;
    fseek(result, 0, 2);
    Size = ftell(File);
    fseek(File, 0, 0);
    DstBuf = malloc(Size);
    fread(DstBuf, 1u, Size, File);
    v4 = RecorreArray_401000((char *)a2);
    for ( i = 0; i < Size; ++i )
      *((char *)DstBuf + i) ^= *(char *)(i % v4 + a2);
    fseek(File, 0, 0);
    fwrite(DstBuf, 1u, Size, dresult);
    free(DstBuf);
    fclose(File);
    result = (FILE *)1;
  }
  return result;
}



int main(int arv, char *argv[]){	
	if(arv<2){
		printf("Usage: <%s> File\n",argv[0]);
		exit(1);
	}else{
		char pass[]="666AnotherPassword666";
		printf("Pass: %s\tFile%s\n",pass,argv[1]);
		DecodeFile_40152A(argv[1],pass);
	}
}