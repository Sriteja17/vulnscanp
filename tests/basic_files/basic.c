#include<stdio.h>
#include<string.h>
int main() {
    char a[10];
     gets(a);//using gets
    char b[5];
    strcpy(b,a);
   int gets_value=1;
    printf("%s",b);
    char c[15];
    scanf("%s",c);
    return 0;
}