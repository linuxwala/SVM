//Program to convert the features into SVM format
#include<stdio.h>
#include<stdlib.h>
void main()
{
FILE *fp;
FILE *ft;
int ch,i=0,c;
fp=fopen("temps.txt","r");  //input file
if(fp==NULL)
         {
               //puts(“cannot open file”);
               exit(1);
         }
ft=fopen("svm1.txt","w"); //temp file
if(ft==NULL)
	{
              // puts(“Cannot open target file”) ;
               fclose(fp);
               exit(1) ;
        }
while(1)
        {
               
               ch=fgetc(fp);
               if (ch==EOF)
                      break; 
               else if (ch=='/')
                      {
                      ch='\t'; //new vectors are marked by /t in temps.txt
                      fputc(ch,ft);                      
               	      fputc(ch,ft); 
               	      }                             
               else if(ch=='#') 
               	{     
               	ch=' ';
               	fputc(ch,ft);               	      
               	      ch=fgetc(fp);
               	      fputc(ch,ft);
               	      while((ch!=' ')) 
               	      {
               	     
               	      ch=fgetc(fp);             	       	      
               	      fputc(ch,ft);
               	      }                	             	                     	     
                     }     
                     i=0;              
        } 
        fclose(fp);
        fclose(ft);
        FILE *fs,*fr;
fs=fopen("svm1.txt","r"); //temp file
fr=fopen("svm.txt","w");  //output file
while(1)
{

	ch=fgetc(fs);
	if (ch==EOF)
        break; 	
	else if((ch==' '))
		{
		 	i++;
		 	c=' ';
		 	fputc(c,fr);
		 	if(i<39)
		 	{
			fprintf(fr,"%d",i);
			c=':';
		 	fputc(c,fr);
			}
			ch=fgetc(fs);  
			if((ch!=' '))           	       	      
               	      {
               	      fputc(ch,fr); 
               	      }
		}
	else if((ch=='\t'))
		{
			i=0;
			c='\n';
			fputc(c,fr);
		}
	else
		{
			fputc(ch,fr);
		}
	}   
fclose(fs);
fclose(fr);    
}
