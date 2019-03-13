#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include <string.h>
#include "panonymizer.h"

int main(int argc, char * argv[]) {
	
	using namespace std;
	
    	// Provide your own 256-bit key here
    	unsigned char my_key[32] = 
    	{21,34,23,141,51,164,207,128,19,10,91,22,73,144,125,16,
     	216,152,143,131,121,121,101,39,98,87,76,45,42,132,34,2};

    	FILE * f;
    
    	// Create an instance of PAnonymizer with the key
    	PAnonymizer my_anonymizer(my_key);

    	unsigned int raw_srcip, raw_dstip, anonymized_srcip, anonymized_dstip;
    	unsigned int srcOc1, srcOc2, srcOc3, srcOc4, dstOc1, dstOc2, dstOc3, dstOc4;
    	unsigned int version;
    	std::string  protocol, srcipv4, dstipv4, nextHeader, srcipv6, dstipv6; 
    	char pkthead[2048];
    	char pkttail[2048];	

    	if (argc != 2) {
      		fprintf(stderr, "usage: sample raw-trace-file\n");
      		exit(-1);
    	}
    
    	if ((f = fopen(argv[1],"r")) == NULL) {
      		fprintf(stderr,"Cannot open file %s\n", argv[0]);
      		exit(-2);
    	}
	
	ofstream myfile;
	myfile.open ("anonymized2.dat");    

    	//readin and handle each line of the input file
    	while  (fscanf(f, "%u", &version) != EOF) {
		if(version == 4){
			char* pkthead2 = pkthead;
			for(int i = 0; i < 12; i ++){
				fscanf(f,"%s",pkthead2);
				pkthead2 += strlen(pkthead2);
				strcpy(pkthead2,"\t");
				pkthead2 ++;
			}		
			*pkthead2 = 0;
			if(fscanf(f,"%u.%u.%u.%u\t%u.%u.%u.%u", &srcOc1, &srcOc2, &srcOc3, &srcOc4, &dstOc1, &dstOc2, &dstOc3, &dstOc4)!=8){
				cout << "Feil!";
				exit(-1);
			}
			char * pkttail2 = pkttail;
			for(int i = 0; i < 26; i ++){
				fscanf(f,"%s",pkttail2);
				pkttail2 += strlen(pkttail2);
				strcpy(pkttail2,"\t");
				pkttail2 ++;
			}		
			*pkttail2 = 0;

			//convert the raw IP from a.b.c.d format into unsigned int format.
			raw_srcip = (srcOc1 << 24) + (srcOc2 << 16) + (srcOc3 << 8) + srcOc4;
			raw_dstip = (dstOc1 << 24) + (dstOc2 << 16) + (dstOc3 << 8) + dstOc4;
	
			//Anonymize the raw IP
			anonymized_srcip = my_anonymizer.anonymize(raw_srcip);
			anonymized_dstip = my_anonymizer.anonymize(raw_dstip);

			//convert the anonymized IP from unsigned int format to a.b.c.d format
			srcOc1 = anonymized_srcip >> 24;
			srcOc2 = (anonymized_srcip << 8) >> 24;
			srcOc3 = (anonymized_srcip << 16) >> 24;
			srcOc4 = (anonymized_srcip << 24) >> 24;
			dstOc1 = anonymized_dstip >> 24;
			dstOc2 = (anonymized_dstip << 8) >> 24;
			dstOc3 = (anonymized_dstip << 16) >> 24;
			dstOc4 = (anonymized_dstip << 24) >> 24;
	
			//converts octets into string address	
			srcipv4 = std::to_string(srcOc1) + "." + std::to_string(srcOc2) + "." + std::to_string(srcOc3) + "." + std::to_string(srcOc4);
			dstipv4 = std::to_string(dstOc1) + "." + std::to_string(dstOc2) + "." + std::to_string(dstOc3) + "." + std::to_string(dstOc4);

			//stores the data to file
			myfile << version << "\t" << pkthead << srcipv4 << "\t" << dstipv4 << "\t" << pkttail << std::string("\n");
		}
		else{
			*pkthead = 0;
			char * pkttail2 = pkttail;
			for(int i = 0; i < 40; i ++){
				fscanf(f,"%s",pkttail2);
				pkttail2 += strlen(pkttail2);
				strcpy(pkttail2,"\t");
				pkttail2 ++;
			}		
			*pkttail2 = 0;
		
			//stores the data to file
			myfile << version << "\t" << pkttail << std::string("\n");
		}
    	}
	myfile.close();
	fclose(f);
}
