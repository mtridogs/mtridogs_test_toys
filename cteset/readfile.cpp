#include "namespace_me.h"
#include <Windows.h>
void filebinread::readfilebin(string filepath)
{
	char *dosbuf= (char*)malloc(sizeof(DOS_HEADER));
	char *pehead= (char*)malloc(sizeof(IMAGE_NT_HEADERS64 ));
	char *datadirection= (char*)malloc(sizeof(DATA_DIRECTION ));
	char *imagesection = (char*)malloc(sizeof(IMAGE_SECTION_HEADER));
	DOS_HEADER *dosheader=(DOS_HEADER*)malloc(sizeof(DOS_HEADER));
	IMAGE_NT_HEADERS64 *ntpeheader = (IMAGE_NT_HEADERS64 *)malloc(sizeof(IMAGE_NT_HEADERS64));
	DATA_DIRECTION* data_direction = (DATA_DIRECTION *)malloc(sizeof(DATA_DIRECTION));
	IMAGE_SECTION_HEADER *imagesec_header = (IMAGE_SECTION_HEADER *)malloc(sizeof(IMAGE_SECTION_HEADER));

    vector<IMAGE_SECTION_HEADER *> image_se_header;//内有节表
	


	std::ifstream filestream(filepath,std::ios::binary);

	filestream.read(dosbuf,sizeof(DOS_HEADER));
	dosheader = (DOS_HEADER*)dosbuf;

	int pehe = dosheader->e_lfanew;//DOS

	filestream.seekg(pehe);//seek point
	filestream.read(pehead,pehe);//PE HEADER 64
	ntpeheader = (IMAGE_NT_HEADERS64*)pehead;//pentheader

	int datastart = ntpeheader->OptionalHeader.DataDirectory->VirtualAddress;
	int peek32=pehe+sizeof(IMAGE_NT_HEADERS32);
	int peek64=pehe+sizeof(IMAGE_NT_HEADERS64);

	while(true){
	if(ntpeheader->FileHeader.Machine==0x8664)//judge cpu x86 or x64
	{
    filestream.seekg(peek64);//seek point
	filestream.read(imagesection,sizeof(IMAGE_SECTION_HEADER));
	imagesec_header=(IMAGE_SECTION_HEADER*)imagesection;
	if(imagesec_header->SizeOfRawData==0)
	break;
	else{
	image_se_header.push_back(imagesec_header);}}
	else{
	filestream.seekg(peek32);//seek point
	filestream.read(imagesection,sizeof(IMAGE_SECTION_HEADER));
	imagesec_header=(IMAGE_SECTION_HEADER*)imagesection;
	if(imagesec_header->SizeOfRawData==0)
	break;
	else{
	image_se_header.push_back(imagesec_header);}}
	peek32=peek32+sizeof(IMAGE_SECTION_HEADER);
	peek64=peek64+sizeof(IMAGE_SECTION_HEADER);
	}//while 循环结束

	





}