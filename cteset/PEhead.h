#include <Windows.h>

typedef struct DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    DWORD   e_lfanew;                    // File address of new exe header
  } DOS_HEADER, *DOS_HEADERS;

typedef struct DATA_DIRECTION{
	DWORD export_tableava;
	DWORD export_size;
	DWORD import_table;
	DWORD import_size;
	DWORD resource_table;
	DWORD resource_size;
	DWORD exception_table;
	DWORD exception_size;
	DWORD certificate_table;
	DWORD certificate_size;
	DWORD relocation_table;
    DWORD relocation_size;
    DWORD debug_table;
    DWORD debug_size;
    DWORD Architecture_table;
	DWORD Architecture_size;
	DWORD Global_ptr_table;
	DWORD Global_ptr_size;
	DWORD TLS_table;
	DWORD TLS_size;
	DWORD LOAD_table;
	DWORD LOAD_size;
	DWORD BOUND_table;
	DWORD BOUND_size;
	DWORD IAT_table;
	DWORD IAT_size;
	DWORD Delay_import_table;
	DWORD Delay_import_size;
	DWORD CLR_table;
	DWORD CLR_size;
	DWORD Reserved_table;
	DWORD Reserved_size;
}DATA_DIRECTION;