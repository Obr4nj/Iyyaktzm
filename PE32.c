#include <stdio.h>
#include <string.h>
#include "Windows.h"

int main(int argc, char* argv[]) {
	size_t MAX_FILEPATH = 255;
	char fileName[MAX_FILEPATH];
	char filenamein[MAX_FILEPATH];
	printf("Input file name: ");
	scanf("%s", &fileName);
	printf("\n");
	//memcpy_s(&fileName, MAX_FILEPATH, argv[1], MAX_FILEPATH); //argv[1]
	HANDLE file = NULL;
	DWORD fileSize = NULL;
	DWORD bytesRead = NULL;
	LPVOID fileData = NULL;
	PIMAGE_DOS_HEADER dosHeader = {0};
	PIMAGE_NT_HEADERS imageNTHeaders = {0};
	PIMAGE_SECTION_HEADER sectionHeader = {0};
	PIMAGE_SECTION_HEADER importSection = {0};
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor = {0};
	PIMAGE_THUNK_DATA thunkData = {0};
	DWORD thunk = NULL;
	DWORD rawOffset = NULL;

	// open file
	file = CreateFileA(fileName, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		puts("Could not read file!!!");
		exit(1);
	}

	// allocate heap
	fileSize = GetFileSize(file, NULL);
	fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);

	// read file bytes to memory
	ReadFile(file, fileData, fileSize, &bytesRead, NULL);

	// IMAGE_DOS_HEADER
	dosHeader = (PIMAGE_DOS_HEADER)fileData;
	puts("- DOS HEADER");
	printf("\t%04hX\t\tMagic number\n", dosHeader->e_magic);
	printf("\t%04hX\t\tBytes on last page of file\n", dosHeader->e_cblp);
	printf("\t%04hX\t\tPages in file\n", dosHeader->e_cp);
	printf("\t%04hX\t\tRelocations\n", dosHeader->e_crlc);
	printf("\t%04hX\t\tSize of header in paragraphs\n", dosHeader->e_cparhdr);
	printf("\t%04hX\t\tMinimum extra paragraphs needed\n", dosHeader->e_minalloc);
	printf("\t%04hX\t\tMaximum extra paragraphs needed\n", dosHeader->e_maxalloc);
	printf("\t%04hX\t\tInitial (relative) SS value\n", dosHeader->e_ss);
	printf("\t%04hX\t\tInitial SP value\n", dosHeader->e_sp);
	printf("\t%04hX\t\tInitial SP value\n", dosHeader->e_sp);
	printf("\t%04hX\t\tChecksum\n", dosHeader->e_csum);
	printf("\t%04hX\t\tInitial IP value\n", dosHeader->e_ip);
	printf("\t%04hX\t\tInitial (relative) CS value\n", dosHeader->e_cs);
	printf("\t%04hX\t\tFile address of relocation table\n", dosHeader->e_lfarlc);
	printf("\t%04hX\t\tOverlay number\n", dosHeader->e_ovno);
	printf("\t%04hX\t\tOEM identifier (for e_oeminfo)\n", dosHeader->e_oemid);
	printf("\t%04hX\t\tOEM information; e_oemid specific\n", dosHeader->e_oeminfo);
	printf("\t%08hX\tFile address of new exe header\n", dosHeader->e_lfanew);

	// IMAGE_NT_HEADERS
	imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)fileData + dosHeader->e_lfanew);
	puts("\n- NT HEADERS");
	printf("\t%08hX\tSignature\n", imageNTHeaders->Signature);

	// FILE_HEADER
	puts("\n- FILE HEADER");
	printf("\t%04hX\t\tMachine\n", imageNTHeaders->FileHeader.Machine);
	printf("\t%04hX\t\tNumber of Sections\n", imageNTHeaders->FileHeader.NumberOfSections);
	printf("\t%08hX\tTime Stamp\n", imageNTHeaders->FileHeader.TimeDateStamp);
	printf("\t%08hX\tPointer to Symbol Table\n", imageNTHeaders->FileHeader.PointerToSymbolTable);
	printf("\t%08hX\tNumber of Symbols\n", imageNTHeaders->FileHeader.NumberOfSymbols);
	printf("\t%04hX\t\tSize of Optional Header\n", imageNTHeaders->FileHeader.SizeOfOptionalHeader);
	printf("\t%04hX\t\tCharacteristics\n", imageNTHeaders->FileHeader.Characteristics);

	// OPTIONAL_HEADER
	puts("\n- OPTIONAL HEADER");
	printf("\t%04hX\t\tMagic\n", imageNTHeaders->OptionalHeader.Magic);
	printf("\t%02hX\t\tMajor Linker Version\n", imageNTHeaders->OptionalHeader.MajorLinkerVersion);
	printf("\t%02hX\t\tMinor Linker Version\n", imageNTHeaders->OptionalHeader.MinorLinkerVersion);
	printf("\t%08hX\tSize Of Code\n", imageNTHeaders->OptionalHeader.SizeOfCode);
	printf("\t%08hX\tSize Of Initialized Data\n", imageNTHeaders->OptionalHeader.SizeOfInitializedData);
	printf("\t%08hX\tSize Of UnInitialized Data\n", imageNTHeaders->OptionalHeader.SizeOfUninitializedData);
	printf("\t%08hX\tAddress Of Entry Point (.text)\n", imageNTHeaders->OptionalHeader.AddressOfEntryPoint);
	printf("\t%08hX\tBase Of Code\n", imageNTHeaders->OptionalHeader.BaseOfCode);
	//printf("\t%08hX\t\tBase Of Data\n", imageNTHeaders->OptionalHeader.BaseOfData);
	printf("\t%08hX\tImage Base\n", imageNTHeaders->OptionalHeader.ImageBase);
	printf("\t%08hX\tSection Alignment\n", imageNTHeaders->OptionalHeader.SectionAlignment);
	printf("\t%08hX\tFile Alignment\n", imageNTHeaders->OptionalHeader.FileAlignment);
	printf("\t%04hX\t\tMajor Operating System Version\n", imageNTHeaders->OptionalHeader.MajorOperatingSystemVersion);
	printf("\t%04hX\t\tMinor Operating System Version\n", imageNTHeaders->OptionalHeader.MinorOperatingSystemVersion);
	printf("\t%04hX\t\tMajor Image Version\n", imageNTHeaders->OptionalHeader.MajorImageVersion);
	printf("\t%04hX\t\tMinor Image Version\n", imageNTHeaders->OptionalHeader.MinorImageVersion);
	printf("\t%04hX\t\tMajor Subsystem Version\n", imageNTHeaders->OptionalHeader.MajorSubsystemVersion);
	printf("\t%04hX\t\tMinor Subsystem Version\n", imageNTHeaders->OptionalHeader.MinorSubsystemVersion);
	printf("\t%08hX\tWin32 Version Value\n", imageNTHeaders->OptionalHeader.Win32VersionValue);
	printf("\t%08hX\tSize Of Image\n", imageNTHeaders->OptionalHeader.SizeOfImage);
	printf("\t%08hX\tSize Of Headers\n", imageNTHeaders->OptionalHeader.SizeOfHeaders);
	printf("\t%08hX\tCheckSum\n", imageNTHeaders->OptionalHeader.CheckSum);
	printf("\t%04hX\t\tSubsystem\n", imageNTHeaders->OptionalHeader.Subsystem);
	printf("\t%04hX\t\tDllCharacteristics\n", imageNTHeaders->OptionalHeader.DllCharacteristics);
	printf("\t%08hX\tSize Of Stack Reserve\n", imageNTHeaders->OptionalHeader.SizeOfStackReserve);
	printf("\t%08hX\tSize Of Stack Commit\n", imageNTHeaders->OptionalHeader.SizeOfStackCommit);
	printf("\t%08hX\tSize Of Heap Reserve\n", imageNTHeaders->OptionalHeader.SizeOfHeapReserve);
	printf("\t%08hX\tSize Of Heap Commit\n", imageNTHeaders->OptionalHeader.SizeOfHeapCommit);
	printf("\t%08hX\tLoader Flags\n", imageNTHeaders->OptionalHeader.LoaderFlags);
	printf("\t%08hX\tNumber Of Rva And Sizes\n", imageNTHeaders->OptionalHeader.NumberOfRvaAndSizes);

	// DATA_DIRECTORIES
	puts("\n- DATA DIRECTORIES");
	printf("\tExport Directory RVA:\t\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	printf("\tExport Directory Size:\t\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[0].Size);
	printf("\tImport Directory RVA:\t\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[1].VirtualAddress);
	printf("\tImport Directory Size:\t\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[1].Size);
	printf("\tResource Directory RVA:\t\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[2].VirtualAddress);
	printf("\tResource Directory Size:\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[2].Size);
	printf("\tException Directory RVA:\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[3].VirtualAddress);
	printf("\tException Directory Size:\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[3].Size);
	printf("\tSecurity Directory RVA:\t\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[4].VirtualAddress);
	printf("\tSecurity Directory Size:\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[4].Size);
	printf("\tRelocation Directory RVA:\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[5].VirtualAddress);
	printf("\tRelocation Directory Size:\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[5].Size);
	printf("\tDebug Directory RVA:\t\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[6].VirtualAddress);
	printf("\tDebug Directory Size:\t\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[6].Size);
	printf("\tArchitecture Directory RVA:\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[7].VirtualAddress);
	printf("\tArchitecture Directory Size:\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[7].Size);
	printf("\tReserved Directory RVA:\t\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[8].VirtualAddress);
	printf("\tReserved Directory Size:\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[8].Size);
	printf("\tTLS Directory RVA:\t\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[9].VirtualAddress);
	printf("\tTLS Directory Size:\t\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[9].Size);
	printf("\tConfiguration Directory RVA:\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[10].VirtualAddress);
	printf("\tConfiguration Directory Size:\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[10].Size);
	printf("\tBound Import Directory RVA:\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[11].VirtualAddress);
	printf("\tBound Import Directory Size:\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[11].Size);
	printf("\tImport Address Table Directory RVA:\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[12].VirtualAddress);
	printf("\tImport Address Table Directory Size:\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[12].Size);
	printf("\tDelay Import Directory RVA:\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[13].VirtualAddress);
	printf("\tDelay Import Directory Size:\t\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[13].Size);
	printf("\t.NET MetaData Directory Directory RVA:\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[14].VirtualAddress);
	printf("\t.NET MetaData Directory Directory Size:\t%08hX\n", imageNTHeaders->OptionalHeader.DataDirectory[14].Size);

	/**
	*/

	// SECTION_HEADERS
	puts("\n- SECTION HEADERS");
	// get offset to first section headeer
	DWORD sectionLocation = (DWORD)imageNTHeaders + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)imageNTHeaders->FileHeader.SizeOfOptionalHeader;
	DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);

	// get offset to the import directory RVA
	DWORD importDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	// print section data
	int i;
	for (i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
		sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
		printf("\t%s\n", sectionHeader->Name);
		printf("\t\t%08hX\tVirtual Size\n", sectionHeader->Misc.VirtualSize);
		printf("\t\t%08hX\tVirtual Address\n", sectionHeader->VirtualAddress);
		printf("\t\t%08hX\tSize Of Raw Data\n", sectionHeader->SizeOfRawData);
		printf("\t\t%08hX\tPointer To Raw Data\n", sectionHeader->PointerToRawData);
		printf("\t\t%08hX\tPointer To Relocations\n", sectionHeader->PointerToRelocations);
		printf("\t\t%08hX\tPointer To Line Numbers\n", sectionHeader->PointerToLinenumbers);
		printf("\t\t%08hX\tNumber Of Relocations\n", sectionHeader->NumberOfRelocations);
		printf("\t\t%08hX\tNumber Of Line Numbers\n", sectionHeader->NumberOfLinenumbers);
		printf("\t\t%08hX\tCharacteristics\n", sectionHeader->Characteristics);

		// save section that contains import directory table
		if (importDirectoryRVA >= sectionHeader->VirtualAddress && importDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
			importSection = sectionHeader;
		}
		sectionLocation += sectionSize;
	}

	// get file offset to import table
	rawOffset = (DWORD)fileData + importSection->PointerToRawData;

	// get pointer to import descriptor's file offset. Note that the formula for calculating file offset is: imageBaseAddress + pointerToRawDataOfTheSectionContainingRVAofInterest + (RVAofInterest - SectionContainingRVAofInterest.VirtualAddress)
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(rawOffset + (imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - importSection->VirtualAddress));

	puts("\n- DLL IMPORTS\n");
	for (; importDescriptor->Name != 0; importDescriptor++) {
		// imported dll modules
		printf("\t%s\n", rawOffset + (importDescriptor->Name - importSection->VirtualAddress));
		thunk = importDescriptor->OriginalFirstThunk == 0 ? importDescriptor->FirstThunk : importDescriptor->OriginalFirstThunk;
		thunkData = (PIMAGE_THUNK_DATA)(rawOffset + (thunk - importSection->VirtualAddress));

		// dll exported functions
		for (; thunkData->u1.AddressOfData != 0; thunkData++) {
			//a cheap and probably non-reliable way of checking if the function is imported via its ordinal number Â¯\_(ãƒ„)_/Â¯
			if (thunkData->u1.AddressOfData > 0x80000000) {
				//show lower bits of the value to get the ordinal Â¯\_(ãƒ„)_/Â¯
				printf("\t\tOrdinal: %08hX\n", (WORD)thunkData->u1.AddressOfData);
			}
			else {
				printf("\t\t%s\n", (rawOffset + (thunkData->u1.AddressOfData - importSection->VirtualAddress + 2)));
			}
		}
	}

	return 0;
}
