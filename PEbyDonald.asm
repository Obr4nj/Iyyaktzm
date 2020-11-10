INCLUDE \masm32\include\masm32rt.inc
;--------------------------------------------------------------------------------
.DATA
	dosHeader              IMAGE_DOS_HEADER <>
	ntHeader               IMAGE_NT_HEADERS <>
	BUFFER_MAX             =    4
	crlf                   db   13,10,0
	crlf2                  db   13,10,13,10,0
	ox					   db	"0x",0
	tox					   db	9,"0x",0
	ttox			       db   9,9,"0x",0
	tab                    db   9,0
	FileName               db   MAX_PATH   dup(?)
	welcome                db   "!!! PE Parser !!!",10,13,10,0
	; read file and check if is valid
	fnameString            db   "Enter File (Name/Path): ",0
	openfileString         db   13,10,"Opening File...",13,10,0
	readSuccessString      db   "File Successiful read!",13,10,0
	validHeaderString      db   13,10,13,10,"NT Header ",13,10,0
	validSignature		   db   9,"Signature:",9,9,"0x",0
	writeSuccessString     db   13,10,13,10,"File successiful saved",13,10,0
	; Sections
	sectionshow		       db   13,10,13,10,"------------- Section Table -------------",0
	sectionNameString      db   13,10,0
	virtualSizeString      db   13,10,9,"Virtual Size:",9,9,"0x",0
	virtualAddrString      db   13,10,9,"Virtual Address:",9,"0x",0
	sizeRawDataString      db   13,10,9,"Size Of Raw Data:",9,"0x",0
	ptrRawDataString       db   13,10,9,"Pointer To Raw Data:",9,"0x",0
	charactString          db   13,10,9,"Characteristics:",9,"0x",0
	; Import Directory
	importTableString      db   13,10,13,10,"------------- Import Directory -------------",13,10,0
	; Error messages
	createError            db   "Cannot open the file.",13,10,0
	allocError             db   "Cannot allocate the memory.",13,10,0
	readError              db   "Cannon read the file.",13,10,0
	invalidDosHeader       db   "Invalid DOS Header.",13,10,0
	invalidNtHeader        db   "Invalid NT Header.",13,10,0
	writeErrorString       db   "Write Error",0
	importTableErrorString db   "IT doesn't exist",13,10,0
	ordinalString          db   "Imported by Ordinal: 0x",0
	closeFailed            db   "Close failed",13,10,0
; BSS Section
.DATA?
	BaseAddress            dd            ?
	hFile                  DWORD         ?
	FileSize               DWORD         ?
	BR                     DWORD         ?
	buffer1                db   9    dup(?)
	buffer2                db   40   dup(?)
	buffer                 db   4    dup(?)
	choice                 db   4    dup(?)
	sectionName            db   20   dup(?)
	sectionSizeS           db   100  dup(?)
	importName             db            ?
	sectionSize            dw            ?
	nameSize               dd            ?
	numberOfSections       dw            ?
;---------------------------------------------------------------------------------
.CODE
start:
	call main
	push    0
	call    ExitProcess

main PROC
	push    offset welcome
	call    StdOut
	call    loadFile
	cmp     eax,0         ; 0 = load failed --> exit program
	jne     quit_main
	call    readNTHeader
	cmp     eax, 0        ; 0 = DOS header doesn't exist --> exit program
	jne     quit_main
	print	offset sectionshow
	call    readSectionTable
	call    readImportDescriptor
quit_main:
	ret
main ENDP
; Read Dos Header
loadFile  PROC
	print    offset fnameString
	; Read file name
	push    MAX_PATH
	push    offset FileName
	call    StdIn
	print   offset openfileString
	; Create file (Open file and get HANDLE)
	invoke  CreateFile, addr FileName, GENERIC_READ or GENERIC_WRITE ,FILE_SHARE_READ OR FILE_SHARE_WRITE,0, OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	mov     hFile, eax
	cmp     hFile,INVALID_HANDLE_VALUE
	jne     createSuccess
	print   offset createError
	mov     eax, 1
	ret
createSuccess:
	invoke  GetFileSize,hFile,0
	mov     FileSize,eax
	invoke  GetProcessHeap
	invoke  HeapAlloc, eax, HEAP_NO_SERIALIZE + HEAP_ZERO_MEMORY, FileSize
	mov     BaseAddress, eax
	cmp     BaseAddress, NULL
	jne     allocSuccess
	print   offset allocError
	mov     eax, 1
	ret
  ; Memory allocation successiful. Now we can read...
allocSuccess:
	invoke  ReadFile, hFile, BaseAddress, FileSize, addr BR,0
	cmp     eax, 0
	jne     readSuccess
	print   offset readError
	mov     eax, 1
readSuccess:
	print   offset readSuccessString
	mov     eax, 0
	ret
loadFile ENDP
; End load file

; Magic number, NT header
readNTHeader  PROC
	; same as C:
	; BYTE             *BaseAddress;
	; IMAGE_DOS_HEADER *dosHeader;
	; ..... (allocation memory for BaseAddress) ....
	; dosHeader = (IMAGE_DOS_HEADER *) BaseAddress;
	invoke  RtlMoveMemory, ADDR dosHeader, BaseAddress, SIZEOF dosHeader
	cmp     dosHeader.e_magic, IMAGE_DOS_SIGNATURE ; MZ ?
	je      valid_PE
	print   offset invalidDosHeader
	mov     eax, 1
	ret
valid_PE:
	print   offset validHeaderString
	print   offset validSignature
	invoke  RtlZeroMemory,addr buffer,BUFFER_MAX
	invoke  dw2hex,dosHeader.e_lfanew,addr buffer
	print   offset buffer
	mov     eax, BaseAddress
	add     eax, [dosHeader.e_lfanew]
	invoke  RtlMoveMemory, ADDR ntHeader, eax, SIZEOF ntHeader
	cmp     ntHeader.Signature, IMAGE_NT_SIGNATURE   ; PE ?
	je      valid_nt_header
	print   offset invalidNtHeader
	mov     eax, 1
valid_nt_header:
	print   offset tox
	invoke  dw2hex,ntHeader.Signature,addr buffer
	print	offset buffer; Value
	mov     eax, 0
	ret
readNTHeader   ENDP

; Image Section Header
readSectionTable   PROC uses esi
	xor     ebx, ebx
	xor     esi, esi
	call    findNTHeader
	assume  esi:ptr IMAGE_FILE_HEADER
	xor     ecx, ecx
	mov     cx, [esi].NumberOfSections
	movzx   ecx, cx
	call    findSectionHeader ; ...and store it's address in ESI register
	assume  esi:ptr IMAGE_SECTION_HEADER
	; Print sections
show_sections:
	cmp     ecx, 0
	je      exit_show
	; Push ecx because lstrcpyn don't use
	; register preservation...
	push    ecx
	push    offset sectionNameString
	call    StdOut
	invoke  RtlZeroMemory,addr buffer1,9
	invoke  lstrcpyn,addr buffer1,addr [esi].Name1,8
	print   offset buffer1
	push    offset virtualSizeString
	call    StdOut
	invoke  RtlZeroMemory,addr buffer,BUFFER_MAX
	invoke  dw2hex, [esi].Misc.VirtualSize, addr buffer
	print   offset  buffer
	push    offset virtualAddrString
	call    StdOut
	invoke  RtlZeroMemory,addr buffer,BUFFER_MAX
	invoke  dw2hex, [esi].VirtualAddress, addr buffer
	print   offset buffer
	push    offset sizeRawDataString
	call    StdOut
	invoke  RtlZeroMemory,addr buffer,BUFFER_MAX
	invoke  dw2hex, [esi].SizeOfRawData, addr buffer
	print   offset buffer
	push    offset ptrRawDataString
	call    StdOut
	invoke  RtlZeroMemory,addr buffer,BUFFER_MAX
	invoke  dw2hex, [esi].PointerToRawData, addr buffer
	print   offset buffer
	push    offset charactString
	call    StdOut
	invoke  RtlZeroMemory,addr buffer,BUFFER_MAX
	invoke  dw2hex, [esi].Characteristics, addr buffer
	print   offset buffer
	pop     ecx ; get the previously pushed value
	dec     ecx
	add     esi, 28h
	jmp     show_sections
exit_show:
	ret
readSectionTable  ENDP ; End Image Section Header

; Print Import Table information
readImportDescriptor  PROC uses esi edi
	LOCAL   nameLen:DWORD
	call    findNTHeader
	add     esi, 14h
	assume  esi:ptr IMAGE_OPTIONAL_HEADER
	; Get Import Table address into DataDirectory array
	; sizeof IMAGE_DATA_DIRECTORY = 2nd member of the array -> Import Table (VirtualAddress) 
	mov     edx,[esi].DataDirectory[sizeof IMAGE_DATA_DIRECTORY].VirtualAddress
	; EDX = RVA of the IT
	call    RVAToOffset
	cmp     edx, 0
	jne     continue_read_import ; if valid, read import
	push    offset importTableErrorString
	call    StdOut
	mov     eax, 0
	ret
	; Read IMAGE_IMPORT_DESCRIPTOR
	; each member is a DLL import
continue_read_import:
	mov     esi, edx
	add     esi, BaseAddress
	assume  esi:ptr IMAGE_IMPORT_DESCRIPTOR
	push    offset importTableString
	call    StdOut
while_descriptors:
	; IMAGE_THUNK_DATA (basicly the RVA) 
	; contains pointer to
	; an IMAGE_IMPORT_BY_NAME
	cmp     [esi].FirstThunk, 0
	je      exit_descriptors_while
	; Name of the module
	mov     edx, [esi].Name1
	push    esi
	call    findNTHeader
	add     esi, 14h
	assume  esi:ptr IMAGE_OPTIONAL_HEADER
	call    RVAToOffset
	add     edx, BaseAddress
	; register preservation
	; RtlZeroMemory change the value of EDX
	push    edx
	invoke  RtlZeroMemory,addr buffer,20
	;print	offset crlf
	pop     edx
	; restore the previously pushed value
	invoke  lstrcpyn,addr buffer, edx,19
	print   offset buffer
	push    offset crlf
	call    StdOut
	pop     esi
	assume  esi:ptr IMAGE_IMPORT_DESCRIPTOR
	; select correct array
	mov     edx, [esi].OriginalFirstThunk
	cmp     [esi].OriginalFirstThunk,0
	mov   edx, [esi].FirstThunk ;cmove
	push    esi
	; same as before; convert RVA into file offset
	call    RVAToOffset
	add     edx, BaseAddress
	mov     edi, edx
	assume  edi:ptr IMAGE_IMPORT_DESCRIPTOR
	; IMAGE_IMPORT_BY_NAME -> name of the functions
	; imported by modules  
functions:
	push    offset tab
	call    StdOut
	cmp     dword ptr[edi], 0
	jz      exit_descriptors_while
	; check if it is imported by name or ordinal
	test    dword ptr [edi],IMAGE_ORDINAL_FLAG32 
	jnz     importByOrdinal
	; ---- Imported by name block ----
	mov     edx, dword ptr [edi]
	push    edi
	call    RVAToOffset
	pop     edi
	add     edx, BaseAddress
	assume  edx:ptr IMAGE_IMPORT_BY_NAME
	push    edx
	invoke  RtlZeroMemory,addr buffer2,40
	pop     edx
	invoke  lstrcpyn,addr buffer2,addr [edx].Name1,39
	push    offset buffer2
	call    StdOut
	jmp     printText
	; --- imported by ordinal block -----
importByOrdinal:
	mov     edx, dword ptr [edi]
	and     edx, 0FFFFh
	push    edx
	push    offset ordinalString
	call    StdOut
	invoke  RtlZeroMemory,addr buffer,BUFFER_MAX
	pop     edx
	invoke  dw2hex, addr [edx], addr buffer
	print   offset buffer
printText:
	push    offset crlf
	call    StdOut
	add     edi, 4
	jmp     functions  ; read the next function
exit_descriptors_while:
	ret
readImportDescriptor  ENDP
; #########################################
; #          UTILITY PROCEDURES           #
; #########################################
; Find first IMAGE_SECTION_HEADER
findSectionHeader PROC
	mov     esi, BaseAddress
	add     esi, dosHeader.e_lfanew
	mov     bx, ntHeader.FileHeader.SizeOfOptionalHeader
	movzx   ebx, bx
	add     esi,ebx
	add     esi, 18h ; ESI -> block of sections
					; 18h -> Signature NT Header
	ret
findSectionHeader  ENDP
; Get Last Section (IMAGE_SECTION_HEADER)
; last section = the section inserted by user
findLastSection   PROC
	xor     ecx, ecx
	find_section:
	cmp     cx, numberOfSections
	je      exit_find
	add     edi, sizeof IMAGE_SECTION_HEADER
	inc     cx
	jmp     find_section
exit_find:
	ret
findLastSection   ENDP
; Memory location of NT Header
findNTHeader PROC
	xor     esi, esi
	mov     esi, BaseAddress
	add     esi, dosHeader.e_lfanew
	add     esi, 4h ; 4h = size of Signature
					; now ESI point to IMAGE_FILE_HEADER struct
  ret
findNTHeader ENDP
; FASTCALL:
; EAX = first parameter
; EDX = second parameter
Alignment   PROC
	mov     ecx, eax
calc:
	cmp     edx, ecx
	jle     exit_calc
	add     ecx, eax
	jmp     calc
exit_calc:
	ret
Alignment   ENDP
; Convert RVA address into File Offset
; return value in EDX
RVAToOffset   PROC uses eax edi esi
	LOCAL   limit:DWORD
	call    findSectionHeader
	mov     edi, esi
	pop     esi
	assume  edi:ptr IMAGE_SECTION_HEADER
	;EDI = first section
	cmp     edx, [edi].PointerToRawData
	jge     continue
	ret
continue:  
	push    ecx
	push    ebx
	xor     ecx, ecx
	mov     cx, ntHeader.FileHeader.NumberOfSections
	movzx   ecx, cx
while_sections:
	cmp     ecx, 0
	je      exit_while
	cmp     [edi].SizeOfRawData, 0
	jne     raw_data_0
	mov     eax, [edi].Misc.VirtualSize
	jmp     continue_else
raw_data_0:
	mov     eax, [edi].SizeOfRawData
continue_else:
	cmp     edx, [edi].VirtualAddress
	jge     control_and
	jmp     continue_while
control_and:
	add     eax, [edi].VirtualAddress
	cmp     edx, eax
	jl      another_control
	jmp     continue_while
another_control:
	cmp     [edi].PointerToRawData, 0
	je      return_value
	sub     edx, [edi].VirtualAddress
	add     edx, [edi].PointerToRawData
return_value:
	pop     ebx
	pop     ecx
	ret
continue_while:
	dec     ecx
	add     edi, sizeof IMAGE_SECTION_HEADER
	jmp     while_sections
exit_while:
	mov     edx, 0
	pop     ebx
	pop     ecx
	ret
RVAToOffset    ENDP
; -----------------------------------------------------;
END start