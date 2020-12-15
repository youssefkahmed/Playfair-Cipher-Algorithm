
INCLUDE Irvine32.inc
.DATA
KeyStr BYTE 1000 dup(?), 0
StrCount DWORD 0

Plaintext BYTE 1000 dup(?), 0
PTCount DWORD 0

EncryptedText BYTE 1000 dup(?), 0
ETCount DWORD 0

CipherTable DWORD 5 dup('x')
            DWORD 5 dup('x')
		    DWORD 5 dup('x')
            DWORD 5 dup('x')
			DWORD 5 dup('x')

row DWORD 0

col DWORD 0

currentLetter BYTE 'a'

DuplicateCounter DWORD 0

IndexHolder DWORD -1

LetterHolder DWORD ?

colIndex BYTE 2 dup(?) 
rowIndex BYTE 2 dup(?)

iterator BYTE 0

.code
main PROC

   mov edx, OFFSET KeyStr
   mov ecx, LENGTHOF KeyStr

   CALL readString

   mov StrCount, eax

   CALL GenerateTable

   CALL CRLF

   CALL OutputTable

   CALL CRLF

   mov edx, OFFSET Plaintext
   mov ecx, LENGTHOF Plaintext

   CALL readString

   mov PTCount, eax

   CALL ToLowercase

  CALL CRLF

  CALL Decrypt
   


	exit
main ENDP


;
;
; Generating the Playfair cipher table

GenerateTable PROC
mov ecx, 5
mov esi, 0
mov edi, StrCount

OuterLoop:
mov ebx, ecx
mov ecx, 5

InnerLoop:
mov eax, row
mov edx, 5
MUL edx
add eax, col
mov edx, 4
MUL edx

CMP edi, 0
JZ ResetESI
movzx edx, KeyStr[esi]
mov LetterHolder, edx
PUSH eax
mov eax, StrCount
mov DuplicateCounter, eax
POP eax
sub DuplicateCounter, edi
CMP DuplicateCounter, 0
JZ AddLetter

PUSH ebx

CheckDuplicate:
POP ebx
inc IndexHolder
mov edx, IndexHolder
CMP edx, DuplicateCounter
JZ AddLetter
PUSH eax
mov eax, IndexHolder
mov dl, KeyStr[eax]
POP eax
PUSH ebx
mov ebx, DuplicateCounter
CMP dl, KeyStr[ebx]
JNZ CheckDuplicate
POP ebx
inc esi
dec edi
JMP InnerLoop

AddLetter:
mov edx, LetterHolder
CMP edx, ' '
JZ SkipSpace
OR edx, 00100000b
mov CipherTable[eax], edx
JMP nxt

SkipSpace:
dec col
inc ecx
nxt:
dec edi
inc esi
mov IndexHolder, -1
JMP Rest

ResetESI:
mov esi, -1

CheckLoop:
inc esi
CMP esi, StrCount
JZ Next
mov dl, KeyStr[esi]
CMP currentLetter, dl
JNZ CheckLoop
inc currentLetter
JMP ResetESI

Next:
CMP currentLetter, 'j'
JNZ contNext
inc currentLetter
JMP ResetESI
contNext:
mov dl, currentLetter
mov CipherTable[eax], edx
inc currentLetter

Rest:
inc col
dec ecx
JNZ InnerLoop

inc row
mov col, 0
mov ecx, ebx
dec ecx
jnz OuterLoop

ret
GenerateTable ENDP



;
;
; Extra procedure to check if the table was generated correctly

OutputTable PROC

mov ecx, 5
mov esi, 0
mov row, 0
mov col, 0

L1:
mov ebx, ecx
mov ecx, 5

L2:
mov eax, row
mov edx, 5
MUL edx
add eax, col
mov edx, 4
MUL edx

mov edx, CipherTable[eax]
mov eax, edx

call writeChar

inc col
Loop L2

CALL CRLF
inc row
mov col, 0
mov ecx, ebx
Loop L1

ret
OutputTable ENDP




;
;
;
; Convert all letters of the plaintext to lowercase


ToLowercase PROC
mov esi, 0
mov ecx, PTCount

ConvertLoop:
OR Plaintext[esi], 00100000b
CMP plaintext[esi], 'j'
JNZ continue
mov plaintext[esi], 'i'
continue:
inc esi
Loop ConvertLoop

ret
ToLowercase ENDP



;
;
; Encrypting the plaintext

Encrypt PROC

mov edx, 0
mov eax, PTCount
mov ebx, 2
DIV ebx
ADD eax, edx

mov ecx, eax
mov esi, 0

CMP edx, 0
JZ MajorLoop
mov edx, PTCount
mov plaintext[edx], 'z'


MajorLoop:
mov edi, 0
mov iterator, cl
mov ecx, 2

MinorLoop:
PUSH ecx
mov ecx, 5
mov row, 0
mov col, 0

TableLoop1:
mov ebx, ecx
mov ecx, 5

TableLoop2:
mov eax, row
mov edx, 5
MUL edx
add eax, col
mov edx, 4
MUL edx

mov edx, CipherTable[eax]
CMP plaintext[esi], dl
JNZ NotFound

inc esi
mov ecx, 5
mov edx, col
mov colIndex[edi], dl
mov edx, row
mov rowIndex[edi], dl
inc edi
JMP GoOn


NotFound:
inc col
Loop TableLoop2

inc row
mov col, 0
mov ecx, ebx
Loop TableLoop1

GoOn:
POP ecx
DEC ecx
JNZ MinorLoop

dec edi

mov bl, colIndex[edi-1]
CMP bl, colIndex[edi]
JNZ SecondCondition
movzx eax, rowIndex[edi-1]
inc eax
CMP eax, 4
JBE Row_Condition1
mov eax, 0
Row_Condition1:
mov edx, 5
MUL edx
add eax, ebx
mov edx, 4
MUL edx

mov edx, CipherTable[eax]
mov plaintext[esi-2], dl


movzx eax, rowIndex[edi]
inc eax
CMP eax, 4
JBE Row_Condition2
mov eax, 0
Row_Condition2:
mov edx, 5
MUL edx
add eax, ebx
mov edx, 4
MUL edx

mov edx, CipherTable[eax]
mov plaintext[esi-1], dl
JMP FinalStep




SecondCondition:
mov bl, rowIndex[edi-1]
CMP bl, rowIndex[edi]
JNZ ThirdCondition
mov eax, ebx
mov edx, 5
MUL edx
mov dl, colIndex[edi-1]
inc dl
CMP dl, 4
JBE Col_Condition1
mov dl, 0
Col_Condition1:
add eax, edx
mov edx, 4
MUL edx

mov edx, CipherTable[eax]
mov plaintext[esi-2], dl


mov eax, ebx
mov edx, 5
MUL edx
mov dl, colIndex[edi]
inc dl
CMP dl, 4
JBE Col_Condition2
mov dl, 0
Col_Condition2:
add eax, edx
mov edx, 4
MUL edx

mov edx, CipherTable[eax]
mov plaintext[esi-1], dl
JMP FinalStep




ThirdCondition:
movzx ebx, colIndex[edi-1]
CMP bl, colIndex[edi]
JA ThirdCondition_2
mov bl, colIndex[edi]
sub bl, colIndex[edi-1]

movzx eax, rowIndex[edi-1]
mov edx, 5
MUL edx
mov dl, colIndex[edi-1]
add dl, bl
add eax, edx
mov edx, 4
MUL edx

mov edx, CipherTable[eax]
mov plaintext[esi-2], dl

movzx eax, rowIndex[edi]
mov edx, 5
MUL edx
mov dl, colIndex[edi]
sub dl, bl
add eax, edx
mov edx, 4
MUL edx

mov edx, CipherTable[eax]
mov plaintext[esi-1], dl
JMP FinalStep


ThirdCondition_2:
sub bl, colIndex[edi]

movzx eax, rowIndex[edi-1]
mov edx, 5
MUL edx
mov dl, colIndex[edi-1]
sub dl, bl
add eax, edx
mov edx, 4
MUL edx

mov edx, CipherTable[eax]
mov plaintext[esi-2], dl

movzx eax, rowIndex[edi]
mov edx, 5
MUL edx
mov dl, colIndex[edi]
add dl, bl
add eax, edx
mov edx, 4
MUL edx

mov edx, CipherTable[eax]
mov plaintext[esi-1], dl
JMP FinalStep


FinalStep:
movzx ecx, iterator
DEC ecx
JNZ MajorLoop


mov edx, OFFSET plaintext
CALL writeString

ret
Encrypt ENDP






;
;
;
;
;
; Decryption Proc



Decrypt PROC

mov edx, 0
mov eax, PTCount
mov ebx, 2
DIV ebx
ADD eax, edx

mov ecx, eax
mov esi, 0

D_MajorLoop:
mov edi, 0
mov iterator, cl
mov ecx, 2

D_MinorLoop:
PUSH ecx
mov ecx, 5
mov row, 0
mov col, 0

D_TableLoop1:
mov ebx, ecx
mov ecx, 5

D_TableLoop2:
mov eax, row
mov edx, 5
MUL edx
add eax, col
mov edx, 4
MUL edx

mov edx, CipherTable[eax]
CMP plaintext[esi], dl
JNZ D_NotFound

inc esi
mov ecx, 5
mov edx, col
mov colIndex[edi], dl
mov edx, row
mov rowIndex[edi], dl
inc edi
JMP D_GoOn


D_NotFound:
inc col
Loop D_TableLoop2

inc row
mov col, 0
mov ecx, ebx
Loop D_TableLoop1

D_GoOn:
POP ecx
DEC ecx
JNZ D_MinorLoop

dec edi

mov bl, colIndex[edi-1]
CMP bl, colIndex[edi]
JNZ D_SecondCondition
movzx eax, rowIndex[edi-1]
dec eax
CMP eax, 4
JBE D_Row_Condition1
mov eax, 0
D_Row_Condition1:
mov edx, 5
MUL edx
add eax, ebx
mov edx, 4
MUL edx

mov edx, CipherTable[eax]
mov plaintext[esi-2], dl


movzx eax, rowIndex[edi]
dec eax
CMP eax, 4
JBE D_Row_Condition2
mov eax, 4
D_Row_Condition2:
mov edx, 5
MUL edx
add eax, ebx
mov edx, 4
MUL edx

mov edx, CipherTable[eax]
mov plaintext[esi-1], dl
JMP D_FinalStep




D_SecondCondition:
mov bl, rowIndex[edi-1]
CMP bl, rowIndex[edi]
JNZ D_ThirdCondition
mov eax, ebx
mov edx, 5
MUL edx
mov dl, colIndex[edi-1]
dec dl
CMP dl, 4
JBE D_Col_Condition1
mov dl, 4
D_Col_Condition1:
add eax, edx
mov edx, 4
MUL edx

mov edx, CipherTable[eax]
mov plaintext[esi-2], dl


mov eax, ebx
mov edx, 5
MUL edx
mov dl, colIndex[edi]
dec dl
CMP dl, 4
JBE D_Col_Condition2
mov dl, 4
D_Col_Condition2:
add eax, edx
mov edx, 4
MUL edx

mov edx, CipherTable[eax]
mov plaintext[esi-1], dl
JMP D_FinalStep




D_ThirdCondition:
movzx ebx, colIndex[edi-1]
CMP bl, colIndex[edi]
JA D_ThirdCondition_2
mov bl, colIndex[edi]
sub bl, colIndex[edi-1]

movzx eax, rowIndex[edi-1]
mov edx, 5
MUL edx
mov dl, colIndex[edi-1]
add dl, bl
add eax, edx
mov edx, 4
MUL edx

mov edx, CipherTable[eax]
mov plaintext[esi-2], dl

movzx eax, rowIndex[edi]
mov edx, 5
MUL edx
mov dl, colIndex[edi]
sub dl, bl
add eax, edx
mov edx, 4
MUL edx

mov edx, CipherTable[eax]
mov plaintext[esi-1], dl
JMP D_FinalStep


D_ThirdCondition_2:
sub bl, colIndex[edi]

movzx eax, rowIndex[edi-1]
mov edx, 5
MUL edx
mov dl, colIndex[edi-1]
sub dl, bl
add eax, edx
mov edx, 4
MUL edx

mov edx, CipherTable[eax]
mov plaintext[esi-2], dl

movzx eax, rowIndex[edi]
mov edx, 5
MUL edx
mov dl, colIndex[edi]
add dl, bl
add eax, edx
mov edx, 4
MUL edx

mov edx, CipherTable[eax]
mov plaintext[esi-1], dl
JMP D_FinalStep


D_FinalStep:
movzx ecx, iterator
DEC ecx
JNZ D_MajorLoop


mov edx, OFFSET plaintext
CALL writeString


ret
Decrypt ENDP

END main