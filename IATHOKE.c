#undef _WIN64
#define _WIN32

#include<stdio.h>
#include<Windows.h>

#ifdef _WIN32
typedef IMAGE_THUNK_DATA INT_ENTRY, *PINT_ENTRY;
typedef DWORD *PIAT_ENTRY;
#endif

DWORD baseAddr;


int
WINAPI
HOOK_MessageBoxW(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCWSTR lpText,
        _In_opt_ LPCWSTR lpCaption,
        _In_ UINT uType) {
    return MessageBoxA(hWnd, "fake", "fake", MB_OK);
};

HMODULE getmodule(char *name) {
    HMODULE module = GetModuleHandleA(name);
    baseAddr = (DWORD) module;
    return module;
};

PIMAGE_DOS_HEADER getPIMAGE_DOS_HEADER(HMODULE hmodule) {
    return (PIMAGE_DOS_HEADER) hmodule;
};

PIMAGE_NT_HEADERS getPIMAGE_NT_HEADERS(PIMAGE_DOS_HEADER dosHeader) {

    return (PIMAGE_NT_HEADERS) (dosHeader->e_lfanew + baseAddr);
}

PIMAGE_OPTIONAL_HEADER getPIMAGE_OPTIONAL_HEADER(PIMAGE_NT_HEADERS ntHeaders) {
    return (PIMAGE_OPTIONAL_HEADER) &(ntHeaders->OptionalHeader);
}

IMAGE_DATA_DIRECTORY *getIMAGE_DATA_DIRECTORY(PIMAGE_OPTIONAL_HEADER optionalHeader) {
    return optionalHeader->DataDirectory;
}

IMAGE_IMPORT_DESCRIPTOR *getIMAGE_IMPORT_DESCRIPTOR(IMAGE_DATA_DIRECTORY *dataDirectory) {
    return (IMAGE_IMPORT_DESCRIPTOR *) ((DWORD) (dataDirectory[1].VirtualAddress) + baseAddr);
}

IMAGE_IMPORT_DESCRIPTOR *findIMAGE_IMPORT_DESCRIPTOR_BY_NAME(IMAGE_IMPORT_DESCRIPTOR *importDescriptor, char *dllname) {
    DWORD oldprotect;
    while (importDescriptor->Name != 0) {
//        VirtualProtect((LPVOID)importDescriptor->Name,16,PAGE_EXECUTE_READWRITE,&oldprotect);
        char *descriptorName = ((char *) importDescriptor->Name) + baseAddr;
//        VirtualProtect((LPVOID)importDescriptor->Name,16,oldprotect,NULL);
        if (strcmp(descriptorName, dllname) == 0) {
            printf("success\n");
            return importDescriptor;
        }
        importDescriptor++;
    }
    fprintf(stderr, "not find dll %s\n", dllname);
    exit(1);
}

PINT_ENTRY getPINT_ENTRY_BY_IMAGE_IMPORT_DESCRIPTOR(IMAGE_IMPORT_DESCRIPTOR *importDescriptor) {
    return (PINT_ENTRY) (importDescriptor->OriginalFirstThunk + baseAddr);
}

PIAT_ENTRY getPIAT_ENTRY_BY_IMAGE_IMPORT_DESCRIPTOR(IMAGE_IMPORT_DESCRIPTOR *importDescriptor) {
    return (PIAT_ENTRY) (importDescriptor->FirstThunk + baseAddr);
}

char *getName_BY_PINT_ENTRY(PINT_ENTRY pintEntry) {
    return ((IMAGE_IMPORT_BY_NAME *) ((pintEntry->u1.Function)+baseAddr))->Name;
}

PIAT_ENTRY getHOOK_PIAT_ENTRY_AND_FUCNAME(PINT_ENTRY pintEntry, PIAT_ENTRY piatEntry, char *funcname) {
    while ((DWORD) (pintEntry->u1.Function) != 0 && ((*piatEntry) != 0)) {
        if (strcmp(getName_BY_PINT_ENTRY(pintEntry), funcname) == 0) {
            return piatEntry;
        }
        pintEntry++;
        piatEntry++;
    }
}

void INSTALL_HOOK(PIAT_ENTRY HOOK_PIAT_ENTRY, DWORD source, DWORD target) {
    DWORD oldprotoct;
    VirtualProtect((void *) HOOK_PIAT_ENTRY, 4, PAGE_EXECUTE_READWRITE, &oldprotoct);
    memcpy((void *) HOOK_PIAT_ENTRY, &target, 4);
    VirtualProtect((void *) HOOK_PIAT_ENTRY, 4, oldprotoct, NULL);
}


int main() {

    HMODULE module = getmodule(NULL);

    PIMAGE_DOS_HEADER dosHeader = getPIMAGE_DOS_HEADER(module);

    PIMAGE_NT_HEADERS ntHeaders = getPIMAGE_NT_HEADERS(dosHeader);

    PIMAGE_OPTIONAL_HEADER optionalHeader = getPIMAGE_OPTIONAL_HEADER(ntHeaders);

    IMAGE_DATA_DIRECTORY *imageDataDirectory = getIMAGE_DATA_DIRECTORY(optionalHeader);

    IMAGE_IMPORT_DESCRIPTOR *importDescriptor = getIMAGE_IMPORT_DESCRIPTOR(imageDataDirectory);

    importDescriptor = findIMAGE_IMPORT_DESCRIPTOR_BY_NAME(importDescriptor, "USER32.dll");

    PIAT_ENTRY piatEntry = getPIAT_ENTRY_BY_IMAGE_IMPORT_DESCRIPTOR(importDescriptor);

    PINT_ENTRY pintEntry = getPINT_ENTRY_BY_IMAGE_IMPORT_DESCRIPTOR(importDescriptor);

    pintEntry = getHOOK_PIAT_ENTRY_AND_FUCNAME(pintEntry, piatEntry, "MessageBoxW");

    INSTALL_HOOK(pintEntry, (DWORD) MessageBoxW, (DWORD) HOOK_MessageBoxW);

    MessageBoxW(NULL, L"hello world", L"hello", MB_OK);

    return 0;
}

