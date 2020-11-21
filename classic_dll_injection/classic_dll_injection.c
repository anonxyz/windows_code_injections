#include<windows.h>
#include<tlhelp32.h>
#include<stdio.h>
DWORD getprocessadd()
{
    HANDLE snapshot;
    snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    PROCESSENTRY32 pr;
    pr.dwSize=sizeof(PROCESSENTRY32);
    if(!Process32First(snapshot,&pr))
    {
        printf("error %d",GetLastError());
    }

    do
    {
      if(!strcmp(pr.szExeFile,"notepad.exe"))
      {
          printf("notepad running PID:-%d\n",pr.th32ProcessID);
         return pr.th32ProcessID;
      }
    }
    while(Process32Next(snapshot,&pr));
}


int main()
{
    DWORD pid=getprocessadd();//get the process id of the process to inject into(here notepad.exe)
    const char *dllname="C:\\Users\\HP\\Desktop\\project_banking\\test.dll"; //this is the absolute path for dll to inject
    size_t dllnamesize=strlen(dllname);
    HANDLE openproc=OpenProcess(PROCESS_ALL_ACCESS,TRUE,pid); //calling the open process to get a handle on notepad process.
    if(openproc==NULL)
    {
        printf("process not open because %d\n",GetLastError());
    }
    LPVOID lpbaseaddress=VirtualAllocEx(openproc,NULL,dllnamesize,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE); //allocate memory in the virtual address space of notepad.exe process
    if(lpbaseaddress==NULL)
    {
        printf("VIRTUAL ALLOC EX EROOR %d\n",GetLastError());
    }
    else
    {
        printf("%x\n",lpbaseaddress);
    }
    if(WriteProcessMemory(openproc,lpbaseaddress,dllname,dllnamesize,NULL)==0) //write the dllname into the base address of virtual address space of notepad.exe memory
    {
        printf("WRITE PROCESS MEMORY ERROR %d\n",GetLastError());
    }

    HMODULE mod=GetModuleHandle("kernel32.dll");   //obtain the function address of loadlibrary inside kernal32.dll in order to call the function in context of another process
    LPVOID startaddress=GetProcAddress(mod,"LoadLibraryA");
    HANDLE hthread=CreateRemoteThread(openproc,NULL,0,(LPTHREAD_START_ROUTINE)startaddress,lpbaseaddress,0,NULL); //execute the loadlibrary in the context of notepad process and passing it the base address which is the full dll pathname
    if(hthread)
    {
        printf("injection successfull"); //the loadlibrary executes the dll main of the function
    }
    else
    {
        printf("CREATE REMOTE THREAD ERROR %d\n",GetLastError());
    }

}
