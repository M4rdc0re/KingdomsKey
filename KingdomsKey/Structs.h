#pragma once
#include <Windows.h>

typedef struct _UNICODE_STRING {
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;
} USTRING;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING, * PUNICODE_STR;

typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBase;
	PPEB_LDR_DATA           LoaderData;
	PVOID                   ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PVOID                   FastPebLockRoutine;
	PVOID                   FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PVOID                   FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, * PPEB;

typedef struct __CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
	ULONG Flags;
	PCHAR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
	ULONG Flags;
	struct _TEB_ACTIVE_FRAME* Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct _GDI_TEB_BATCH {
	ULONG Offset;
	ULONG HDC;
	ULONG Buffer[310];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef PVOID PACTIVATION_CONTEXT;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
	struct __RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
	PACTIVATION_CONTEXT ActivationContext;
	ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK {
	PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
	LIST_ENTRY FrameListCache;
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _TEB {
	NT_TIB				NtTib;
	PVOID				EnvironmentPointer;
	CLIENT_ID			ClientId;
	PVOID				ActiveRpcHandle;
	PVOID				ThreadLocalStoragePointer;
	PPEB				ProcessEnvironmentBlock;
	ULONG               LastErrorValue;
	ULONG               CountOfOwnedCriticalSections;
	PVOID				CsrClientThread;
	PVOID				Win32ThreadInfo;
	ULONG               User32Reserved[26];
	ULONG               UserReserved[5];
	PVOID				WOW32Reserved;
	LCID                CurrentLocale;
	ULONG               FpSoftwareStatusRegister;
	PVOID				SystemReserved1[54];
	LONG                ExceptionCode;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;
	UCHAR                  SpareBytes1[0x30 - 3 * sizeof(PVOID)];
	ULONG                  TxFsContext;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
	UCHAR                  SpareBytes1[0x34 - 3 * sizeof(PVOID)];
#else
	ACTIVATION_CONTEXT_STACK ActivationContextStack;
	UCHAR                  SpareBytes1[24];
#endif
	GDI_TEB_BATCH			GdiTebBatch;
	CLIENT_ID				RealClientId;
	PVOID					GdiCachedProcessHandle;
	ULONG                   GdiClientPID;
	ULONG                   GdiClientTID;
	PVOID					GdiThreadLocalInfo;
	PSIZE_T					Win32ClientInfo[62];
	PVOID					glDispatchTable[233];
	PSIZE_T					glReserved1[29];
	PVOID					glReserved2;
	PVOID					glSectionInfo;
	PVOID					glSection;
	PVOID					glTable;
	PVOID					glCurrentRC;
	PVOID					glContext;
	NTSTATUS                LastStatusValue;
	UNICODE_STRING			StaticUnicodeString;
	WCHAR                   StaticUnicodeBuffer[261];
	PVOID					DeallocationStack;
	PVOID					TlsSlots[64];
	LIST_ENTRY				TlsLinks;
	PVOID					Vdm;
	PVOID					ReservedForNtRpc;
	PVOID					DbgSsReserved[2];
#if (NTDDI_VERSION >= NTDDI_WS03)
	ULONG                   HardErrorMode;
#else
	ULONG                  HardErrorsAreDisabled;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID					Instrumentation[13 - sizeof(GUID) / sizeof(PVOID)];
	GUID                    ActivityId;
	PVOID					SubProcessTag;
	PVOID					EtwLocalData;
	PVOID					EtwTraceData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	PVOID					Instrumentation[14];
	PVOID					SubProcessTag;
	PVOID					EtwLocalData;
#else
	PVOID					Instrumentation[16];
#endif
	PVOID					WinSockData;
	ULONG					GdiBatchCount;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	BOOLEAN                SpareBool0;
	BOOLEAN                SpareBool1;
	BOOLEAN                SpareBool2;
#else
	BOOLEAN                InDbgPrint;
	BOOLEAN                FreeStackOnTermination;
	BOOLEAN                HasFiberData;
#endif
	UCHAR                  IdealProcessor;
#if (NTDDI_VERSION >= NTDDI_WS03)
	ULONG                  GuaranteedStackBytes;
#else
	ULONG                  Spare3;
#endif
	PVOID				   ReservedForPerf;
	PVOID				   ReservedForOle;
	ULONG                  WaitingOnLoaderLock;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID				   SavedPriorityState;
	ULONG_PTR			   SoftPatchPtr1;
	ULONG_PTR			   ThreadPoolData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	ULONG_PTR			   SparePointer1;
	ULONG_PTR              SoftPatchPtr1;
	ULONG_PTR              SoftPatchPtr2;
#else
	Wx86ThreadState        Wx86Thread;
#endif
	PVOID* TlsExpansionSlots;
#if defined(_WIN64) && !defined(EXPLICIT_32BIT)
	PVOID                  DeallocationBStore;
	PVOID                  BStoreLimit;
#endif
	ULONG                  ImpersonationLocale;
	ULONG                  IsImpersonating;
	PVOID                  NlsCache;
	PVOID                  pShimData;
	ULONG                  HeapVirtualAffinity;
	HANDLE                 CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME      ActiveFrame;
#if (NTDDI_VERSION >= NTDDI_WS03)
	PVOID FlsData;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID PreferredLangauges;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;
	union
	{
		struct
		{
			USHORT SpareCrossTebFlags : 16;
		};
		USHORT CrossTebFlags;
	};
	union
	{
		struct
		{
			USHORT DbgSafeThunkCall : 1;
			USHORT DbgInDebugPrint : 1;
			USHORT DbgHasFiberData : 1;
			USHORT DbgSkipThreadAttach : 1;
			USHORT DbgWerInShipAssertCode : 1;
			USHORT DbgIssuedInitialBp : 1;
			USHORT DbgClonedThread : 1;
			USHORT SpareSameTebBits : 9;
		};
		USHORT SameTebFlags;
	};
	PVOID TxnScopeEntercallback;
	PVOID TxnScopeExitCAllback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	ULONG ProcessRundown;
	ULONG64 LastSwitchTime;
	ULONG64 TotalSwitchOutTime;
	LARGE_INTEGER WaitReasonBitMap;
#else
	BOOLEAN SafeThunkCall;
	BOOLEAN BooleanSpare[3];
#endif
} TEB, * PTEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PACTIVATION_CONTEXT EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	PVOID RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _INITIAL_TEB {
	PVOID                StackBase;
	PVOID                StackLimit;
	PVOID                StackCommit;
	PVOID                StackCommitMax;
	PVOID                StackReserved;
} INITIAL_TEB, * PINITIAL_TEB;


typedef enum _PS_CREATE_STATE
{
	PsCreateInitialState,
	PsCreateFailOnFileOpen,
	PsCreateFailOnSectionCreate,
	PsCreateFailExeFormat,
	PsCreateFailMachineMismatch,
	PsCreateFailExeName,
	PsCreateSuccess,
	PsCreateMaximumStates
} PS_CREATE_STATE, * PPS_CREATE_STATE;

typedef struct _PS_CREATE_INFO
{
	SIZE_T Size;
	PS_CREATE_STATE State;
	union
	{
		struct {
			union {
				ULONG InitFlags;
				struct {
					UCHAR  WriteOutputOnExit : 1;
					UCHAR  DetectManifest : 1;
					UCHAR  IFEOSkipDebugger : 1;
					UCHAR  IFEODoNotPropagateKeyState : 1;
					UCHAR  SpareBits1 : 4;
					UCHAR  SpareBits2 : 8;
					USHORT ProhibitedImageCharacteristics : 16;
				};
			};
			ACCESS_MASK AdditionalFileAccess;
		} InitState;
		struct {
			HANDLE FileHandle;
		} FailSection;
		struct {
			USHORT DllCharacteristics;
		} ExeFormat;
		struct {
			HANDLE IFEOKey;
		} ExeName;
		struct {
			union {
				ULONG OutputFlags;
				struct {
					UCHAR  ProtectedProcess : 1;
					UCHAR  AddressSpaceOverride : 1;
					UCHAR  DevOverrideEnabled : 1;
					UCHAR  ManifestDetected : 1;
					UCHAR  ProtectedProcessLight : 1;
					UCHAR  SpareBits1 : 3;
					UCHAR  SpareBits2 : 8;
					USHORT SpareBits3 : 16;
				};
			};
			HANDLE    FileHandle;
			HANDLE    SectionHandle;
			ULONGLONG UserProcessParametersNative;
			ULONG     UserProcessParametersWow64;
			ULONG     CurrentParameterFlags;
			ULONGLONG PebAddressNative;
			ULONG     PebAddressWow64;
			ULONGLONG ManifestAddress;
			ULONG     ManifestSize;
		} SuccessState;
	};
} PS_CREATE_INFO, * PPS_CREATE_INFO;

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef enum _KWAIT_REASON
{
	Executive = 0,
	FreePage = 1,
	PageIn = 2,
	PoolAllocation = 3,
	DelayExecution = 4,
	Suspended = 5,
	UserRequest = 6,
	WrExecutive = 7,
	WrFreePage = 8,
	WrPageIn = 9,
	WrPoolAllocation = 10,
	WrDelayExecution = 11,
	WrSuspended = 12,
	WrUserRequest = 13,
	WrEventPair = 14,
	WrQueue = 15,
	WrLpcReceive = 16,
	WrLpcReply = 17,
	WrVirtualMemory = 18,
	WrPageOut = 19,
	WrRendezvous = 20,
	Spare2 = 21,
	Spare3 = 22,
	Spare4 = 23,
	Spare5 = 24,
	WrCalloutStack = 25,
	WrKernel = 26,
	WrResource = 27,
	WrPushLock = 28,
	WrMutex = 29,
	WrQuantumEnd = 30,
	WrDispatchInt = 31,
	WrPreempted = 32,
	WrYieldExecution = 33,
	WrFastMutex = 34,
	WrGuardedMutex = 35,
	WrRundown = 36,
	MaximumWaitReason = 37
} KWAIT_REASON;

typedef LONG KPRIORITY;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;


typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformationObsolete,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	SystemThreadPriorityClientIdInformation,
	SystemProcessorIdleCycleTimeInformation,
	SystemVerifierCancellationInformation,
	SystemProcessorPowerInformationEx,
	SystemRefTraceInformation,
	SystemSpecialPoolInformation,
	SystemProcessIdInformation,
	SystemErrorPortInformation,
	SystemBootEnvironmentInformation,
	SystemHypervisorInformation,
	SystemVerifierInformationEx,
	SystemTimeZoneInformation,
	SystemImageFileExecutionOptionsInformation,
	SystemCoverageInformation,
	SystemPrefetchPatchInformation,
	SystemVerifierFaultsInformation,
	SystemSystemPartitionInformation,
	SystemSystemDiskInformation,
	SystemProcessorPerformanceDistribution,
	SystemNumaProximityNodeInformation,
	SystemDynamicTimeZoneInformation,
	SystemCodeIntegrityInformation,
	SystemProcessorMicrocodeUpdateInformation,
	SystemProcessorBrandString,
	SystemVirtualAddressInformation,
	SystemLogicalProcessorAndGroupInformation,
	SystemProcessorCycleTimeInformation,
	SystemStoreInformation,
	SystemRegistryAppendString,
	SystemAitSamplingValue,
	SystemVhdBootInformation,
	SystemCpuQuotaInformation,
	SystemNativeBasicInformation,
	SystemSpare1,
	SystemLowPriorityIoInformation,
	SystemTpmBootEntropyInformation,
	SystemVerifierCountersInformation,
	SystemPagedPoolInformationEx,
	SystemSystemPtesInformationEx,
	SystemNodeDistanceInformation,
	SystemAcpiAuditInformation,
	SystemBasicPerformanceInformation,
	SystemQueryPerformanceCounterInformation,
	SystemSessionBigPoolInformation,
	SystemBootGraphicsInformation,
	SystemScrubPhysicalMemoryInformation,
	SystemBadPageInformation,
	SystemProcessorProfileControlArea,
	SystemCombinePhysicalMemoryInformation,
	SystemEntropyInterruptTimingCallback,
	SystemConsoleInformation,
	SystemPlatformBinaryInformation,
	SystemThrottleNotificationInformation,
	SystemHypervisorProcessorCountInformation,
	SystemDeviceDataInformation,
	SystemDeviceDataEnumerationInformation,
	SystemMemoryTopologyInformation,
	SystemMemoryChannelInformation,
	SystemBootLogoInformation,
	SystemProcessorPerformanceInformationEx,
	SystemSpare0,
	SystemSecureBootPolicyInformation,
	SystemPageFileInformationEx,
	SystemSecureBootInformation,
	SystemEntropyInterruptTimingRawInformation,
	SystemPortableWorkspaceEfiLauncherInformation,
	SystemFullProcessInformation,
	SystemKernelDebuggerInformationEx,
	SystemBootMetadataInformation,
	SystemSoftRebootInformation,
	SystemElamCertificateInformation,
	SystemOfflineDumpConfigInformation,
	SystemProcessorFeaturesInformation,
	SystemRegistryReconciliationInformation,
	SystemEdidInformation,
	SystemManufacturingInformation,
	SystemEnergyEstimationConfigInformation,
	SystemHypervisorDetailInformation,
	SystemProcessorCycleStatsInformation,
	SystemVmGenerationCountInformation,
	SystemTrustedPlatformModuleInformation,
	SystemKernelDebuggerFlags,
	SystemCodeIntegrityPolicyInformation,
	SystemIsolatedUserModeInformation,
	SystemHardwareSecurityTestInterfaceResultsInformation,
	SystemSingleModuleInformation,
	SystemAllowedCpuSetsInformation,
	SystemDmaProtectionInformation,
	SystemInterruptCpuSetsInformation,
	SystemSecureBootPolicyFullInformation,
	SystemCodeIntegrityPolicyFullInformation,
	SystemAffinitizedInterruptProcessorInformation,
	SystemRootSiloInformation,
	MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;