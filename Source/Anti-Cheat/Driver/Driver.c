//#include <ntddk.h>
#include <ntifs.h>
#include <ntddk.h>

#define IO_SEND_PROCESSES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0700, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_SEND_SYSTEMPROCESSES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0701, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)


typedef struct _KERNEL_PROCESS_INFO
{
	ULONG pidUserModeAntiCheat;
	ULONG pidGame;
	ULONG bReceived;
}KERNEL_PROCESS_INFO, *PKERNEL_PROCESS_INFO;

typedef struct _KERNEL_SYSTEMPROCESSES_INFO
{
	ULONG pidLsass;
	ULONG pidCsrss1;
	ULONG pidCsrss2;
}KERNEL_SYSTEMPROCESS_INFO, *PKERNEL_SYSTEMPROCESS_INFO;


#define IO_INPUT(Type)  ((Type)(pIrp->AssociatedIrp.SystemBuffer)) 
#define IO_OUTPUT(Type) ((Type)(pIrp->UserBuffer))

DRIVER_INITIALIZE DriverEntry;

const WCHAR sc_wszDeviceNameBuffer[] = L"\\Device\\AntiCheatDriver";
const WCHAR sc_wszDeviceSymLinkBuffer[] = L"\\DosDevices\\AntiCheatDriver";

PVOID ObHandle = 0;

ULONG pidAntiCheat = 0;
ULONG pidGame = 0;

ULONG pidLsass = 0;
ULONG pidCsrss1 = 0;
ULONG pidCsrss2 = 0;

NTSTATUS OnIoControll(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);

	NTSTATUS ntStatus = STATUS_SUCCESS;
	

	__try {
		
		PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
		pIrp->IoStatus.Information = 0;

		ULONG uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;

		switch (uIoControlCode)
		{
			case IO_SEND_PROCESSES:
			{
			
				pidGame =  IO_INPUT(PKERNEL_PROCESS_INFO)->pidGame;
				pidAntiCheat = IO_INPUT(PKERNEL_PROCESS_INFO)->pidUserModeAntiCheat;
		
				IO_OUTPUT(PKERNEL_PROCESS_INFO)->bReceived = 1;
				pIrp->IoStatus.Information = 0; 

			
			}break;
			case IO_SEND_SYSTEMPROCESSES:
			{
				pidCsrss1 = IO_INPUT(PKERNEL_SYSTEMPROCESS_INFO)->pidCsrss1;
				pidCsrss2 = IO_INPUT(PKERNEL_SYSTEMPROCESS_INFO)->pidCsrss2;
				pidLsass = IO_INPUT(PKERNEL_SYSTEMPROCESS_INFO)->pidLsass;

				pIrp->IoStatus.Information = sizeof(KERNEL_SYSTEMPROCESS_INFO);

			}break;
	
		
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ntStatus = STATUS_UNSUCCESSFUL;
		DbgPrint("OnIoControl Exception catched!\n");

	}



	pIrp->IoStatus.Status = ntStatus;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return ntStatus;

}

//Wird benutzt da für alle nicht definierten funktionen das notwenige default zurückgegeben wird. Sont müsste man OnClose, OnCreate undso implementieren
NTSTATUS OnMajorFunctionCall(PDEVICE_OBJECT pDriverObject, PIRP pIrp)
{
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIrp);
	switch (pStack->MajorFunction)
	{
	case IRP_MJ_DEVICE_CONTROL:
		OnIoControll(pDriverObject, pIrp);
		break;
	default:
		pIrp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	}

	
	return STATUS_SUCCESS;
}

VOID OnDriverUnload(IN PDRIVER_OBJECT pDriverObject)
{

	if (ObHandle)
	{
		ObUnRegisterCallbacks(ObHandle);
		ObHandle = NULL;
	}



	UNICODE_STRING symLink;
	RtlInitUnicodeString(&symLink, sc_wszDeviceSymLinkBuffer);


	IoDeleteSymbolicLink(&symLink);
	if (pDriverObject && pDriverObject->DeviceObject)
	{
		IoDeleteDevice(pDriverObject->DeviceObject);
	}
}

OB_PREOP_CALLBACK_STATUS ProcessPreCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	
	if ((pidAntiCheat == 0) || (pidGame == 0) || (pidLsass == 0) || (pidCsrss1 == 0) || (pidCsrss2 == 0))
		return OB_PREOP_SUCCESS;


	PEPROCESS OpenedProcess; 
	PEPROCESS CurrentProcess; 
	OpenedProcess = (PEPROCESS)OperationInformation->Object;
	CurrentProcess = PsGetCurrentProcess();


	unsigned long long pidOpenedProcess = 0;
	unsigned long long pidCurrentProcess = 0;
	pidOpenedProcess = (unsigned long long)PsGetProcessId(OpenedProcess);
	pidCurrentProcess = (unsigned long long)PsGetProcessId(CurrentProcess);

	if ((pidCurrentProcess == pidCsrss1) || (pidCurrentProcess == pidCsrss2) || (pidCurrentProcess == pidLsass) || (pidCurrentProcess == pidCurrentProcess) || (OperationInformation->KernelHandle) || (pidCurrentProcess == pidAntiCheat) || (pidCurrentProcess == pidGame))
		return OB_PREOP_SUCCESS;

	PEPROCESS GamePEPROCESS;
	PEPROCESS UserModeACPEPROCESS;
	PsLookupProcessByProcessId((HANDLE)pidAntiCheat, &UserModeACPEPROCESS);
	PsLookupProcessByProcessId((HANDLE)pidGame, &GamePEPROCESS);
	UNREFERENCED_PARAMETER(GamePEPROCESS);
	UNREFERENCED_PARAMETER(UserModeACPEPROCESS);

	if (GamePEPROCESS != 0)
	{
		if (pidOpenedProcess == pidGame)
		{
			if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = (SYNCHRONIZE | 0x1000);
			else
				OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = (SYNCHRONIZE | 0x1000);
		}
	
	}
	
	if (UserModeACPEPROCESS != 0)
	{
		if (pidOpenedProcess == pidAntiCheat)
		{
			if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = (SYNCHRONIZE | 0x1000);
			else
				OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = (SYNCHRONIZE | 0x1000);
		}
		
	}

	return OB_PREOP_SUCCESS;
}

VOID ProcessPostCallBack(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);
}

VOID EnableCallBack()
{
	NTSTATUS NtHandleCallback = STATUS_UNSUCCESSFUL;

	OB_OPERATION_REGISTRATION OBOperationRegistration;
	OB_CALLBACK_REGISTRATION OBCallbackRegistration;
	UNICODE_STRING usAltitude;
	RtlSecureZeroMemory(&OBOperationRegistration, sizeof(OB_OPERATION_REGISTRATION));
	RtlSecureZeroMemory(&OBCallbackRegistration, sizeof(OB_CALLBACK_REGISTRATION));
	RtlInitUnicodeString(&usAltitude, L"1063450"); //gibt nur an wann treiber geladen werden soll. Hier nicht wichtig

	if (ObGetFilterVersion() == OB_FLT_REGISTRATION_VERSION)
	{
		OBOperationRegistration.ObjectType = PsProcessType;
		OBOperationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		OBOperationRegistration.PreOperation = ProcessPreCallBack;
		OBOperationRegistration.PostOperation = ProcessPostCallBack;

		OBCallbackRegistration.Altitude = usAltitude;
		OBCallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
		OBCallbackRegistration.OperationRegistrationCount = 1;
		OBCallbackRegistration.RegistrationContext = NULL;
		OBCallbackRegistration.OperationRegistration = &OBOperationRegistration;

		NtHandleCallback = ObRegisterCallbacks(&OBCallbackRegistration, &ObHandle);


		if (!NT_SUCCESS(NtHandleCallback))
		{
			if (ObHandle)
			{
				ObUnRegisterCallbacks(ObHandle);
				ObHandle = NULL;
			}
			DbgPrintEx(0, 0, "Error: ObRegisterCallbacks Has Failed\n");
		}
	}
}


NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);

	if (!pDriverObject)
	{
		DbgPrint("DispatchTestSys driver entry is null! \n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	//Register unload routine
	pDriverObject->DriverUnload = OnDriverUnload;

	NTSTATUS ntStatus = 0;

	//Normalize name and symbolic link
	UNICODE_STRING deviceNameUnicodeString, deviceSymLinkUnicodeString;
	RtlInitUnicodeString(&deviceNameUnicodeString, sc_wszDeviceNameBuffer);
	RtlInitUnicodeString(&deviceSymLinkUnicodeString, sc_wszDeviceSymLinkBuffer);

	// Create the device.
	PDEVICE_OBJECT pDeviceObject = NULL;
	ntStatus = IoCreateDevice(pDriverObject, 0, &deviceNameUnicodeString, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	if (ntStatus != STATUS_SUCCESS)
	{
		DbgPrint("IoCreateDevice fail! Status: %p\n", ntStatus);
		return ntStatus;
	}

	// Create the symbolic link
	ntStatus = IoCreateSymbolicLink(&deviceSymLinkUnicodeString, &deviceNameUnicodeString);
	if (ntStatus != STATUS_SUCCESS)
	{
		DbgPrint("IoCreateSymbolicLink fail! Status: %p\n", ntStatus);
		return ntStatus;
	}

	// Register driver major callbacks
	for (ULONG t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
		pDriverObject->MajorFunction[t] = &OnMajorFunctionCall;

	pDeviceObject->Flags |= DO_DIRECT_IO;
	pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);


	EnableCallBack();

	return STATUS_SUCCESS;
}