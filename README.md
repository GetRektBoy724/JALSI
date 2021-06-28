# JALSI - Just Another Lame Shellcode Injector
JALSI is short for Just Another Lame Shellcode Injector.JALSI can inject shellcode (in the form of byte array,ofcourse) to local process or remote process.The special thing about JALSI is just that it uses D/Invoke.Anything else,its pretty lame.
### This tool is tested on Windows 10 v20H2 x64 using MSFVenom's shellcode
# Usage
Simply load the pre-compiled DLL or add the code function and call the LocalInject,RemoteInject,or QueueAPCInject function from the JALSI class. You can load the pre-compiled DLL on Powershell with Reflection.Assembly too! This code uses C# 5,so it can be compiled with the built-in CSC from Windows 10.
### Parameters
- `RemoteInject(int TargetProcessID, byte[] shellcode)`
- `LocalInject(byte[] shellcode)`
- `QueueAPCInject(string PathToExecutableForProcess, byte[] shellcode)`
### RemoteInject Function 
Inject shellcode to a remote process using `NtOpenProcess/NtAllocateVirtualMemory/NtWriteVirtualMemory/NtProtectVirtualMemory(preventing RWX)/NtCreateThreadEx` pattern.
Memory Protection settings used : RW,RX
![JALSIRemoteInject](https://user-images.githubusercontent.com/41237415/123536377-1d13e580-d754-11eb-9511-f1a10aa8444f.png)


### LocalInject Function
Inject shellcode to local/current process using `Marshal.AllocHGlobal/NtProtectVirtualMemory/Marshal.Copy/NtCreateThreadEx` pattern.
Memory Protection settings used : RWX

![JALSILocalInject](https://user-images.githubusercontent.com/41237415/123536372-16856e00-d754-11eb-8e27-43f25509b049.png)


### QueueAPCInject Function 
Inject shellcode to a newly spawned process using `CreateProcess/NtAllocateVirtualMemory/NtWriteVirtualMemory/NtProtectVirtualMemory(preventing RWX)/NtQueueApcThread/NtAlertResumeThread` pattern
Memory Protection settings used : RW,RX

![JALSIQueueAPCInject](https://user-images.githubusercontent.com/41237415/123536357-0a99ac00-d754-11eb-8573-218a8b1fa777.png)


