# JALSI - Just Another Lame Shellcode Injector
JALSI is short for Just Another Lame Shellcode Injector.JALSI can inject shellcode (in the form of byte array,ofcourse) to local process or remote process.The special thing about JALSI is just that it uses D/Invoke.Anything else,its pretty lame.
### This tool is tested on Windows 10 v20H2 using MSFVenom's shellcode
# Usage
Simply load the pre-compiled DLL or add the code function and call the LocalInject or RemoteInject function from the JALSI class. You can load the pre-compiled DLL on Powershell with Reflection.Assembly too! This code uses C# 5,so it can be compiled with the built-in CSC from Windows 10.
### Parameters
Look at the code,dont be a skid.
### RemoteInject Function 

![JALSIRemoteInject](https://user-images.githubusercontent.com/41237415/122629728-56f84280-d0e9-11eb-944f-86f3761bdd11.png)

### LocalInject Function

![JALSILocalInject](https://user-images.githubusercontent.com/41237415/122629732-624b6e00-d0e9-11eb-8fee-74024ea41682.png)

