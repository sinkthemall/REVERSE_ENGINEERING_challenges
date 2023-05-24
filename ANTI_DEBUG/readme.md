## Lời giải
### Chall 1
Nhìn thử vào đoạn xử lý ở hàm main:
```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int i; // [esp+0h] [ebp-20h]
  __uid_t uid; // [esp+4h] [ebp-1Ch]
  struct passwd *v5; // [esp+8h] [ebp-18h]
  char *s1; // [esp+Ch] [ebp-14h]
  size_t v7; // [esp+10h] [ebp-10h]
  char *s; // [esp+14h] [ebp-Ch]

  puts("Who are you?");
  uid = geteuid();
  v5 = getpwuid(uid);
  if ( ptrace(PTRACE_TRACEME, 0, 0, 0) )
  {
    puts("This doesn't seem right");
    exit(1);
  }
  if ( v5 )
  {
    s1 = v5->pw_name;
    if ( !strcmp(v5->pw_name, username) )
    {
      for ( i = 0; i < (char *)marker - (char *)main; ++i )
      {
        if ( (unsigned __int8)*(_DWORD *)((char *)main + i) == breakpointvalue )
        {
          puts("What's this now?");
          exit(1);
        }
      }
      v7 = strlen(encrypted_flag);
      s = (char *)malloc(4 * (v7 + 1));
      decrypt(s1, encrypted_flag, (int)s);
      s[v7] = 0;
      puts(s);
    }
    else
    {
      puts("No you are not the right person");
    }
    exit(0);
  }
  puts("?");
  exit(1);
}
```
Đầu tiên là ptrace, thì ptrace sử dụng để trace 1 process, kiểm tra memory và register của tracee
```
   The ptrace() system call provides a means by which one process
       (the "tracer") may observe and control the execution of another
       process (the "tracee"), and examine and change the tracee's
       memory and registers.  It is primarily used to implement
       breakpoint debugging and system call tracing.
```

Một đặc điểm của ptrace đó chính là, khi 1 process được ptrace, thì nó không thể bị ptrace bởi 1 process khác( 1 tracee chỉ được trace bởi 1 tracer tại 1 thời điểm duy nhất). Tìm hiểu thông tin về ```ptrace(PTRACE_TRACEME, 0, 0, 0) ``` thì ta biết được như sau:
```
The ptrace function is a system call in Linux used for process tracing and debugging. It allows a process to control and observe another process. The PTRACE_TRACEME request is a specific request code used with the ptrace function. It is used by a tracee process to request that it be traced by its parent process or a debugger.
```
Như vậy nếu như 1 process đang bị debug bởi debugger, thì debugger sẽ gọi ptrace tới process đó => process bị trace và ```ptrace(PTRACE_TRACEME, 0, 0, 0) ``` sẽ return khác 0.

Để bypass thì ta có thể sửa kết quả trả về hoặc sửa lệnh rẽ nhánh.
```c
if ( v5 )
  {
    s1 = v5->pw_name;
    if ( !strcmp(v5->pw_name, username) )
    {
      for ( i = 0; i < (char *)marker - (char *)main; ++i )
      {
        if ( (unsigned __int8)*(_DWORD *)((char *)main + i) == breakpointvalue )
        {
          puts("What's this now?");
          exit(1);
        }
      }
      v7 = strlen(encrypted_flag);
      s = (char *)malloc(4 * (v7 + 1));
      decrypt(s1, encrypted_flag, (int)s);
      s[v7] = 0;
      puts(s);
    }
    else
    {
      puts("No you are not the right person");
    }
    exit(0);
  }
```
Đến đoạn code trên thì nó dùng để check xem liệu trong code section có chứa kí tự '\xCC' hay không, cho những ai chưa biết thì '\xCC' là Int3 opcode. Lệnh này dùng để interupt, chuyển quyền cho kernel, thường thì lệnh này sử dụng như 1 breakpoint. Vì vậy, đoạn code sẽ kiểm tra xem nếu trong code section có chứa '\xCC' khi này sẽ thoát khỏi flow => Khúc này thì mình có thể rẽ nhánh kết quả compare để tránh nhảy vào exit. Với ```!strcmp(v5->pw_name, username)``` thì mình cũng làm điều tương tự: không cần quan tâm tới username mang giá trị gì, chỉ cần sửa lại phần rẽ nhánh là có thể bypass. Tuy nhiên làm sao để làm được khi mà số lượng kí tự trong code section lên tới hàng trăm, hàng nghìn (điều này có vẻ rất mất thời gian) ??? Thì ở đây mình sử dụng 1 cái plugin có tên keypatch dùng để patch lại các lệnh trong file. Patch các đoạn rẽ nhánh thành ```jmp``` là coi như bypass đoạn AntiDebugger rồi.

Kết quả:
![](https://github.com/sinkthemall/REVERSE_ENGINEERING_challenges/blob/main/img/result_chall1.png)

### Chall 2
Ở bài này thì hơi phức tạp nên mình sẽ chỉ giải thích ở những công đoạn quan trọng
```c
// positive sp value has been detected, the output may be wrong!
int __cdecl main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // eax
  HANDLE CurrentProcess; // eax
  int v6; // [esp+C4h] [ebp-A8h]
  DWORD TickCount; // [esp+D4h] [ebp-98h]
  LPCSTR lpFileName; // [esp+D8h] [ebp-94h] BYREF
  BOOL pbDebuggerPresent[6]; // [esp+DCh] [ebp-90h] BYREF
  char Str2[16]; // [esp+F8h] [ebp-74h] BYREF
  int v11; // [esp+108h] [ebp-64h]
  char Str1[68]; // [esp+10Ch] [ebp-60h] BYREF
  CPPEH_RECORD ms_exc; // [esp+154h] [ebp-18h]

  memset(Str1, 0, 64);
  v11 = 1;
  printf("Input password >");
  v3 = (FILE *)sub_40223D();
  fgets(Str1, 64, v3);
  strcpy(Str2, "I have a pen.");
  v11 = strncmp(Str1, Str2, 0xDu);
  if ( !v11 )
  {
    puts("Your password is correct.");
    if ( IsDebuggerPresent() )
    {
      puts("But detected debugger!");
      exit(1);
    }
    if ( sub_401120() == 112 )
    {
      puts("But detected NtGlobalFlag!");
      exit(1);
    }
    CurrentProcess = GetCurrentProcess();
    CheckRemoteDebuggerPresent(CurrentProcess, pbDebuggerPresent);
    if ( pbDebuggerPresent[0] )
    {
      printf("But detected remotedebug.\n");
      exit(1);
    }
    TickCount = GetTickCount();
    pbDebuggerPresent[3] = 0;
    pbDebuggerPresent[1] = 1000;
    if ( GetTickCount() - TickCount > 0x3E8 )
    {
      printf("But detected debug.\n");
      exit(1);
    }
    lpFileName = "\\\\.\\Global\\ProcmonDebugLogger";
    if ( CreateFileA("\\\\.\\Global\\ProcmonDebugLogger", 0x80000000, 7u, 0, 3u, 0x80u, 0) != (HANDLE)-1 )
    {
      printf("But detect %s.\n", (const char *)&lpFileName);
      exit(1);
    }
    v6 = sub_401130();
    switch ( v6 )
    {
      case 1:
        printf("But detected Ollydbg.\n");
        exit(1);
      case 2:
        printf("But detected ImmunityDebugger.\n");
        exit(1);
      case 3:
        printf("But detected IDA.\n");
        exit(1);
      case 4:
        printf("But detected WireShark.\n");
        exit(1);
    }
    if ( sub_401240() == 1 )
    {
      printf("But detected VMware.\n");
      exit(1);
    }
    pbDebuggerPresent[2] = 1;
    pbDebuggerPresent[5] = 1;
    pbDebuggerPresent[4] = 1 / 0;
    ms_exc.registration.TryLevel = -2;
    printf("But detected Debugged.\n");
    exit(1);
  }
  printf("password is wrong.\n");
  return 0;
}
```

Để ý ở đoạn này :
```c
  printf("Input password >");
  v3 = (FILE *)sub_40223D();
  fgets(Str1, 64, v3);
  strcpy(Str2, "I have a pen.");
  v11 = strncmp(Str1, Str2, 0xDu);
  if ( !v11 )
  {
    puts("Your password is correct.");
```
Dựa vào thông tin trên thì ta có thể chắc rằng input cần nhập sẽ là ```I have a pen.``` Kế tiếp ta sẽ nhìn sơ qua về các hàm dùng để check being debugged.

Đầu tiên là IsDebuggerPresent(), hàm này sẽ kiểm tra xem liệu chương trình có bị debug hay không thông qua kiểm tra trường BeingDebugged của PEB (Process Environment Block) ở địa chỉ fs:[0x30] (với file 32bit), và BeingDebugged nằm tại offset 0x2.
Tiếp theo là về NtGlobalFlag:
```
NtGlobalFlag is a system-level flag that can be found in the Windows kernel data structure known as the KUSER_SHARED_DATA. This data structure is used to store various global data values that are accessible to both user-mode and kernel-mode code.
```
Làm sao mà NtGlobalFlag phát hiện rằng process đang bị debug thì :
```
Yes, the NtGlobalFlag can be used to determine if a process is being debugged or not. In particular, the NtGlobalFlag bit 0x70 (also known as the FLG_HEAP_ENABLE_TAIL_CHECK) can be used for this purpose.

When a process is being debugged, this bit is often manipulated by debuggers or debugging techniques to change the behavior of memory allocations and heap operations. By default, the value of this bit is set to 0, indicating that tail checking of heap allocations is disabled.

If a debugger enables the tail checking feature, it sets the NtGlobalFlag bit 0x70 to 1. When the process is running under a debugger, and this bit is set to 1, it indicates that the process is being debugged. This information can be useful for anti-debugging techniques or for implementing specific behaviors that should only occur when a debugger is present.

So, if the expression "NtGlobalFlag & 0x70 = 112" evaluates to true, it suggests that the NtGlobalFlag bit 0x70 is set to 1, which may indicate that the process is being debugged.
```
Qua đến GetTickCount, thì GetTickCount sẽ trả về số lượng Tick tính từ thời điểm process bắt đầu. Và trong đoạn code trên thì cái này được dùng để kiểm tra xem liệu chương trình có đang bị debug không = kiểm tra nếu thời gian tính từ khi process running > 1s (xảy ra khi debug) => process đang bị debug.

Kế đên là trong function tại địa chỉ 401130:
```c
int sub_401130()
{
  PROCESSENTRY32 pe; // [esp+0h] [ebp-138h] BYREF
  HANDLE hSnapshot; // [esp+130h] [ebp-8h]
  BOOL i; // [esp+134h] [ebp-4h]

  pe.dwSize = 296;
  memset(&pe.cntUsage, 0, 0x124u);
  hSnapshot = CreateToolhelp32Snapshot(2u, 0);
  for ( i = Process32First(hSnapshot, &pe); i; i = Process32Next(hSnapshot, &pe) )
  {
    if ( !_stricmp(pe.szExeFile, "ollydbg.exe") )
      return 1;
    if ( !_stricmp(pe.szExeFile, "ImmunityDebugger.exe") )
      return 2;
    if ( !_stricmp(pe.szExeFile, "idaq.exe") )
      return 3;
    if ( !_stricmp(pe.szExeFile, "Wireshark.exe") )
      return 4;
  }
  return 0;
}
```
Ta phát hiện sự có mặt của ```CreateToolhelp32Snapshot(2u, 0)```, cụ thể thì hàm này sẽ trả về handle của toàn bộ process trong system, và theo như đoạn code trên thì nó kiểm tra sự có mặt của 1 số tiến trình như: ollydbg, ImmunityDebugger, IDA, wireshark. 3 cái trên (olly, Immunitydebugger, ida) đều là những trình debugger nổi tiếng, thế nên việc kiểm tra chúng không có gì là lạ (mình cũng không thực sự hiểu vì sao nó lại kiểm tra wireshark).

Sang function tại địa chỉ 401240
```c
int __spoils<ecx> sub_401240()
{
  __indword(0x5658u);
  return 1;
}
```
Sau 1 thời gian tìm hiểu thì mình biết được rằng, hàm trên dùng để đọc dữ liệu từ port 0x5658, cụ thể hơn thì:
```
This is a "backdoor" I/O port for VMware, 0x5658 = &quot;VX&quot;. If the program is running inside VMware, the program uses the In instruction to read data through the 0x5658 port, the value of the EBX register. Will become 0x564D5868 (0x564D5868 == &quot;VMXh&quot;)
```

Tổng quan chung thì chúng ta đã có sơ lược thông tin về những cách mà process chống bị debug. Và technique mà ta sử dụng để bypass cũng tương tự như bài 1: patch lại các lệnh rẽ nhánh. Riêng đối với lời gọi hàm 401240, ta hoàn toàn có thể patch = những lệnh NOP => chương trình sẽ bỏ qua mà không thực hiện. Tiếp theo, nếu để ý kĩ thì ta sẽ có 1 đoạn khá là nghi vấn như sau:
```
mov     ecx, 7
mov     esi, offset aAjJq7hbotHU8ac ; ";aj&@:JQ7HBOt[h?U8aCBk]OaI38"
lea     edi, [ebp+var_CC]
rep movsd
movsb
xor     ecx, ecx
mov     [ebp+var_AF], ecx
lea     edx, [ebp+var_CC]
mov     [ebp+Str], edx
mov     [ebp+Text], 0
push    7Fh             ; Size
push    0               ; Val
lea     eax, [ebp+var_157]
push    eax             ; void *
call    _memset
add     esp, 0Ch
lea     ecx, [ebp+Text]
mov     [ebp+var_D4], ecx
mov     edx, [ebp+Str]
push    edx             ; Str
call    _strlen
add     esp, 4
mov     [ebp+var_D0], eax
mov     [ebp+var_15C], 0
```
Sau đoạn code này sẽ có 1 đoạn gọi tới message box. Dựa trên những gì mình quan sát thì có thể đây là đoạn nó in ra flag thật. Và để có thể nhảy được tới đoạn này thì ta cần phải chỉnh sửa các điều kiện( một số cái có thể kể đến như là nó cố tình đặt điều kiện sai để không nhảy vào, hoặc là division by zero gây ra lỗi...)

Kết quả:
![](https://github.com/sinkthemall/REVERSE_ENGINEERING_challenges/blob/main/img/result_chall2.png)

### Chall 3

Sang tới chall 3 thì mình hơi bất ngờ vì không phát hiện việc process có sử dụng anti debugger. Tuy nhiên thì ta sẽ xem thử xem trong chương trình có gì:
```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int i; // [rsp+8h] [rbp-8h]
  int j; // [rsp+Ch] [rbp-4h]

  pipe(pipedes);
  __isoc99_scanf(&unk_5635DD957004, enter_string);
  len_str = strlen(enter_string);
  set_increasing_sequence(&byte_5635DD959240);
  key_scheduling(&byte_5635DD959240, &byte_5635DD959100, (unsigned int)dword_5635DD959164);
  rc4_producing_stream(&byte_5635DD959240, (unsigned int)len_str, byte_5635DD959340);
  for ( i = 0; i < len_str; ++i )
    enter_string[i] ^= byte_5635DD959340[i];
  for ( j = 0; j < len_str; ++j )
  {
    if ( enter_string[j] != byte_5635DD9590C0[j] )
      exit(1);
  }
  return 0LL;
}
```
Dựa trên những gì mình tìm thấy trong hàm main, thì mình có thể suy ra rằng challenge lần này có liên quan tới rc4 ( 1 loại stream cipher ), các hàm trên đã được mình rename lại sao cho dễ hiểu nhất có thể. Mình sẽ giải thích sơ lược các hàm để có thể dẽ hình dung:
- set_increasing_sequence: hàm này dùng để tạo chuỗi tăng dần từ 0 đến 255, sau đó lưu vào 1 mảng. Đây là hàm được sử dụng trong quá trình key scheduling của rc4.
- key_scheduling: hàm này là 1 part chính trong thuật toán rc4, nói nôm na thì hàm này sử dụng để sắp xếp, scheduling lại key.
- rc4_producing_stream: hàm tạo stream cipher, stream này sẽ được lưu trong mảng, độ dài phụ thuộc vào chuỗi mà ta nhập vào
Nếu như flow của main chỉ có như vầy thì nếu ta tạo ra được rc4 stream rồi đem xor với chuỗi ```byte_5635DD9590C0``` thì ta sẽ tìm ra được chuỗi chính xác mà ta cần tìm. Nhận thấy cách giải quyết, mình hí hửng loay hoay để debug lấy keystream và xor với chuỗi encrypted, thì đây là kết quả:
```python
def xor(a,b):
    return bytes([i^j for i,j in zip(a,b)])

key = b'\xb8\x86Dc\xb5\xd8\x1c\x95\xd1~p^\xbcVc4(\x90\x15\xf8MR\x9d\x1e\xf5\x1f\xc8dR\x1bd\x0f$'
enc = b'\xdb\xb6*\x04\xc7\xb9h\xe0\xbd>\x04o\xd38\x10kJ\xe5a\xa7$\r\xfcs\xaaq\xf8\x10\r}UnC'
print(xor(key, enc))
```
![]()
## Reference:

- https://www.apriorit.com/dev-blog/367-anti-reverse-engineering-protection-techniques-to-use-before-releasing-software
- https://linuxsecurity.com/features/anti-debugging-for-noobs-part-1
- https://www.codeproject.com/Articles/621236/Nanomite-and-Debug-Blocker-for-Linux-Applications