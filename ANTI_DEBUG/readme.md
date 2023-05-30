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
![](https://github.com/sinkthemall/REVERSE_ENGINEERING_challenges/blob/main/img/fake_flag_chall3.png)
Hừm what!? Nếu nó không phải real flag thì làm sao để tìm được đây? Thật sự thì đến khúc này mình không có bất kì ý tưởng nào để mà làm cả( 1 phần vì file bị stripped nên rất khó để biết được những hàm trong file và nó được sử dụng để làm gì). Thì ở đây mình quyết định tìm hiểu thêm về 1 số thứ và sau khi tìm hiểu thì mình đã phát hiện được ra kiến thức mới: .init_array và .fini_array! Vậy thì hai cái này có liên quan gì tới challenge mà ta đang làm?
Đầu tiên, đây là định nghĩa về .init_array và .fini_array:
```
The .init_array and .fini_array are sections in the binary executable file format, specifically used in the ELF (Executable and Linkable Format) commonly used in Linux and Unix-like systems.

.init_array:
The .init_array section contains an array of function pointers that are executed before the program's main function is called. These functions are commonly referred to as "constructor" functions because they perform initialization tasks before the program starts executing its main logic. The purpose of the .init_array section is to provide a convenient way to execute such initialization functions automatically.
When the program starts, the runtime environment (such as the C runtime) looks for the .init_array section and iterates through the function pointers, calling each function in the order they appear in the array. This allows developers to ensure that certain initialization tasks, such as setting up global variables or configuring libraries, are performed before the main program execution begins.

.fini_array:
Similarly, the .fini_array section contains an array of function pointers that are executed when the program is about to exit, just before the exit function is called. These functions are often called "destructor" functions because they handle cleanup tasks or perform finalization operations before the program terminates.
```
Dựa trên định nghĩa trên, thì ta biết rằng .init_array và .fini_array chứa 1 chuỗi các function pointer, và chúng hoạt động giống như constructor và destructor vậy: .init_array sẽ chạy các function pointer khi chương trình bắt đầu (tức là từ trước lúc hàm main), ngược lại .fini_array sẽ chạy các pointer chứa bên trong khi chương trình kết thúc bình thường.
Vậy câu hỏi đặt ra: nếu giả sử 1 hàm được lưu trữ trong .init_array (hoặc .fini_array), thì liệu nhất thiết có cần phải xuất hiện trong main flow thì mới chạy được không? Câu trả lời là không: nếu như chúng xuất hiện trong .init_array và .fini_array thì khi chạy chương trình( hoặc khi kết thúc), những chương trình ấy cũng sẽ tự động chạy mà không nhất thiết phải được gọi trong main flow. Đây có thể là lí do cho việc chúng ta không tim ra bất cứ thông tin nào liên quan đến real flag.

Thì sau một hồi tìm hiểu mò mẫm thì mình phát hiện ra 1 hàm xuất hiện trong .fini_array
```c
unsigned __int64 what2()
{
  int v1; // eax
  __WAIT_STATUS stat_loc; // [rsp+4h] [rbp-2Ch] BYREF
  int i; // [rsp+Ch] [rbp-24h]
  int j; // [rsp+10h] [rbp-20h]
  int k; // [rsp+14h] [rbp-1Ch]
  __pid_t v6; // [rsp+18h] [rbp-18h]
  int v7; // [rsp+1Ch] [rbp-14h]
  int pipedes[2]; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v9; // [rsp+28h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  if ( pipe(pipedes) == -1 )
    exit(1);
  v6 = fork();
  if ( v6 < 0 )
    exit(1);
  if ( v6 )
  {
    close(pipedes[0]);
    v7 = 2;
    HIDWORD(stat_loc.__iptr) = 3;
    while ( SHIDWORD(stat_loc.__iptr) < len_str )
    {
      if ( SHIDWORD(stat_loc.__iptr) % v7 )
        write(pipedes[1], (char *)&stat_loc.__iptr + 4, 4uLL);
      else
        ++dword_5563B13C9168;
      ++HIDWORD(stat_loc.__iptr);
    }
    close(pipedes[1]);
    close(dword_5563B13C93AC);
    while ( (unsigned int)read(::pipedes[0], (char *)&stat_loc.__iptr + 4, 4uLL) )
    {
      v1 = dword_5563B13C9164++;
      byte_5563B13C9100[v1] = BYTE4(stat_loc.__iptr);
    }
    close(::pipedes[0]);
    wait((__WAIT_STATUS)&stat_loc);
    if ( LODWORD(stat_loc.__uptr) )
    {
      puts(s);
      exit(1);
    }
    v6 = fork();
    if ( v6 < 0 )
      exit(1);
    if ( !v6 )
    {
      key_scheduling((__int64)byte_5563B13C9240, (__int64)byte_5563B13C9100, dword_5563B13C9164);
      for ( i = 0; i < dword_5563B13C9168; ++i )
        rc4_producing_stream((__int64)byte_5563B13C9240, len_str, (__int64)byte_5563B13C9340);
      for ( j = 0; j < len_str; j += 2 )
      {
        enter_string[j] = (enter_string[j] + enter_string[j + 1]) ^ byte_5563B13C9340[j];
        enter_string[j + 1] = byte_5563B13C9340[j + 1] ^ (enter_string[j] - enter_string[j + 1]);
      }
      for ( k = 0; k < len_str; ++k )
      {
        if ( enter_string[k] != byte_5563B13C9180[k] )
          exit(1);
      }
      exit(0);
    }
    wait((__WAIT_STATUS)&stat_loc);
    if ( LODWORD(stat_loc.__uptr) )
      puts(s);
    else
      puts(aGqk9lLwyvj);
    exit(0);
  }
  what1(pipedes);
  return v9 - __readfsqword(0x28u);
}
```
Nếu như hàm key_scheduling được gọi trong này thì chắc chắn là nó phải có liên quan tới real flag rồi. Ở đây xuất hiện thêm 1 chuỗi encrypt khác nằm ở offset 180 : ```byte_5563B13C9180```, có thể kết luận rằng đây là real flag, vậy thì chỉ cần reverse đoạn này thì ta có thể tìm ra real flag rồi.

Ngoài lề 1 chút, ngoài việc gặp khó khăn trong quá trình tìm hiểu và phát hiện về .init_array và .fini_array thì mình còn gặp 1 khó khăn nữa đó chính là việc debug đoạn real flag. Lí do là vì ở đây nó chuyển toàn bộ quá trình encrypt flag vô process con rồi mới xử lý, mà IDA hiện tại của mình lại debug process cha, nên là mình không thể nào mà debug thằng con để lấy key được (cái này mình sẽ tìm cách xử lý trong tương lai).

Source code dưới đây là mình tham khảo từ 1 người khác, nên là cũng không hẳn là mình làm ra được( bù lại thì mình đã học được kiến thức mới về fini và init, nên cx ko quá tệ).

```python
s = "abcdefghijklmnopqrstuvwxyz0123456789"
s_arr = [ord(c) for c in s]
s_enc = [0xD9, 0xE4, 0x27, 0x07, 0xD0, 0xBE, 0x7B, 0xFD, 0xB8, 0x14, 0x1B, 0x32, 0xD1, 0x38, 0x0C, 0x44, 0x59, 0xE2, 0x66, 0x8C, 0x38, 0x24, 0xEA, 0x66, 0x8C, 0x65, 0xF8, 0x55, 0x60, 0x28, 0x50, 0x3A, 0x12, 0xA4, 0x78, 0x64]
xor_box_1 = []
for i in range(len(s_arr)): 
    xor_box_1.append(s_arr[i] ^ s_enc[i])
xor_box_2 = [0x35, 0x4B, 0xA0, 0x60, 0x08, 0x50, 0xA5, 0xF1, 0x33, 0x97, 0xB2, 0x13, 0xCB, 0x4C, 0x0D, 0xCF, 0xA3, 0x7C, 0x57, 0x53, 0xE2, 0xA9, 0x65, 0x4E, 0x0E, 0xC7, 0x7A, 0x0F, 0xFD, 0xB5, 0x9E, 0xB4, 0x33, 0xF9, 0x61, 0xD3]
enc = [0xF7, 0x5F, 0xE7, 0xB0, 0x9A, 0xB4, 0xE0, 0xE7, 0x9E, 0x05, 0xFE, 0xD8, 0x35, 0x5C, 0x72, 0xE0, 0x86, 0xDE, 0x73, 0x9F, 0x9A, 0xF6, 0x0D, 0xDC, 0xC8, 0x4F, 0xC2, 0xA4, 0x7A, 0xB5, 0xE3, 0xCD, 0x60, 0x9D, 0x04, 0x1F]
for i in range(0, len(enc), 2): 
    enc[i+1] ^= xor_box_2[i+1] 
    enc[i+1] = enc[i]-enc[i+1] 
    enc[i+1] %= 0x100 
    enc[i] ^= xor_box_2[i] 
    enc[i] = enc[i]-enc[i+1] 
    enc[i] %= 0x100
for i in range(len(enc)): 
    enc[i] ^= xor_box_1[i]
print(b"antd3ctf{"+bytes(enc)+b"}")
```
Flag:
```antd3ctf{getting_primes_with_pipes_is_awesome}```

### Chal 4 - Supervisor
Lời đầu tiên: cảm ơn anh Mochi đã giao em 1 bài khó vcl để em làm, I hate you bro!
Tiếp đến là mình sẽ nói về hướng đi cho bài này. Một số điều chúng ta sẽ để ý trong challenge này đó là:
- Có 3 file tất cả: supervisor, crackme.enc và flag.enc
- File supervisor, crackme.enc đều là ELF 64bit, tức là chúng là file có thể thực thi, trong khi thằng flag.enc thì không
- Nếu điều tra kĩ thì ta sẽ thấy rằng crackme có chứa 1 số đoạn code bị lỗi không chạy được.

OK. Vậy thì đầu tiên ta sẽ tìm hiểu đôi chút về supervisor. Tuy nhiên để không làm mất thời gian (vì thực sự mình mất rất nhiều thời gian để làm được bài này), nên mình sẽ chỉ sơ lược những ý chính trong file, ngoài ra các đoạn code khác thì bạn có thể tự debug và tìm hiểu ý nghĩa (file bị stripped, nên bạn hãy coi đó là 1 challenge để cải thiện kĩ năng):
```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  signed int v4; // [rsp+1Ch] [rbp-4h]

  sub_11A5();
  v4 = fork();
  if ( v4 )
  {
    if ( v4 <= 0 )
      return 0xFFFFFFFFLL;
    tracing_child(v4);
  }
  else
  {
    laucnh_crackme("./crackme.enc");
  }
  return 0LL;
}
```
```c
int __fastcall launch_crackme(const char *a1)
{
  __int64 v1; // rax

  v1 = ptrace(PTRACE_TRACEME, 0LL, 0LL, 0LL);
  if ( v1 >= 0 )
    LODWORD(v1) = execl(a1, a1, 0LL);
  return v1;
}
```
Đây là đoạn main chính của supervisor, thì ta thấy rằng nó sẽ fork 1 process con, rồi với process con thì đầu tiên nó sẽ gọi ptrace ( ở đây ta có thể tạm hiểu là nó tự debug bản thân), rồi sau đó execl tới file crackme.enc => thằng process con ngăn chặn việc debug và gọi tới crackme, lúc này có thể coi process con thực chất là crackme.
Về phía process cha, mình sẽ nói sơ qua 1 số nhận định mà mình tìm được:
- Mình phát hiện trong code có chứa 1 số hàm ```ptrace(PTRACE_POKETEXT, ...)```, những đoạn này dùng để modify thằng process con tại 1 địa chỉ nào đó
- Thằng cha đợi tới khi nhận được SIGINT từ con (cái này có thể là int3 từ thằng con) rồi somehow sử dụng ```ptrace(PTRACE_PEEKTEXT,...)``` để lấy RIP của thằng con, lấy data, ... 
- Trong code có 2 section tương tự nhau, đều modify code của con, tuy nhiên mình cx ko hoàn toàn rõ là gì nên tạm thời bỏ qua
- Flow của nó sẽ là: đợi sigint => sửa code => set rip => chạy thằng con tiếp => đợi sigint => sửa code => ...
Đó là cơ bản về tracing_child của thằng cha. Và trong đầu mình có 1 số câu hỏi:
- Làm sao để debug thằng con?
- Dựa theo những điều trên thì thằng con bị sửa code, có cách nào để khôi phục lại crackme.enc ko?
- Liệu những điều này có liên quan gì đến flag?

Nếu như trước đây, ta hay sử dụng việc patch file, set register, ... để bypass các cơ chế anti debug hoặc các điều kiện thì bây giờ chúng ta không thể sử dụng technique đó nữa, lí do là vì:
- Chúng ta không thể modify , patch, set register lên thằng crackme vì cơ bản là nó cũng bị encrypt, chúng ta hoàn toàn không có 1 thông tin cụ thể nào về flow cũng như cách thức nó hoạt động
- Để debug được 1 file thì ta cần phải attach cái debugger. Việc attach vô supervisor là vô nghĩa vì crackme mới là thằng chạy thực sự, mà chúng ta lại không thể attach được ( crackme được spawn = việc fork process con và chạy execl), Ngoài ra, nó còn bồi thêm 1 cú nữa = ptrace chính cái process con đó, đảm bảo không có debugger nào khác có thể debug được process đó.
Và thực tế là, theo mình tìm hiểu được thì đây là 1 cái technique chống việc debug tên là nanomites (gg để rõ hơn). Tuy nhiên thì không hẳn là không có cách. Sau 1 thời gian mày mò tìm hiểu thì mình đã tìm ra cách để debug được. Nó liên quan tới 1 kĩ thuật hooking các hàm có trong thư viện, mình sẽ để (link)[https://tbrindus.ca/correct-ld-preload-hooking-libc/] để bạn có thể tìm hiểu thêm. Nó tận dụng được việc các shared library được load trước, cho phép overwrite lại 1 hàm nào đó ( ở đây thì ta sẽ overwrite theo hướng có lợi cho việc debug thôi).

Để debug được thì ta sẽ bám sát vào việc nó modify dòng code ở đâu, và set RIP ở đâu, điều này được thực hiện thông qua hàm ptrace ( đây là cách làm của mình, overwrite lại hàm ptrace - không hẳn là viết lại mà chỉ ghi ra các tham số được pass vào trong ptrace thôi và mình sẽ viết sao cho ptrace vẫn chạy như bth, ở đây ta sẽ quan tâm 2 thứ : addr và data)

Dưới đây là đoạn code mình overwrite ptrace:
```c
#include <stdio.h>
#include <sys/ptrace.h>
#include <stdarg.h>
#include <unistd.h>
#include <dlfcn.h>

long int ptrace(enum __ptrace_request __request, ...){
    pid_t caller = getpid();
    va_list list;
    va_start(list, __request);
    pid_t pid = va_arg(list, pid_t);
    void* addr = va_arg(list, void*);
    void* data = va_arg(list, void*);
    long int (*orig_ptrace)(enum __ptrace_request __request, pid_t pid, void *addr, void *data);
    orig_ptrace = dlsym(RTLD_NEXT, "ptrace");
    long int result = orig_ptrace(__request, pid, addr, data);
    if (__request == PTRACE_SETREGS){
        unsigned long rip = *((unsigned long*)data + 16) - 0x555555554000;
        //printf("SETREGS: rip: 0x%lx\n", rip);
        printf("0x%lx\n", rip);
    } else if (__request == PTRACE_POKETEXT){
       // printf("POKETEXT: (addr , data) = (0x%lx , 0x%lx)\n", (unsigned long)addr - 0x555555554000, (unsigned long)data);
        printf("(0x%lx , 0x%lx)\n", (unsigned long) addr -  0x555555554000, (unsigned long) data);
    }
    return result;
}
```
Compile nó lại với lệnh ```gcc -shared -fPIC -ldl -o ptrace_hook.so ptrace_hook.c``` . Nếu như bạn chưa biết thì lệnh này sẽ compile file ptrace_hook.c thành 1 thư viện, và ta sẽ đặt ```LD_PRELOAD=/path/to/ptrace_hook.so``` để có thể overwrite được ptrace. Hoặc có thể sử dụng pwntools để làm việc này, mình thì ưa thích pwntools vì nó support rất nhiều thứ, đông thời nên tắt aslr để không phải bận tâm gì nhiều tới random address (file run.py là file mà mình dùng để replace ptrace).

Sau khi chạy run.py thì console nó xuất ra những dòng này:
```
d4rkn19ht@LAPTOP-MGCICI75:/mnt/d/tai_lieu_h0c_tren_lop/thuchanh_ltht/btvn_day2/btvn_day2/Day 2/chal4/backup$ python3 run.py
[+] Starting local process './supervisor': pid 1047
[!] ASLR is disabled!
[*] Switching to interactive mode
(0x1800 , 0x45c748fffff84be8)
(0x1871 , 0x89e0458b48000000)
(0x18e5 , 0x1ebfffff7b5e8c7)
(0x1838 , 0x8948d8458b48c289)
(0x18a8 , 0x775fff883fffffd)
0x17f9
Hello there!
(0x16db , 0xe8c78948000009ab)
(0x174b , 0x8348008b48d8458b)
(0x17bd , 0x1ebfffff93de8c7)
(0x1712 , 0xe8c7894800000000)
(0x1781 , 0xf975e8c78948f845)
0x16d4
Error! https://www.youtube.com/watch?v=Khk6SEQ-K-k
0xCCya!
: No such process
[*] Got EOF while reading in interactive
$
```
Yes, chúng ta đã phát hiện ra những đoạn code bị modify. những dòng có 2 số thì bên trái là địa chỉ, bên phải là data bị modify, còn với dòng có 1 số, thì đó là địa chỉ RIP được set. Từ thông tin trên ta có thể patch lại crackme những đoạn bị encrypt. Với việc làm sao để xử lí set RIP, thì mình tìm thẳng tới địa chỉ xuất hiện int3 gần nhất, và patch từ chỗ đó tới đoạn địa chỉ RIP = các opcode "\x90", những opcode này tương ứng lệnh nop.

============> Speedrun time
Vì mình quá lười để giải thích những phần còn lại, nên mình sẽ tóm gọn những phần mình đã làm.

Trên thực tế, đoạn trên không phải là những chỗ duy nhất mà code bị modify, thực ra là còn nhiều nữa, tuy nhiên do process chưa chạy đến đoạn đó mà đã thoát ra nên mới không thấy những đoạn khác bị sửa. Và ngoài ra, thằng cha không nhũng decrypt thằng con, mà nó còn encrypt lại (idk men, chắc để an toàn thôi). Vậy nên cần phải lưu ý xem là cái nào là cái decrypt, cái nào là cái encrypt, nếu mà patch code lung tung( tức là patch toàn bộ ý), rất dễ khiến code bị sai. Sau khi xong thì mình phát hiện là process nó mở 1 file tên là ```secret_key```, nên mình tạo thêm file đó. Từ những điều trên, mình lặp lại quá trình: patch code => debug => phát hiện những đoạn code bị encrypt => lại sửa tiếp... Mình có up các đoạn code như: patch_crackme.py dùng để vá lại file, run.py dùng để chạy thằng supervisor nma overwrite ptrace, ptrace_hook.so là thư viện mình đã compile sẵn, key_recover.py dùng để recover lại key ban đầu của thằng secret_key, ...có thể sử dụng chúng để tham khảo thêm về cách làm của mình.

Sau khi ta chỉnh sửa xong và chạy thì sẽ xuất hiện 1 file png, đây là file flag cuối cùng.
Flag:```justCTF{Cr4ckm3s_are_0xCCiting}```

Sau đợt này thì mình học được khá nhiều technique hay: hook libc, fini_array, init_array, bypass anti debug, ... nma cái giá phải trả là đau lưng, mệt mỏi, thâm mắt (vì mình thức khá là khuya để làm) 🥲

Life of hacker is never that easy.

## Reference:

- https://www.apriorit.com/dev-blog/367-anti-reverse-engineering-protection-techniques-to-use-before-releasing-software
- https://linuxsecurity.com/features/anti-debugging-for-noobs-part-1
- https://www.codeproject.com/Articles/621236/Nanomite-and-Debug-Blocker-for-Linux-Applications
- https://tbrindus.ca/correct-ld-preload-hooking-libc/