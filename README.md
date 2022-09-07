Usage:<br/> 
<pre>    WMIExec.exe [user] [password or hash] [remote host] [command to run]
    WMIExec.exe CORP\Batman IisBatman! 192.168.1.9 calc.exe
    WMIExec.exe CORP\Batman 560FD8166B98C70D4A4A7F14E5400172 192.168.1.9 calc.exe</pre>

Performs Win32_Process class derivation as detailed in https://www.cybereason.com/blog/wmi-lateral-movement-win32<br/>

Now also supports Pass-The-Hash<br/>
&nbsp;&nbsp;&nbsp;&nbsp;- autodetects if NTLM hash is used as the password and executes accordingly


Heavily borrowed from https://github.com/Kevin-Robertson/Invoke-TheHash