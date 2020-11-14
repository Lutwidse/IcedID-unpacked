## What is IcedID
IcedID is the malware that stealing information from Mail, Browser, etc...<br>
In Japan, it spreading radically as a password-protected zip file sent from malicious e-mail nowadays and it contains .doc file which is using as MS Word macro.<br>
Also, there are two versions of the executable file.<br>
Fortunately, I could be able to dump the main process from one version by set a breakpoint to VirtualAlloc and VirtualProtect.<br>
If we looking into the first 4 bytes "4D 38 5A 90" it seems PE header of a packed file by aPLib.<br>
You can check it precisely in Exeinfo PE.<br>
Therefore it able to decompress with that.
### Analysis result
```cpp
// Might be steganography something
StringEncrypter((uint *)&local_8,CONCAT31((int3)(uint)extraout_EDX_00 >> 8),1),".png",local_12c + iVar1);
```
```cpp
// Strings used in simple encrypt algorithm
aeiuo
bcdfghjklmnpqrstvwxyz
abcedfikmnopsutw
```

#### 005A0000 Password
> infected

#### Sample
> https://bazaar.abuse.ch/sample/a4f244ea588a4d55a542fe9c8fc6875d8b494acf7c2b970d420ff3a537f023cd/

#### References
> https://blog.trendmicro.co.jp/archives/26656

> https://github.com/herrcore/aplib-ripper
