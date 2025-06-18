
# counteredvac

simple dll manual mapper for counter-strike 2 

This uses no shellcode.
Entry is called via thread hijacking

## Demo

https://youtu.be/caWhkLoD0WU

## Injection

You must export in your dll a function called DllEntry.

It must have no return value.

Cleans sections + Pe Headers

To inject drag your dll and make sure it's named "module.dll" and is in the same folder as the injector. 

Then run as admin while cs2 is running.
