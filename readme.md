
# counteredvac

simple dll manual mapper for counter-strike 2 

This uses no shellcode.
Entry is called via thread hijacking



## Authors

- [@iraqichild](https://www.github.com/iraqichild)


## Demo

https://youtu.be/caWhkLoD0WU

## Injection

You must export in your dll a function called DllEntry.

It must have no return value.

Cleans sections + Pe Headers
