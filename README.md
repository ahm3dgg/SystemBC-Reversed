# Reverse Engineering SystemBC Proxy Malware

sha256: 2086ece64145022a260c7676e660e93d2a1be44a767a8233daa4f14d0125e0bd

This repo contains full decompilation of SystemBC Proxy Malware, it was just an excercise for
me in Code Reconstruction, C2 Emulation and Deobfuscation since also this sample was protected
by Themida.

The Repo contains:

    - SystemBC it self full decompilation of the sample by the hash above.

    - SystemBC-Emu: C2 Emulator just a Simple programmatic example on how the SystemBC Protocol can be used to proxy communication, its tested on `TestServer`, which is just a simple tcp echo server, but it doesn't show file downloads
    
    - ThemidaAPILocator: x64dbg to resolve APIs.

The obfuscation was actually simple, the api's are dynamically allocated and these regions contains
code that has bunch of junk, jumps and calls, until you reach the api, my solution was to simply follow
these jumps until I go out of the module, I did that statically though by decoding the instruction and
I did wrote an x64dbg plugin for that and its honestly not the best solution, as it was
done statically so it did fail some but was able to grab most of the APIs, I also did then write the
resolved APIs to a file, that I then loaded via an IDAPython script to continue analysis, kinda stupid.

However a friend of mine found this solution and I actually think is better as it steps through the instructions instead.

https://github.com/ElvisBlue/x64dbgpython/blob/main/example%20script/themida_iat_fixer_x86.py