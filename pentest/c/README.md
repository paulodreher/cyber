# Basic steps to compile C program


### ***All generated files***

Once you run the command bellow 

```
gcc -save-temps example.c -o example
```

It will generate 5 files:

- example.c (source code)
- example.i (pre-processing)
- example.s (assembly)
- example.o (object)
- example (binary)


### ***Identify used library*** 

```
ldd example
```


### ***Compiling (no temporary files)***

```
gcc example.c -o example
```




### ***Example of Deny of Service***

Compile

```
gcc -save-temps dos.c -o dos
```

Run

```
./dos <ip> <port>
```




### ***Example of Port Scan***

Compile

```
gcc -save-temps portscan.c -o portscan
```

Run

```
./portscan <ip>
```




### ***Example of DNS Resolver***

Compile

```
gcc -save-temps resolver.c -o resolver
```

Run

```
./resolver google.com.br subdomains.txt
```
