# GDB Script showing the filtering based on ports when listing sockets.
# This script can be ran with:
#   $ gdb -x ss.gdb

# Define the executable to run. For us this is a locally compiled ss(8) with the `-g` flag so that
# debugging information's included in the binary. Compiling this version of ss(8) is as simple as
# cloning its repo and adding the `-g` option to the CFLGAS in the main Makefile.
file /path/to/ss/with/debug/info

# Set the necessary breakpoints up. We'll be looking at the functions where the socket filtering
# takes place. The function names are extracted from misc/ss.c (i.e. ss's source file). We'll also
# run some commands after stopping here...
break ss.c:1815
command
    echo Local variables\n
    info locals

    echo \nLet's show a's type...\n
    ptype a

    echo \n... and print the target port\n
    print a.port

    echo \nFunction arguments\n
    info args

    echo \nLet's show s' type...\n
    ptype s

    echo \n... and print the l(eft) port...\n
    print s.lport

    echo \n... and print the r(ight) port\n
    print s.rport

    echo \nLet's just continue running...\n
    continue
end

# We're ready to run! To generate traffic so that we actually get a socket we can run the
# the following in two different shells:
#   shell-1$ nc -k -l 5777
#   shell-2$ cat /dev/random | nc --source-port 2345 127.0.0.1 5777
echo Let's run the program!\n
run -emin -f inet dport 5777
