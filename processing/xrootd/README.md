# Adding XRootD monitoring capability
For now, you can:

1. Start the server with

        sudo -u xrootd xrootd -c /etc/xrootd/xrootd.cfg

1. Get the raw datagrams with

        netcat -l -k -u 127.0.0.1 8888 | xxd

1. We can also run the test now!

        go test -run TestRecv

1. Copy a sample file with

        xrdcp --force root://wn247148.ft.uam.es:1094//opt/xrootd/foo .
