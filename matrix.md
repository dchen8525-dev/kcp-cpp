# Cross-language matrix

1 MiB echo per cell, 3 round(s), digest verified against an independent Python computation of the payload.

| direction | config | rounds | result | note |
| --- | --- | --- | --- | --- |
| cpp->go | none fec=0/0 | 3 | PASS | 10.8 MB/s |
| cpp->go | none fec=10/3 | 3 | PASS | 7.5 MB/s |
| cpp->go | aes fec=0/0 | 3 | PASS | 10.1 MB/s |
| cpp->go | aes fec=10/3 | 3 | PASS | 7.6 MB/s |
| cpp->go | aes-gcm fec=0/0 | 3 | PASS | 10.6 MB/s |
| cpp->go | aes-gcm fec=10/3 | 3 | PASS | 7.2 MB/s |
| cpp->go | salsa20 fec=0/0 | 3 | PASS | 10.5 MB/s |
| cpp->go | salsa20 fec=10/3 | 3 | PASS | 7.4 MB/s |
| go->cpp | none fec=0/0 | 3 | PASS | 9.8 MB/s |
| go->cpp | none fec=10/3 | 3 | PASS | 6.9 MB/s |
| go->cpp | aes fec=0/0 | 3 | PASS | 8.0 MB/s |
| go->cpp | aes fec=10/3 | 3 | PASS | 6.2 MB/s |
| go->cpp | aes-gcm fec=0/0 | 3 | PASS | 7.8 MB/s |
| go->cpp | aes-gcm fec=10/3 | 3 | PASS | 8.2 MB/s |
| go->cpp | salsa20 fec=0/0 | 3 | PASS | 9.1 MB/s |
| go->cpp | salsa20 fec=10/3 | 3 | PASS | 6.7 MB/s |
