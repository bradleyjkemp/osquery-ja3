# osquery-ja3
Experimental OSQuery extension to sniff TLS handshakes and extract JA3(S) signatures (https://github.com/salesforce/ja3).

Some example data loading some websites with Chrome:
```
osquery> select * from tls_handshake_signatures;
+------------+----------------------------------+----------------------------------+-------------------------------+
| time       | ja3                              | ja3s                             | sni                           |
+------------+----------------------------------+----------------------------------+-------------------------------+
| 1599070067 | 72e651a0ae22a56dce58aee7a76bd54d | f4febc55ea12b31ae17cfb7e614afda8 | github.com                    |
| 1599070070 | d92450adfb140ea336df325e92be825f | f4febc55ea12b31ae17cfb7e614afda8 | github.com                    |
| 1599070070 | 6a1641c228984ce2f40be634b6a9b271 | fcb2d4d0991292272fcb1e464eedfd43 | github.com                    |
| 1599070156 | 1ede5f3e560df8dcd133fdb0be056e96 | 7bee5c1d424b7e5f943b06983bb11422 | api.twitter.com               |
| 1599070213 | c1e1bbbb4a7e9163930b0abdb770cbfe | eb1d94daa7e0344597e756a1fb6e7054 | osquery.readthedocs.io        |
| 1599070214 | 4300f2c144da1e20dff85c88a2c6cbf8 | 2b0648ab686ee45e0e7c35fcfb0eea7e | cdnjs.cloudflare.com          |
| 1599070214 | f16cb3365396589d15ecf23109a6963e | eb1d94daa7e0344597e756a1fb6e7054 | assets.readthedocs.org        |
| 1599070214 | a0004ec2535a313192ab059c3508c362 | eb1d94daa7e0344597e756a1fb6e7054 | assets.readthedocs.org        |
| 1599070215 | b9ac34f8aec8490bb35f9e0c608f8718 | eb1d94daa7e0344597e756a1fb6e7054 | assets.readthedocs.org        |
+------------+----------------------------------+----------------------------------+-------------------------------+

```


## Usage

Compile a binary using:
```bash
go get github.com/bradleyjkemp/osquery-ja3
go build -o /your/output/file github.com/bradleyjkemp/osquery-ja3 
```

To test this out you can run:
```bash
osqueryi --extension /path/to/osquery-ja3
```

To use as an actual OSQuery extension, follow this guide: https://osquery.readthedocs.io/en/stable/deployment/extensions/#autoloading-extensions