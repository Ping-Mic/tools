# Network

##### portknock.sh

Nmapでポートノッキングするスクリプト

ex) 12345 -> 8080 -> 80の順にノックする
```
./portknock.sh 12345 8080 80 example.com
```

##### showtcports.py

TCPパケットにおける全ての送信先/元ポートを表示

```
$ python showtcports.py ~/Documents/ctf/write-ups-2015/hackcon-2015/forensics/WatchMeSurfTheInternet/spying.pcapng 
WARNING: No route found for IPv6 destination :: (no default route?). This affects only IPv6
WARNING: PacketNGReader: Unparsed block type 4/#4
[*] src ports
192.168.64.148 [60331, 10102, 10108, 60254, 57229, 10052, 10054, 10058, 10032, 10073, 10074, 10117, 10115, 10116, 10077, 10097, 10100, 10101, 10089, 10111, 10117, 10087, 10097, 10116, 10099, 10104, 10077, 10101, 10083, 10117, 10114, 10102, 10084, 10104, 10101, 10073, 10110, 10116, 10101, 10114, 10110, 10101, 10116]
[*] dst ports
192.168.64.148 [80, 445, 445, 443, 443, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445, 445]
```


