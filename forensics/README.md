# Forensics

### Android

##### apkextract.sh

apkファイルをdex2jarする

```
./apkextract.sh apkfile
```

##### adb2tar.py

バックアップファイル(adb形式)のファイルをtarで展開する. 暗号化には非対応.

```
python adb2tar.py <adb file> | tar xvf -
```

##### tar2adb.py

tar形式のファイルをadbにする.

```
python tar2adb.py <tar file> > <adb file>
```

### stego

##### crack-stego.py

openstegoを使ってブルートフォースする

```
$ python2 crack-stego.py stego.png passwords.txt
[i] bruting all words in text file
[+] found bro!
Extracted file: secret.txt

Password: password
```

