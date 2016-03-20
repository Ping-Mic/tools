# Android関係

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

