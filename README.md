# Usage demo

```
$ python ps_backup_decrypt.py --file-backup demo/file_backup.bin --aes-wrapping-key C3DD5F2E3F84C50EBDD59B1A5F1780D2
1 - Processing object with label 'myrsaprivatekey'...
  RSA private key.
  Modulus: dfc3c2004eb5de2ef49188b4be0174025289019e34c9e3533f3dcd28984804020c1015791c3eb04054fc119de12a5ad2647461a9992e699ad73acdf2334cf087
  Public exponent: d5db
  Private exponent: 4f627614a90c1c9aea4a3e878b2e46816f23cfd2e46ce90af199b546771fe753b1650574bc6e211a2204cc3aecdcbea63425bce9623ab203c67d20feb159b9d7
  Object with label 'myrsaprivatekey' stored to file 'key_1_myrsaprivatekey'
2 - Processing object with label 'myaeskey'...
  AES secret key.
  KCV: 11E810
  Object with label 'myaeskey' stored to file 'key_2_myaeskey'
```

# Compatibility

This program has been tested only with a backup file produced with Thales ProtectToolkit 5.9.1.
