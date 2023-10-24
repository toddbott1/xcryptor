DESCRIPTION {BYTES}

__DEK__
Tag+Version {0...3}, ESalt {4...11}, HMACSalt {12...19}, IV {20...35}, Encrypted256BitKey {data: 36...67 + cbcstarter: 68...83}, HMAC {84...115}

__NOTE, FILENAME, FILETYPE, FILEDATA__
Tag+Version {0...3}, IV {4...19), EncryptedData {data: 20...x + cbcstarter: (x+1)...(x+16)}, HMAC {end-32...end}
