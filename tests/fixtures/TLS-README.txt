The tls-md5-cert.pem / tls-test-key.pem pair is a synthetic localhost test key.
It was generated locally for the loopback TLS regression and has never been
used by a real service or account. It is deliberately MD5-signed with a 1024-bit
RSA key to reproduce the legacy school certificate compatibility requirement.
It is not the school's certificate or private key, and no fixture is trusted
or installed in the Windows certificate store.
