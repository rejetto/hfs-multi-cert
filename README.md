# hfs-multi-cert

HFS plugin to add secondary HTTPS certificates selected by SNI hostname.

Configure one or more certificate/private-key pairs. DNS hostnames are read from the certificate SANs, so you do not need to repeat them in the configuration.

HFS' own HTTPS certificate remains the fallback certificate. This plugin does not manage ACME/Let's Encrypt issuance or renewal.

HFS ~ HTTP File Server https://github.com/rejetto/hfs
