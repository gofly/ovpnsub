dev tun
proto tcp
remote <host> <port>
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verb 3
cipher AES-256-CBC
auth-nocache
allow-compression yes

<ca>
{{.CACert}}
</ca>

<cert>
{{.Cert}}
</cert>

<key>
{{.Key}}
</key>

key-direction 1
<tls-auth>
{{.TlsAuth}}
</tls-auth>