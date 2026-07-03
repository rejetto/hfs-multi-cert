exports.version = 1.0
exports.apiRequired = 12.8 // api.onServer
exports.description = "Add secondary TLS certificates for SNI hostnames"
exports.repo = "rejetto/hfs-multi-cert"
exports.changelog = [
    { "version": 1.0, "message": "First version" }
]

exports.configDialog = { sx: { maxWidth: '90vw' } }

exports.config = {
    certificates: {
        type: 'array',
        defaultValue: [],
        helperText: "Additional certificates are selected by browser SNI hostname; HFS' certificate remains the fallback.",
        fields: {
            cert: { type: 'real_path', label: "Certificate", fileMask: '*.pem|*.crt|*.cer', $width: 2 },
            key: { type: 'real_path', label: "Private key", fileMask: '*.pem|*.key', $width: 2 },
        },
    },
}

const fs = require('fs')
const tls = require('tls')
const { X509Certificate } = require('crypto')

exports.init = api => {
    const httpsServers = new Set()
    let activeHostnames = new Set()

    api.onServer(server => {
        if (typeof server.addContext !== 'function') return
        httpsServers.add(server)
        server.on('close', () => httpsServers.delete(server))
        applyCertificates()
    })
    api.subscribeConfig('certificates', applyCertificates)

    function applyCertificates() {
        const errors = []
        const hostnames = new Set()
        for (const entry of api.getConfig('certificates') || []) {
            try {
                const loaded = loadCertificate(entry)
                for (const hostname of loaded.hostnames) {
                    hostnames.add(hostname)
                    for (const server of httpsServers)
                        server.addContext(hostname, loaded.context)
                }
            }
            catch (e) {
                errors.push(e.message || String(e))
            }
        }
        // node can replace SNI contexts but cannot remove them from a live server
        const removed = [...activeHostnames].filter(x => !hostnames.has(x))
        activeHostnames = hostnames
        const warning = removed.length && httpsServers.size
            ? `Removed hostnames stay active until HTTPS restarts: ${removed.join(', ')}`
            : ''
        api.setError([...errors, warning].filter(Boolean).join('\n'))
    }
}

function loadCertificate({ cert, key }) {
    if (!cert || !key)
        throw Error("certificate and private key are required")
    const certificate = fs.readFileSync(cert)
    const privateKey = fs.readFileSync(key)
    const names = getDnsNames(certificate)
    if (!names.length)
        throw Error(`no DNS names found in ${cert}`)
    return {
        hostnames: names,
        context: tls.createSecureContext({ cert: certificate, key: privateKey }),
    }
}

function getDnsNames(certificate) {
    const { subjectAltName } = new X509Certificate(certificate)
    return (subjectAltName || '')
        .split(/,\s*/)
        .map(x => /^DNS:(.+)$/.exec(x)?.[1]?.toLowerCase())
        .filter(Boolean)
}
