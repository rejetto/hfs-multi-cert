const assert = require('assert')
const { execFileSync } = require('child_process')
const { mkdtempSync } = require('fs')
const { tmpdir } = require('os')
const { join } = require('path')
const test = require('node:test')

const plugin = require('../dist/plugin')

test('registers SNI contexts from certificate DNS SANs', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hfs-multi-cert-'))
    const cert = join(dir, 'cert.pem')
    const key = join(dir, 'key.pem')
    execFileSync('openssl', [
        'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', key, '-out', cert, '-days', '1',
        '-subj', '/CN=ignored.example',
        '-addext', 'subjectAltName=DNS:minecraft.example.com,DNS:*.direct.example.com',
    ], { stdio: 'ignore' })

    const registered = []
    plugin.init({
        getConfig: () => [{ cert, key }],
        setError: error => assert.strictEqual(error, ''),
        subscribeConfig() {},
        onServer(cb) {
            cb({
                addContext: (hostname, context) => registered.push({ hostname, context }),
                on() {},
            })
        },
    })

    assert.deepStrictEqual(registered.map(x => x.hostname), [
        'minecraft.example.com',
        '*.direct.example.com',
    ])
    assert(registered.every(x => x.context))
})
