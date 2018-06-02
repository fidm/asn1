'use strict'
// **Github:** https://github.com/fidm/asn1
//
// **License:** MIT

import fs from 'fs'
import { strictEqual, ok, throws } from 'assert'
import { suite, it } from 'tman'
import { PEM } from '../src/index'

suite('PEM', function () {
  it('should work', function () {
    const crtData = fs.readFileSync('./test/cert/rootkey.pem')
    const pems = PEM.parse(crtData)
    strictEqual(pems.length, 1)
    strictEqual(pems[0].type, 'PRIVATE KEY')
    strictEqual(pems[0].procType, '')
    strictEqual(pems[0].getHeader('DEK-Info'), '')
    strictEqual(pems[0].toString(), crtData.toString())
    ok(pems[0].body instanceof Buffer)
  })

  it('should throw error if no block', function () {
    throws(() => PEM.parse(Buffer.alloc(0)))
  })

  it('should work for Mozilla\'s Root Certificates', function () {
    // https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt
    // https://github.com/agl/extract-nss-root-certs
    const crtData = fs.readFileSync('./test/cert/certdata.pem')
    const pems = PEM.parse(crtData)
    strictEqual(pems.length, 132)
    for (const pem of pems) {
      strictEqual(pem.type, 'CERTIFICATE')
    }
  })
})
