'use strict'
// **Github:** https://github.com/fidm/asn1
//
// **License:** MIT

require('ts-node/register')

const fs = require('fs')
const { PEM, ASN1 } = require('../src/index')

const pems = PEM.parse(fs.readFileSync('./test/cert/github.crt'))

const asn1 = ASN1.fromDER(pems[0].body)
console.log(asn1)
