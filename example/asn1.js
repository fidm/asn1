'use strict'
// **Github:** https://github.com/fidm/asn1
//
// **License:** MIT

require('ts-node/register')

const fs = require('fs')
const { PEM, ASN1, Class, Tag } = require('../src/index')

const pems = PEM.parse(fs.readFileSync('./test/cert/github.crt'))
const asn1 = ASN1.fromDER(pems[0].body)
console.log(asn1)

// ASN.1 Template
const privateKeyValidator = {
  name: 'PrivateKeyInfo',
  class: Class.UNIVERSAL,
  tag: Tag.SEQUENCE,
  capture: 'privateKeyInfo',
  value: [{
    name: 'PrivateKeyInfo.Version',
    class: Class.UNIVERSAL,
    tag: Tag.INTEGER,
    capture: 'privateKeyVersion'
  }, {
    name: 'PrivateKeyInfo.AlgorithmIdentifier',
    class: Class.UNIVERSAL,
    tag: Tag.SEQUENCE,
    value: [{
      name: 'PrivateKeyAlgorithmIdentifier.algorithm',
      class: Class.UNIVERSAL,
      tag: Tag.OID,
      capture: 'privateKeyOID'
    }]
  }, {
    name: 'PrivateKeyInfo.PrivateKey',
    class: Class.UNIVERSAL,
    tag: Tag.OCTETSTRING,
    capture: 'privateKey'
  }]
}

const rootkey = PEM.parse(fs.readFileSync('./test/cert/rootkey.pem'))[0]
const captures = ASN1.parseDERWithTemplate(rootkey.body, privateKeyValidator)
console.log(captures)
