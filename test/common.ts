'use strict'
// **Github:** https://github.com/fidm/asn1
//
// **License:** MIT

import { strictEqual } from 'assert'
import { suite, it } from 'tman'
import { BufferVisitor } from '../src/index'

suite('common', function () {
  it('BufferVisitor', function () {
    const bufv = new BufferVisitor(Buffer.allocUnsafe(10))
    strictEqual(bufv.start, 0)
    strictEqual(bufv.end, 0)
    bufv.walk(10)
    strictEqual(bufv.start, 0)
    strictEqual(bufv.end, 10)
    bufv.walk(100)
    strictEqual(bufv.start, 10)
    strictEqual(bufv.end, 110)
    bufv.reset(10)
    strictEqual(bufv.start, 10)
    strictEqual(bufv.end, 110)
    bufv.reset(20, 20)
    strictEqual(bufv.start, 20)
    strictEqual(bufv.end, 20)
    bufv.reset(0, 200)
    strictEqual(bufv.start, 0)
    strictEqual(bufv.end, 200)
    bufv.reset(0, 0)
    strictEqual(bufv.start, 0)
    strictEqual(bufv.end, 0)

    bufv.walk(1)
    bufv.walk(2)
    bufv.buf.writeUIntBE(0, bufv.start, bufv.end - bufv.start)
    bufv.walk(4)
    bufv.buf.writeUIntBE(0, bufv.start, bufv.end - bufv.start)
    bufv.reset()
    bufv.walk(3)
    bufv.walk(4)
    strictEqual(bufv.buf.readUIntBE(bufv.start, bufv.end - bufv.start), 0)
  })
})
