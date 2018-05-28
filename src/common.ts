'use strict'
// **Github:** https://github.com/fidm/x509
//
// **License:** MIT

/**
 * BufferVisitor is a visit tool to manipulate buffer.
 */
export class BufferVisitor {
  start: number
  end: number
  readonly buf: Buffer
  constructor (buf: Buffer, start: number = 0, end: number = 0) {
    this.start = start
    this.end = end > start ? end : start
    this.buf = buf
  }

  /**
   * return the underlying buffer length
   */
  get length () {
    return this.buf.length
  }

  /**
   * Reset visitor' start and end value.
   * @param start
   * @param end
   */
  reset (start: number = 0, end: number = 0): this {
    this.start = start
    if (end >= this.start) {
      this.end = end
    } else if (this.end < this.start) {
      this.end = this.start
    }
    return this
  }

  /**
   * consume some bytes.
   * @param steps steps to walk
   */
  walk (steps: number): this {
    this.start = this.end
    this.end += steps
    return this
  }

  /**
   * The buffer should have remaining the "steps" of bytes to consume,
   * otherwise it will throw an error with given message.
   * @param steps steps to consume.
   * @param message message to throw.
   */
  mustHas (steps: number, message: string = 'Too few bytes to parse.'): this {
    const requested = this.end + steps
    if (requested > this.buf.length) {
      const error = new Error(message) as any
      error.available = this.buf.length
      error.requested = requested
      throw error
    }
    this.walk(0)
    return this
  }

  /**
   * Check the remaining bytes with bufferVisitor.mustHas method and then walk.
   * @param steps steps to consume.
   * @param message message to throw.
   */
  mustWalk (steps: number, message?: string): this {
    this.mustHas(steps, message)
    this.walk(steps)
    return this
  }
}
