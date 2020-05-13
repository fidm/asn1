'use strict'
// **Github:** https://github.com/fidm/asn1
//
// **License:** MIT

import { inspect } from 'util'
import { BufferVisitor } from './common'

/**
 * Template is use to create schema of ASN.1 object for `asn1.validate` method.
 */
export interface Template {
  name: string
  class: Class
  tag: Tag | Tag[]
  optional?: boolean
  capture?: string
  value?: Template | Template[]
}

/**
 * Captures is use to capture sub objects from ASN.1 object for `asn1.validate` method.
 */
export interface Captures {
  [index: string]: ASN1
}

/**
 * ASN.1 classes.
 */
export enum Class {
  UNIVERSAL = 0x00,
  APPLICATION = 0x40,
  CONTEXT_SPECIFIC = 0x80,
  PRIVATE = 0xC0,
}

/**
 * ASN.1 types. Not all types are supported by this implementation.
 */
export enum Tag {
  NONE = 0,
  BOOLEAN = 1,
  INTEGER = 2,
  BITSTRING = 3,
  OCTETSTRING = 4,
  NULL = 5,
  OID = 6,
  // ODESC = 7,
  // EXTERNAL = 8,
  // REAL = 9,
  ENUMERATED = 10,
  // EMBEDDED = 11,
  UTF8 = 12,
  // ROID = 13,
  SEQUENCE = 16,
  SET = 17,
  NUMERICSTRING = 18,
  PRINTABLESTRING = 19,
  T61STRING = 20,
  IA5STRING = 22,
  UTCTIME = 23,
  GENERALIZEDTIME = 24,
  GENERALSTRING = 27,
}

/**
 * BitString is the structure to use when you want an ASN.1 BIT STRING type. A
 * bit string is padded up to the nearest byte in memory and the number of
 * valid bits is recorded. Padding bits will be zero.
 */
export class BitString {
  /**
   * The underlying buffer
   */
  readonly buf: Buffer

  /**
   * The length of bits
   */
  readonly bitLen: number
  constructor (buf: Buffer, bitLen: number) {
    this.buf = buf
    this.bitLen = bitLen
  }

  /**
   * Returns the value for the given bits offset.
   * @param i bits offet
   */
  at (i: number): number {
    if (i < 0 || i >= this.bitLen || !Number.isInteger(i)) {
      return 0
    }
    const x = Math.floor(i / 8)
    const y = 7 - i % 8
    return (this.buf[x] >> y) & 1
  }

  /**
   * Align buffer
   */
  rightAlign (): Buffer {
    const shift = 8 - (this.bitLen % 8)
    if (shift === 8 || this.buf.length === 0) {
      return this.buf
    }

    const buf = Buffer.alloc(this.buf.length)
    buf[0] = this.buf[0] >> shift
    for (let i = 1; i < this.buf.length; i++) {
      buf[i] = this.buf[i - 1] << (8 - shift)
      buf[i] |= this.buf[i] >> shift
    }
    return buf
  }
}

/**
 * Implements parsing of DER-encoded ASN.1 data structures,
 * as defined in ITU-T Rec X.690.
 *
 * See also ``A Layman's Guide to a Subset of ASN.1, BER, and DER,''
 * http://luca.ntop.org/Teaching/Appunti/asn1.html.
 *
 * ASN.1 is a syntax for specifying abstract objects and BER, DER, PER, XER etc
 * are different encoding formats for those objects. Here, we'll be dealing
 * with DER, the Distinguished Encoding Rules. DER is used in X.509 because
 * it's fast to parse and, unlike BER, has a unique encoding for every object.
 * When calculating hashes over objects, it's important that the resulting
 * bytes be the same at both ends and DER removes this margin of error.
 * ASN.1 is very complex and this package doesn't attempt to implement
 * everything by any means.
 *
 * DER Encoding of ASN.1 Types:
 * https://msdn.microsoft.com/en-us/library/windows/desktop/bb540792(v=vs.85).aspx
 */
export class ASN1 {

  /**
   * Creates a Tag.BOOLEAN ASN.1 object.
   * @param val boolean value.
   */
  static Bool (val: boolean): ASN1 {
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.BOOLEAN, Buffer.from([val ? 0xff : 0x0]))
    asn1._value = val
    return asn1
  }

  /**
   * Parse a Tag.BOOLEAN value from ASN.1 object' value.
   * @param buf the buffer to parse.
   */
  static parseBool (buf: Buffer): boolean {
    if (!(buf instanceof Buffer) || buf.length !== 1) {
      throw new Error('ASN1 syntax error: invalid boolean')
    }
    switch (buf[0]) {
    case 0:
      return false
    case 0xff:
      return true
    default:
      throw new Error('ASN1 syntax error: invalid boolean')
    }
  }

  /**
   * Creates a Tag.INTEGER ASN.1 object.
   * @param val integer value or buffer.
   */
  static Integer (val: number | Buffer): ASN1 {
    if (val instanceof Buffer) {
      const asn = new ASN1(Class.UNIVERSAL, Tag.INTEGER, val)
      asn._value = val.toString('hex')
      return asn
    }

    if (!Number.isSafeInteger(val)) {
      throw new Error('ASN1 syntax error: invalid integer')
    }
    let buf
    if (val >= -0x80 && val < 0x80) {
      buf = Buffer.alloc(1)
      buf.writeInt8(val, 0)
    } else if (val >= -0x8000 && val < 0x8000) {
      buf = Buffer.alloc(2)
      buf.writeIntBE(val, 0, 2)
    } else if (val >= -0x800000 && val < 0x800000) {
      buf = Buffer.alloc(3)
      buf.writeIntBE(val, 0, 3)
    } else if (val >= -0x80000000 && val < 0x80000000) {
      buf = Buffer.alloc(4)
      buf.writeIntBE(val, 0, 4)
    } else if (val >= -0x8000000000 && val < 0x8000000000) {
      buf = Buffer.alloc(5)
      buf.writeIntBE(val, 0, 5)
    } else if (val >= -0x800000000000 && val < 0x800000000000) {
      buf = Buffer.alloc(6)
      buf.writeIntBE(val, 0, 6)
    } else {
      throw new Error('ASN1 syntax error: invalid Integer')
    }
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.INTEGER, buf)
    asn1._value = val
    return asn1
  }

  /**
   * Parse a Tag.INTEGER value from ASN.1 object' value.
   * @param buf the buffer to parse.
   */
  static parseInteger (buf: Buffer): number | string {
    if (!(buf instanceof Buffer) || buf.length === 0) {
      throw new Error('ASN1 syntax error: invalid Integer')
    }
    // some INTEGER (BigInt) will be 16 bytes, 32 bytes or others.
    // CertificateSerialNumber ::= INTEGER (>= 16 bytes)
    if (buf.length > 6) {
      return buf.toString('hex')
    }
    return buf.readIntBE(0, buf.length)
  }

  /**
   * Parse a Tag.INTEGER value as a number from ASN.1 object' value.
   * @param buf the buffer to parse.
   */
  static parseIntegerNum (buf: Buffer): number {
    const value = ASN1.parseInteger(buf)
    if (typeof value !== 'number') {
      throw new Error('ASN1 syntax error: invalid Integer number')
    }
    return value as number
  }

  /**
   * Parse a Tag.INTEGER value as a hex string(for BigInt) from ASN.1 object' value.
   * @param buf the buffer to parse.
   */
  static parseIntegerStr (buf: Buffer): string {
    const value = ASN1.parseInteger(buf)
    if (typeof value === 'number') {
      return value.toString(16)
    }
    return value as string
  }

  /**
   * Creates a Tag.BITSTRING ASN.1 object.
   * @param val BitString object or buffer.
   */
  static BitString (val: BitString | Buffer): ASN1 {
    if (val instanceof Buffer) {
      val = new BitString(val, val.length * 8)
    }
    const paddingBits = val.buf.length * 8 - val.bitLen
    const buf = Buffer.alloc(val.buf.length + 1)
    buf.writeInt8(paddingBits, 0)
    val.buf.copy(buf, 1)
    return new ASN1(Class.UNIVERSAL, Tag.BITSTRING, buf)
  }

  /**
   * Parse a Tag.BITSTRING value from ASN.1 object' value.
   * @param buf the buffer to parse.
   */
  static parseBitString (buf: Buffer): BitString {
    if (!(buf instanceof Buffer) || buf.length === 0) {
      throw new Error('ASN1 syntax error: invalid BitString')
    }

    const paddingBits = buf[0]
    if (paddingBits > 7 ||
      buf.length === 1 && paddingBits > 0 ||
      (buf[buf.length - 1] & ((1 << buf[0]) - 1)) !== 0) {
      throw new Error('ASN1 syntax error: invalid padding bits in BIT STRING')
    }

    return new BitString(buf.slice(1), (buf.length - 1) * 8 - paddingBits)
  }

  /**
   * Creates a Tag.NULL ASN.1 object.
   */
  static Null (): ASN1 {
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.NULL, Buffer.alloc(0))
    asn1._value = null
    return asn1
  }

  /**
   * Parse a Tag.NULL value from ASN.1 object' value.
   * @param buf the buffer to parse.
   */
  static parseNull (buf: Buffer): null {
    if (!(buf instanceof Buffer) || buf.length !== 0) {
      throw new Error('ASN1 syntax error: invalid null')
    }
    return null
  }

  /**
   * Creates an Tag.OID (dot-separated numeric string) ASN.1 object.
   * @param val dot-separated numeric string.
   */
  static OID (val: string): ASN1 {
    const values = val.split('.')
    if (values.length === 0) {
      throw new Error('ASN1 syntax error: invalid Object Identifier')
    }
    const bytes: number[] = []

    // first byte is 40 * value1 + value2
    bytes.push(40 * mustParseInt(values[0]) + mustParseInt(values[1]))
    // other bytes are each value in base 128 with 8th bit set except for
    // the last byte for each value
    const valueBytes = []
    for (let i = 2; i < values.length; ++i) {
      let value = mustParseInt(values[i])
      valueBytes.length = 0
      valueBytes.push(value & 0x7f)
      while (value > 0x7f) {
        value = value >>> 7
        valueBytes.unshift((value & 0x7f) | 0x80) // add value bytes in reverse for big endian
      }

      bytes.push(...valueBytes)
    }

    const asn1 = new ASN1(Class.UNIVERSAL, Tag.OID, Buffer.from(bytes))
    asn1._value = val
    return asn1
  }

  /**
   * Parse a Tag.OID value from ASN.1 object' value.
   * @param buf the buffer to parse.
   */
  static parseOID (buf: Buffer): string {
    if (!(buf instanceof Buffer) || buf.length === 0) {
      throw new Error('ASN1 syntax error: invalid OID')
    }
    // first byte is 40 * value1 + value2
    let oid = Math.floor(buf[0] / 40) + '.' + (buf[0] % 40)

    // other bytes are each value in base 128 with 8th bit set except for
    // the last byte for each value
    let high = 0
    for (let i = 1; i < buf.length; i++) {
      // not the last byte for the value
      if (buf[i] >= 0x80) {
        high += buf[i] & 0x7F
        high = high << 7
      } else {
        oid += '.' + (high + buf[i])
        high = 0
      }
    }

    return oid
  }

  /**
   * Creates an Tag.UTF8 ASN.1 object.
   * @param val utf8 string.
   */
  static UTF8 (val: string): ASN1 {
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.UTF8, Buffer.from(val, 'utf8'))
    asn1._value = val
    return asn1
  }

  /**
   * Parse a Tag.UTF8 string from ASN.1 object' value.
   * @param buf the buffer to parse.
   */
  static parseUTF8 (buf: Buffer): string {
    if (!(buf instanceof Buffer)) {
      throw new Error('parse ASN1 error: invalid Buffer')
    }
    return buf.toString('utf8')
  }

  /**
   * Creates an Tag.NUMERICSTRING ASN.1 object.
   * @param val numeric string.
   */
  static NumericString (val: string): ASN1 {
    if (!isNumericString(val)) {
      throw new Error('ASN1 syntax error: invalid NumericString')
    }
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.NUMERICSTRING, Buffer.from(val, 'utf8'))
    asn1._value = val
    return asn1
  }

  /**
   * Parse a Tag.UTF8 string from ASN.1 object' value.
   * @param buf the buffer to parse.
   */
  static parseNumericString (buf: Buffer): string {
    if (!(buf instanceof Buffer)) {
      throw new Error('parse ASN1 error: invalid Buffer')
    }
    const str = buf.toString('utf8')
    if (!isNumericString(str)) {
      throw new Error('ASN1 syntax error: invalid NumericString')
    }
    return str
  }

  /**
   * Creates an Tag.NUMERICSTRING ASN.1 object.
   * @param val printable string.
   */
  static PrintableString (val: string): ASN1 {
    // TODO, validate
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.PRINTABLESTRING, Buffer.from(val, 'utf8'))
    asn1._value = val
    return asn1
  }

  /**
   * Parse a Tag.PRINTABLESTRING string from ASN.1 object' value.
   * @param buf the buffer to parse.
   */
  static parsePrintableString (buf: Buffer): string {
    if (!(buf instanceof Buffer)) {
      throw new Error('parse ASN1 error: invalid Buffer')
    }
    // TODO, validate
    return buf.toString('utf8')
  }

  /**
   * Creates an Tag.IA5STRING (ASCII string) ASN.1 object.
   * @param val ASCII string.
   */
  static IA5String (val: string): ASN1 {
    if (!isIA5String(val)) {
      throw new Error('ASN1 syntax error: invalid IA5String')
    }
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.IA5STRING, Buffer.from(val, 'utf8'))
    asn1._value = val
    return asn1
  }

  /**
   * Parse a Tag.IA5STRING string from ASN.1 object' value.
   * @param buf the buffer to parse.
   */
  static parseIA5String (buf: Buffer): string {
    if (!(buf instanceof Buffer)) {
      throw new Error('parse ASN1 error: invalid Buffer')
    }
    const str = buf.toString('utf8')
    if (!isIA5String(str)) {
      throw new Error('ASN1 syntax error: invalid IA5String')
    }
    return str
  }

  /**
   * Creates an Tag.T61STRING (8-bit clean string) ASN.1 object.
   * @param val 8-bit clean string.
   */
  static T61String (val: string): ASN1 {
    // TODO, validate
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.T61STRING, Buffer.from(val, 'utf8'))
    asn1._value = val
    return asn1
  }

  /**
   * Parse a Tag.T61STRING string from ASN.1 object' value.
   * @param buf the buffer to parse.
   */
  static parseT61String (buf: Buffer): string {
    if (!(buf instanceof Buffer)) {
      throw new Error('parse ASN1 error: invalid Buffer')
    }
    // TODO, validate
    return buf.toString('utf8')
  }

  /**
   * Creates an Tag.GENERALSTRING (specified in ISO-2022/ECMA-35) ASN.1 object.
   * @param val general string.
   */
  static GeneralString (val: string): ASN1 {
    // TODO, validate
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.GENERALSTRING, Buffer.from(val, 'utf8'))
    asn1._value = val
    return asn1
  }

  /**
   * Parse a Tag.GENERALSTRING string from ASN.1 object' value.
   * @param buf the buffer to parse.
   */
  static parseGeneralString (buf: Buffer): string {
    if (!(buf instanceof Buffer)) {
      throw new Error('parse ASN1 error: invalid Buffer')
    }
    // TODO, validate
    return buf.toString('utf8')
  }

  /**
   * Creates an Tag.UTCTIME ASN.1 object.
   *
   * Note: GeneralizedTime has 4 digits for the year and is used for X.509.
   * dates past 2049. Converting to a GeneralizedTime hasn't been implemented yet.
   * @param date date value.
   */
  static UTCTime (date: Date): ASN1 {
    let rval = ''

    // create format YYMMDDhhmmssZ
    const format = []
    format.push(('' + date.getUTCFullYear()).substr(2))
    format.push('' + (date.getUTCMonth() + 1))
    format.push('' + date.getUTCDate())
    format.push('' + date.getUTCHours())
    format.push('' + date.getUTCMinutes())
    format.push('' + date.getUTCSeconds())

    // ensure 2 digits are used for each format entry
    for (const s of format) {
      if (s.length < 2) {
        rval += '0'
      }
      rval += s
    }
    rval += 'Z'
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.UTCTIME, Buffer.from(rval, 'utf8'))
    asn1._value = date
    return asn1
  }

  /**
   * Parse a Tag.UTCTIME date from ASN.1 object' value.
   * @param buf the buffer to parse.
   */
  static parseUTCTime (buf: Buffer): Date {
    if (!(buf instanceof Buffer) || buf.length === 0) {
      throw new Error('ASN1 syntax error: invalid UTC Time')
    }
    const utc = buf.toString('utf8')
    /* The following formats can be used:

      YYMMDDhhmmZ
      YYMMDDhhmm+hh'mm'
      YYMMDDhhmm-hh'mm'
      YYMMDDhhmmssZ
      YYMMDDhhmmss+hh'mm'
      YYMMDDhhmmss-hh'mm'

      Where:

      YY is the least significant two digits of the year
      MM is the month (01 to 12)
      DD is the day (01 to 31)
      hh is the hour (00 to 23)
      mm are the minutes (00 to 59)
      ss are the seconds (00 to 59)
      Z indicates that local time is GMT, + indicates that local time is
      later than GMT, and - indicates that local time is earlier than GMT
      hh' is the absolute value of the offset from GMT in hours
      mm' is the absolute value of the offset from GMT in minutes */
    const date = new Date()

    // if YY >= 50 use 19xx, if YY < 50 use 20xx
    let year = mustParseInt(utc.substr(0, 2))
    year = (year >= 50) ? 1900 + year : 2000 + year
    const MM = mustParseInt(utc.substr(2, 2)) - 1 // use 0-11 for month
    const DD = mustParseInt(utc.substr(4, 2))
    const hh = mustParseInt(utc.substr(6, 2))
    const mm = mustParseInt(utc.substr(8, 2))
    let ss = 0

    let end = 0
    // get character after minutes
    let c = ''
    // not just YYMMDDhhmmZ
    if (utc.length > 11) {
      end = 10
      // get character after minutes
      c = utc.charAt(end)
      // see if seconds are present
      if (c !== '+' && c !== '-') {
        // get seconds
        ss = mustParseInt(utc.substr(10, 2))
        end += 2
      }
    }

    // update date
    date.setUTCFullYear(year, MM, DD)
    date.setUTCHours(hh, mm, ss, 0)

    if (end > 0) {
      // get +/- after end of time
      c = utc.charAt(end)
      if (c === '+' || c === '-') {
        // get hours+minutes offset
        const hhoffset = mustParseInt(utc.substr(end + 1, 2))
        const mmoffset = mustParseInt(utc.substr(end + 4, 2))

        // calculate offset in milliseconds
        let offset = hhoffset * 60 + mmoffset
        offset *= 60000

        // apply offset
        if (c === '+') {
          date.setTime(+date - offset)
        } else {
          date.setTime(+date + offset)
        }
      }
    }

    return date
  }

  /**
   * Creates an Tag.GENERALIZEDTIME ASN.1 object.
   * @param date date value.
   */
  static GeneralizedTime (date: Date): ASN1 {
    let rval = ''

    // create format YYYYMMDDHHMMSSZ
    const format = []
    format.push('' + date.getUTCFullYear())
    format.push('' + (date.getUTCMonth() + 1))
    format.push('' + date.getUTCDate())
    format.push('' + date.getUTCHours())
    format.push('' + date.getUTCMinutes())
    format.push('' + date.getUTCSeconds())

    // ensure 2 digits are used for each format entry
    for (const s of format) {
      if (s.length < 2) {
        rval += '0'
      }
      rval += s
    }
    rval += 'Z'
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.GENERALIZEDTIME, Buffer.from(rval, 'utf8'))
    asn1._value = date
    return asn1
  }

  /**
   * Parse a Tag.GENERALIZEDTIME date from ASN.1 object' value.
   * @param buf the buffer to parse.
   */
  static parseGeneralizedTime (buf: Buffer): Date {
    if (!(buf instanceof Buffer) || buf.length === 0) {
      throw new Error('ASN1 syntax error: invalid Generalized Time')
    }
    const gentime = buf.toString('utf8')
    /* The following formats can be used:

      YYYYMMDDHHMMSS
      YYYYMMDDHHMMSS.fff
      YYYYMMDDHHMMSSZ
      YYYYMMDDHHMMSS.fffZ
      YYYYMMDDHHMMSS+hh'mm'
      YYYYMMDDHHMMSS.fff+hh'mm'
      YYYYMMDDHHMMSS-hh'mm'
      YYYYMMDDHHMMSS.fff-hh'mm'

      Where:

      YYYY is the year
      MM is the month (01 to 12)
      DD is the day (01 to 31)
      hh is the hour (00 to 23)
      mm are the minutes (00 to 59)
      ss are the seconds (00 to 59)
      .fff is the second fraction, accurate to three decimal places
      Z indicates that local time is GMT, + indicates that local time is
      later than GMT, and - indicates that local time is earlier than GMT
      hh' is the absolute value of the offset from GMT in hours
      mm' is the absolute value of the offset from GMT in minutes */
    const date = new Date()

    const YYYY = mustParseInt(gentime.substr(0, 4))
    const MM = mustParseInt(gentime.substr(4, 2)) - 1 // use 0-11 for month
    const DD = mustParseInt(gentime.substr(6, 2))
    const hh = mustParseInt(gentime.substr(8, 2))
    const mm = mustParseInt(gentime.substr(10, 2))
    const ss = mustParseInt(gentime.substr(12, 2))
    let fff = 0
    let offset = 0
    let isUTC = false

    if (gentime.charAt(gentime.length - 1) === 'Z') {
      isUTC = true
    }

    const end = gentime.length - 5
    const c = gentime.charAt(end)
    if (c === '+' || c === '-') {
      // get hours+minutes offset
      const hhoffset = mustParseInt(gentime.substr(end + 1, 2))
      const mmoffset = mustParseInt(gentime.substr(end + 4, 2))

      // calculate offset in milliseconds
      offset = hhoffset * 60 + mmoffset
      offset *= 60000

      // apply offset
      if (c === '+') {
        offset *= -1
      }

      isUTC = true
    }

    // check for second fraction
    if (gentime.charAt(14) === '.') {
      fff = parseFloat(gentime.substr(14)) * 1000
    }

    if (isUTC) {
      date.setUTCFullYear(YYYY, MM, DD)
      date.setUTCHours(hh, mm, ss, fff)
      // apply offset
      date.setTime(+date + offset)
    } else {
      date.setFullYear(YYYY, MM, DD)
      date.setHours(hh, mm, ss, fff)
    }

    return date
  }

  /**
   * Parse a Tag.UTCTIME date of Tag.GENERALIZEDTIME date from ASN.1 object' value.
   * @param tag the type.
   * @param buf the buffer to parse.
   */
  static parseTime (tag: Tag, buf: Buffer): Date {
    switch (tag) {
    case Tag.UTCTIME:
      return ASN1.parseUTCTime(buf)
    case Tag.GENERALIZEDTIME:
      return ASN1.parseGeneralizedTime(buf)
    default:
      throw new Error('Invalid ASN1 time tag')
    }
  }

  /**
   * Creates an Tag.SET ASN.1 object.
   * @param objs an array of ASN.1 objects.
   */
  static Set (objs: ASN1[]): ASN1 {
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.SET, Buffer.concat(objs.map((obj) => obj.toDER())))
    asn1._value = objs
    return asn1
  }

  /**
   * Creates an Tag.SEQUENCE ASN.1 object.
   * @param objs an array of ASN.1 objects.
   */
  static Seq (objs: ASN1[]): ASN1 {
    const asn1 = new ASN1(Class.UNIVERSAL, Tag.SEQUENCE,
      Buffer.concat(objs.map((obj) => obj.toDER())))
    asn1._value = objs
    return asn1
  }

  /**
   * Creates an Class.CONTEXT_SPECIFIC ASN.1 object.
   *
   * Note: the tag means nothing with Class.CONTEXT_SPECIFIC
   * @param tag number.
   * @param objs an array of ASN.1 objects or a ASN.1 object.
   * @param isCompound when objs is a array, the isCompound will be set to true.
   */
  static Spec (tag: Tag, objs: ASN1 | ASN1[], isCompound: boolean = true): ASN1 {
    const bytes = Array.isArray(objs) ? Buffer.concat(objs.map((obj) => obj.toDER())) : objs.toDER()
    if (Array.isArray(objs)) {
      isCompound = true
    }
    const asn1 = new ASN1(Class.CONTEXT_SPECIFIC, tag, bytes, isCompound)
    asn1._value = objs
    return asn1
  }

  /**
   * Parse a ASN.1 object from a buffer in DER format.
   *
   * @param buf the buffer to parse.
   * @param deepParse deeply parse or not.
   */
  static fromDER (buf: Buffer, deepParse: boolean = false): ASN1 {
    return ASN1._fromDER(new BufferVisitor(buf), deepParse)
  }

  /**
   * Parse a ASN.1 object from a buffer in DER format with given class and tag.
   * If class or tag is not match, it will throw a error.
   *
   * @param tagClass expect class to parse.
   * @param tag expect type to parse.
   * @param buf the buffer to parse.
   */
  static parseDER (buf: Buffer, tagClass: Class, tag: Tag): ASN1 {
    const obj = ASN1._fromDER(new BufferVisitor(buf), false)
    if (obj.class !== tagClass && obj.tag !== tag) {
      throw new Error(`invalid ASN.1 DER for class ${tagClass} and tag ${tag}`)
    }
    return obj
  }

  /**
   * Parse a ASN.1 object from a buffer in DER format with given Template object.
   * If template is not match, it will throw a error.
   *
   * @param buf the buffer to parse.
   * @param tpl expect template to parse.
   *
   * @return a Captures object with captured ASN.1 objects
   */
  static parseDERWithTemplate (buf: Buffer, tpl: Template): Captures {
    const obj = ASN1._fromDER(new BufferVisitor(buf), true)
    const captures: Captures = {}
    const err = obj.validate(tpl, captures) as any
    if (err != null) {
      err.data = obj
      throw err
    }
    return captures
  }

  private static _parseCompound (buf: Buffer, deepParse: boolean): ASN1[] {
    const values = []
    const len = buf.length
    const bufv = new BufferVisitor(buf)
    let readByteLen = 0
    while (readByteLen < len) {
      const start = bufv.end
      values.push(ASN1._fromDER(bufv, deepParse))
      readByteLen += bufv.end - start
    }
    return values
  }

  // Internal function to parse an asn1 object from a byte buffer in DER format.
  private static _fromDER (bufv: BufferVisitor, deepParse: boolean): ASN1 {
    if (!(bufv.buf instanceof Buffer) || bufv.length === 0) {
      throw new Error('ASN1 syntax error: invalid Generalized Time')
    }
    bufv.mustWalk(1, 'Too few bytes to read ASN.1 tag.')

    const start = bufv.start
    const b1 = bufv.buf[start]
    const tagClass = b1 & 0xc0
    const tag = b1 & 0x1f

    // value storage
    const valueLen = getValueLength(bufv)
    bufv.mustHas(valueLen)
    if (valueLen !== 0 && tag === Tag.NULL) {
      throw new Error('invalid value length or NULL tag.')
    }

    bufv.mustWalk(valueLen)
    const isCompound = ((b1 & 0x20) === 0x20)
    const asn1 = new ASN1(tagClass, tag, bufv.buf.slice(bufv.start, bufv.end), isCompound)
    if (isCompound && deepParse) {
      asn1._value = ASN1._parseCompound(asn1.bytes, deepParse)
    }
    asn1._der = bufv.buf.slice(start, bufv.end)
    return asn1
  }

  readonly class: Class
  readonly tag: Tag
  readonly bytes: Buffer
  readonly isCompound: boolean
  private _value: any
  private _der: Buffer | null
  constructor (tagClass: Class, tag: Tag, data: Buffer, isCompound: boolean = false) {
    this.class = tagClass
    this.tag = tag
    this.bytes = data
    // CONTEXT_SPECIFIC, SEQUENCE, SET, others...
    this.isCompound = isCompound || tag === Tag.SEQUENCE || tag === Tag.SET
    this._value = undefined
    this._der = null
  }

  /**
   * the well parsed value of this ASN.1 object.
   * It will be boolean, number, string, BitString, Date, array of ASN.1 objects and so on.
   */
  get value (): any {
    if (this._value === undefined) {
      this._value = this.valueOf()
    }
    return this._value
  }

  /**
   * the DER format Buffer of this ASN.1 object.
   */
  get DER (): Buffer {
    if (this._der == null) {
      this._der = this.toDER()
    }
    return this._der
  }

  /**
   * Expecting it is compound ASN.1 object and returns an array of sub ASN.1 objects.
   * @param msg error message to throw when it is not compound ASN.1 object.
   */
  mustCompound (msg: string = 'asn1 object value is not compound'): ASN1[] {
    if (!this.isCompound || !Array.isArray(this.value)) {
      const err = new Error(msg) as any
      err.data = this.toJSON()
      throw err
    }
    return this.value as ASN1[]
  }

  /**
   * Returns true if two ASN.1 objects equally.
   * @param obj another ASN.1 object.
   */
  equals (obj: ASN1): boolean {
    if (!(obj instanceof ASN1)) {
      return false
    }
    if (this.class !== obj.class || this.tag !== obj.tag || this.isCompound !== obj.isCompound) {
      return false
    }
    if (!this.bytes.equals(obj.bytes)) {
      return false
    }
    return true
  }

  /**
   * Converts this ASN.1 object to a buffer of bytes in DER format.
   */
  toDER (): Buffer {
    // build the first byte
    let b1 = this.class | this.tag
    if (this.isCompound) {
      b1 |= 0x20
    }

    const valueLenBytes = getValueLengthByte(this.bytes.length)
    const buf = Buffer.allocUnsafe(2 + valueLenBytes + this.bytes.length)
    buf.writeUInt8(b1, 0)
    if (valueLenBytes === 0) {
      buf.writeUInt8(this.bytes.length, 1)
      this.bytes.copy(buf, 2)
    } else {
      buf.writeUInt8(valueLenBytes | 0x80, 1)
      buf.writeUIntBE(this.bytes.length, 2, valueLenBytes)
      this.bytes.copy(buf, 2 + valueLenBytes)
    }

    return buf
  }

  /**
   * Parse the value of this ASN.1 object when it is Class.UNIVERSAL.
   * The value will be boolean, number, string, BitString, Date, array of ASN.1 objects and so on.
   */
  valueOf (): any {
    if (this.isCompound) {
      return ASN1._parseCompound(this.bytes, false)
    }

    if (this.class !== Class.UNIVERSAL) {
      return this.bytes
    }

    switch (this.tag) {
    case Tag.BOOLEAN:
      return ASN1.parseBool(this.bytes)
    case Tag.INTEGER:
      return ASN1.parseInteger(this.bytes)
    case Tag.BITSTRING:
      return ASN1.parseBitString(this.bytes)
    case Tag.NULL:
      return ASN1.parseNull(this.bytes)
    case Tag.OID:
      return ASN1.parseOID(this.bytes)
    case Tag.UTF8:
      return ASN1.parseUTF8(this.bytes)
    case Tag.NUMERICSTRING:
      return ASN1.parseNumericString(this.bytes)
    case Tag.PRINTABLESTRING:
      return ASN1.parsePrintableString(this.bytes)
    case Tag.T61STRING:
      return ASN1.parseT61String(this.bytes)
    case Tag.IA5STRING:
      return ASN1.parseIA5String(this.bytes)
    case Tag.GENERALSTRING:
      return ASN1.parseGeneralString(this.bytes)
    case Tag.UTCTIME:
      return ASN1.parseUTCTime(this.bytes)
    case Tag.GENERALIZEDTIME:
      return ASN1.parseGeneralizedTime(this.bytes)

    default:
      return this.bytes
    }
  }

  /**
   * Validates that the given ASN.1 object is at least a super set of the
   * given ASN.1 structure. Only tag classes and types are checked. An
   * optional map may also be provided to capture ASN.1 values while the
   * structure is checked.
   *
   * To capture an ASN.1 object, set an object in the validator's 'capture'
   * parameter to the key to use in the capture map.
   *
   * Objects in the validator may set a field 'optional' to true to indicate
   * that it isn't necessary to pass validation.
   *
   * @param tpl Template object to validate.
   * @param captures Captures object to capture ASN.1 object.
   */
  validate (tpl: Template, captures: Captures = {}): Error | null {
    if (this.class !== tpl.class) {
      return new Error(`ASN.1 object validate failure for ${tpl.name} : error class ${Class[this.class]}`)
    }

    const tplTags = Array.isArray(tpl.tag) ? tpl.tag : [tpl.tag]
    if (!tplTags.includes(this.tag)) {
      return new Error(`ASN.1 object validate failure for ${tpl.name}: error tag ${Tag[this.tag]}`)
    }

    if (tpl.capture != null) {
      captures[tpl.capture] = this
    }

    if (Array.isArray(tpl.value)) {
      const values = this.mustCompound(`${tpl.name} need compound ASN1 value`)
      for (let i = 0, j = 0; i < tpl.value.length; i++) {
        if (values[j] != null) {
          const err = values[j].validate(tpl.value[i], captures)
          if (err == null) {
            j++
          } else if (tpl.value[i].optional !== true) {
            return err
          }
        } else if (tpl.value[i].optional !== true) {
          return new Error(`ASN.1 object validate failure for ${tpl.value[i].name}: not exists`)
        }
      }
    } else if (tpl.value != null) {
      const buf = this.tag === Tag.BITSTRING ? this.bytes.slice(1) : this.bytes
      return ASN1.fromDER(buf).validate(tpl.value, captures)
    }

    return null
  }

  /**
   * Return a friendly JSON object for debuging.
   */
  toJSON (): any {
    let value = this.value
    if (Array.isArray(value)) {
      value = value.map((val) => val.toJSON())
    }
    return {
      class: Class[this.class],
      tag: this.class === Class.UNIVERSAL ? Tag[this.tag] : this.tag,
      value,
    }
  }

  protected [inspect.custom] (_depth: any, options: any): string {
    if (options.depth <= 2) {
      options.depth = 10
    }
    return `<${this.constructor.name} ${inspect(this.toJSON(), options)}>`
  }
}

// Gets the length of a BER-encoded ASN.1 value.
function getValueLength (bufv: BufferVisitor): number {
  bufv.mustWalk(1, 'Too few bytes to read ASN.1 value length.')
  const byte = bufv.buf[bufv.start]

  // see if the length is "short form" or "long form" (bit 8 set)
  if ((byte & 0x80) === 0) {
    // if byte is 0, means asn1 object of indefinite length
    return byte
  }

  const byteLen = byte & 0x7f
  bufv.mustWalk(byteLen, 'Too few bytes to read ASN.1 value length.')
  return bufv.buf.readUIntBE(bufv.start, byteLen)
}

// Gets the length of a BER-encoded ASN.1 value length's bytes
function getValueLengthByte (valueLen: number): number {
  if (valueLen <= 127) {
    return 0
  } else if (valueLen <= 0xff) {
    return 1
  } else if (valueLen <= 0xffff) {
    return 2
  } else if (valueLen <= 0xffffff) {
    return 3
  } else if (valueLen <= 0xffffffff) {
    return 4
  } else if (valueLen <= 0xffffffffff) {
    return 5
  } else if (valueLen <= 0xffffffffffff) {
    return 6
  } else {
    throw new Error('invalid value length')
  }
}

function isNumericString (str: string): boolean {
  for (const s of str) {
    const n = s.charCodeAt(0)
    if (n !== 32 && (n < 48 || n > 57)) { // '0' to '9', and ' '
      return false
    }
  }
  return true
}

function isIA5String (str: string): boolean {
  for (const s of str) {
    if (s.charCodeAt(0) >= 0x80) {
      return false
    }
  }
  return true
}

function mustParseInt (str: string, radix: number = 10): number {
  const val = parseInt(str, radix)
  if (Number.isNaN(val)) {
    throw new Error(`Invalid numeric string "${str}" in radix ${radix}.`)
  }
  return val
}
