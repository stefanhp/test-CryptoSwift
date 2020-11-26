//
//  CryptoSwiftTests.swift
//  
//
//  Created by Stefan Paychère on 27.11.20.
//

import XCTest
import CryptoSwift

final class CryptoSwiftTest: XCTestCase {
    func testDecryptAESCCM() {
        // Data generated from http://bitwiseshiftleft.github.io/sjcl/demo/

        // Key generation info used on page:
        let password = "myPassword"

        // Salt: 762CB1CB FA62DEDA
        let salt: [UInt8] = [
            0x76, 0x2C, 0xB1, 0xCB,
            0xFA, 0x62, 0xDE, 0xDA]

        // Generated key:
        // 256 bit key: 0FB130BA CFBE9860 35C094C7 BC94D499 E79C89CD 8112552C F64DF6AE 39BB6912
        let rawKey: [UInt8] = [
            0x0F, 0xB1, 0x30, 0xBA,
            0xCF, 0xBE, 0x98, 0x60,
            0x35, 0xC0, 0x94, 0xC7,
            0xBC, 0x94, 0xD4, 0x99,
            0xE7, 0x9C, 0x89, 0xCD,
            0x81, 0x12, 0x55, 0x2C,
            0xF6, 0x4D, 0xF6, 0xAE,
            0x39, 0xBB, 0x69, 0x12]

        // Message:
        let message = "Test CryptoSwift decrypt"
        // no authenticated additional data

        // Encrypted data:
        /* JSON transport
        {"iv":"dT9+NAjLzdMNvw5x7m2hiw==",
        "v":1,
        "iter":10000,
        "ks":256,
        "ts":64,
        "mode":"ccm",
        "adata":"",
        "cipher":"aes",
        "salt":"diyxy/pi3to=",
        "ct":"LKRxWGCbxnNk6bLjEkl6pfPdTcGeapRrOvyd5anzHqQ="}
        */

        // JSON decoded data:
        let iv = "dT9+NAjLzdMNvw5x7m2hiw=="
        let ts = Int(64)
        let ct = "LKRxWGCbxnNk6bLjEkl6pfPdTcGeapRrOvyd5anzHqQ="

        // Decryption:

        // Base64 decoded
        let ivDecoded: [UInt8] = Data(base64Encoded: iv)!.bytes
        let encrypted: [UInt8] = Data(base64Encoded: ct)!.bytes
        let tsInBytes = Int(ts/8)

        let ccm = CCM(
            iv: ivDecoded,
            tagLength: tsInBytes,
            messageLength: encrypted.count - tsInBytes)

        do {
            let aes = try AES(key: rawKey, blockMode: ccm, padding: .noPadding)
            let decrypted = try aes.decrypt(encrypted)     // <-- crash here
            XCTAssertEqual(String(data: Data(decrypted), encoding: .utf8), message)
        } catch let error {
            XCTFail("Error: \(error)")
            return
        }
    }
}
