//
//  PSBTFile.swift
//  Cove
//
//  Created by Praveen Perera on 11/24/24.
//
import Foundation
import UniformTypeIdentifiers

extension UTType {
    static var psbt: UTType {
        UTType(exportedAs: "org.bitcoin.psbt")
    }

    static var txn: UTType {
        UTType(exportedAs: "org.bitcoin.transaction")
    }
}
