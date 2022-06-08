//
//  Encryptor.swift
//  PassManager
//
//  Created by R4 on 08/06/2022.
//
import UIKit
import CryptoKit

extension StringProtocol {
    subscript(offset: Int) -> Character {
        self[index(startIndex, offsetBy: offset)]
    }
}

class Encryptor{
    //Variable controls size of the plain text + padding prior to encryption
    private let ENTRY_SIZE : Int = 50
    private var key : SymmetricKey? = nil
    
    public init(password : String){
        key = generate_symmetric_key(plain_text_pass: password)
        
    }
    
    //creates the symmetric key through the hashing of the plain text password
    private func generate_symmetric_key(plain_text_pass : String)-> SymmetricKey{
        return SymmetricKey(data: SHA256.hash(data: Data(plain_text_pass.utf8)))
    }
    
    //generate random symbols of given length
    private func generate_random_string(len : Int) -> String{
        let char_bank = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789@%&"
        var rand_string : String = ""
        for _ in 1...len{
            rand_string += String(char_bank[Int.random(in: 0..<char_bank.count)])
        }
        return rand_string
    }
    
    //pads the pass/user to length of 1024 as passwords and user ids will not be that long
    private func pad_entries(info : String) -> String {
        let delimited_plaintext = "/" + info + "/"
        
        let string_len : Int = delimited_plaintext.count
        let num_of_padded_chars : Int = ENTRY_SIZE - string_len
        
        let prefix_size = num_of_padded_chars - (Int.random(in: 1..<num_of_padded_chars))
        let suffix_size = num_of_padded_chars - prefix_size
        
        let prefix = generate_random_string(len: prefix_size)
        let suffix = generate_random_string(len: suffix_size)
        
        let padded_text = prefix + delimited_plaintext + suffix
        
        return padded_text
    }
    
    //function performs encryption
    public func perform_encryption(text : String) -> AES.GCM.SealedBox{
        let padded_text = pad_entries(info: text)
        let sealed_box = try! AES.GCM.seal(padded_text.data(using: .utf8)!, using: key!)
        return sealed_box
    }
    
    //function performs decryption on sealed box object
    public func perform_decryption(sealed_box: AES.GCM.SealedBox) -> String{
        let restored_box = try! AES.GCM.SealedBox(nonce: sealed_box.nonce, ciphertext: sealed_box.ciphertext, tag: sealed_box.tag)
        let decrypted = try! AES.GCM.open(restored_box, using: key!)
        let string_data = String(data: decrypted, encoding: .utf8)
        return de_pad_entry(padded_entry: string_data!)
    }
    
    //de pads the information from the random bits infront and behind the password
    func de_pad_entry(padded_entry : String)-> String{
        let pattern = "[/]{1}.+[/]{1}"
        let result = padded_entry.range(of: pattern, options:.regularExpression)
        let matched_pattern : String = String(padded_entry[result!])
        let start = matched_pattern.index(matched_pattern.startIndex, offsetBy: 1)
        let end = matched_pattern.index(matched_pattern.endIndex, offsetBy: -1)
        let range = start..<end
        let substr : String = String(matched_pattern[range])
        return substr
    }
}
