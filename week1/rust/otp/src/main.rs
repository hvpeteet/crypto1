
use std::collections::HashMap;
use std::cmp;

fn main() {
    // The target ciphertext to decrypt
    let target_str = "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904";

    // Intercepted ciphertexts that all use the same pad.
    let ciphertexts_str = &[
        "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",
        "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",
        "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
        "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa",
        "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070",
        "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4",
        "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce",
        "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3",
        "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027",
        "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83",
    ];

    let mut breaker: OTPBreaker = OTPBreaker::new();
    for string in ciphertexts_str {
        breaker.add_message(hex_str_to_u8_vec(string));
    }
    let final_msg: Vec<u8> = breaker.attempt_decode(&hex_str_to_u8_vec(target_str));
    let final_str: String = u8_vec_to_string(&final_msg);

    println!("---- DECODED MESSAGE ----\n{0}", final_str);
}

pub struct OTPBreaker {
    votes: Vec<HashMap<u8, u64>>,
    ciphertexts: Vec<Vec<u8>>,
}

impl OTPBreaker {

    fn new() -> OTPBreaker {
        return OTPBreaker {votes: Vec::new(), ciphertexts: Vec::new()};
    }

    pub fn add_message(&mut self, message: Vec<u8>) {
        // Ensure votes is long enough for the existing message
        if self.votes.len() < message.len() {
            for _ in self.votes.len()..message.len() {
                self.votes.push(HashMap::new());
            }
        }
        
        // Update the votes
        for j in 0..self.ciphertexts.len() {
            let ciphertext_a = &message;
            let ciphertext_b = &self.ciphertexts[j];
            for k in 0..cmp::min(ciphertext_a.len(), ciphertext_b.len()) {
                let xor = ciphertext_a[k] ^ ciphertext_b[k];
                if (('a' as u8) <= xor && xor <= ('z' as u8)) || (('A' as u8) <= xor && xor <= ('Z' as u8)) {
                    {
                        let count_a = self.votes[k].entry(ciphertext_a[k] ^ (' ' as u8)).or_insert(0);
                        *count_a += 1;
                    }
                    {
                        let count_b = self.votes[k].entry(ciphertext_b[k] ^ (' ' as u8)).or_insert(0);
                        *count_b += 1;
                    }
                }
            }
        }

        // Add the new message to the set of ciphertexts
        self.ciphertexts.push(message);
    }

    /// Uses the existing ciphertexts to try to decode a new one
    ///
    /// # Arguments
    /// 
    /// `message` - The message to decode.
    ///
    /// # Example
    ///
    /// ```
    /// 
    /// ```
    pub fn attempt_decode(&self, message: &Vec<u8>) -> Vec<u8> {
        let pad: Vec<u8> = self.get_likely_pad();
        return apply_pad(&pad, message)
    }

    fn get_likely_pad(&self) -> Vec<u8> {
        let mut final_pad: Vec<u8> = Vec::new();
        for i in 0..self.votes.len() {
            let mut pad_value: u8 = 0x00;
            let mut max_votes: u64 = 0x00; 
            for (val, num_votes) in &self.votes[i] {
                if *num_votes > max_votes {
                    pad_value = *val;
                    max_votes = *num_votes;
                }
            }
            final_pad.push(pad_value);
        }
        return final_pad;
    }
}

/// Applies a pad to a message and returns the new message.
/// 
/// ## WARNING
/// This will assume all entries are ASCII and will
/// always only output 7 bit numbers where the most significant 
/// bit is 0.
/// 
/// # Arguments
/// 
/// * `message` - The message to apply the pad to.
/// * `pad` - The pad to apply to the message. 
/// 
/// # Examples
///
/// ```
/// let message: Vec<u8> = [0x00, 0x01, 0x02].to_vec();
/// let pad: Vec<u8> = [0x1F, 0x2F, 0x3F].to_vec();
/// let result: Vec<u8> = apply_pad(&message, &pad);

/// assert_eq!(0x1F, result[0]);
/// assert_eq!(0x2E, result[1]);
/// assert_eq!(0x3D, result[2]);
/// ```
fn apply_pad(message: &Vec<u8>, pad: &Vec<u8>) -> Vec<u8> {
    let mut final_vec: Vec<u8> = Vec::new();
    for i in 0..cmp::min(message.len(), pad.len()) {
        final_vec.push((message[i] ^ pad[i]) & 0x7F);
    }
    return final_vec;
}

fn hex_str_to_u8_vec(string: &str) -> Vec<u8> {
    let mut tmp: Vec<u8> = Vec::new();
    for i in 0..string.len()/2 {
        tmp.push(u8::from_str_radix(string[i*2..i*2+2].to_string().as_str(), 16).expect("The input strings are not hex encoded"));
    }
    return tmp;
}

fn u8_vec_to_string(message: &Vec<u8>) -> String {
    let mut string: String = String::new();
    for int in message {
        string.push(*int as char);
    }
    return string;
}