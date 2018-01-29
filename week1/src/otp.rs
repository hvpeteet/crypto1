use std::collections::HashMap;
use std::cmp;

/// Used to break OTP encryption when the same pad is used more than once.
pub struct OTPBreaker {
    votes: Vec<HashMap<u8, u64>>,
    ciphertexts: Vec<Vec<u8>>,
}

/// Used to break OTP encryption when the same pad is used more than once.
/// 
/// # Examples
/// 
/// For a full example see otp_example.rs.
///
/// ```
/// // The target ciphertext to decrypt
/// let target_str = "32510ba9ba";
///
/// // Intercepted ciphertexts that all use the same pad.
/// let ciphertexts_str = &[
///     "315c4eeaa8",
///     "234c02ecbb",
///     "32510ba9a7",
///     "32510ba9aa",
///     "3f561ba9ad",
///     "32510bfbac",
///     "32510bfbac",
///     "315c4eeaa8",
///     "271946f9bb",
///     "466d06ece9",
/// ];
///
/// let mut breaker: otp::OTPBreaker = otp::OTPBreaker::new();
/// for string in ciphertexts_str {
///     breaker.add_message(otp::hex_str_to_u8_vec(string));
/// }
/// let final_msg: Vec<u8> = breaker.attempt_decode(&otp::hex_str_to_u8_vec(target_str));
/// let final_str: String = otp::u8_vec_to_string(&final_msg);
/// let orginal_message = "The s";
/// assert_eq!(orginal_message, final_str.as_str());
/// ```
impl OTPBreaker {

    pub fn new() -> OTPBreaker {
        return OTPBreaker {votes: Vec::new(), ciphertexts: Vec::new()};
    }

    /// Provide another ciphertext where the same one-time-pad is used.
    ///
    /// # Arguments:
    ///
    /// `message` - A ciphertext that is believed to use the same pad as 
    /// the other ciphertexts given to this OTPBreaker.
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

    /// Uses the existing ciphertexts to try to decode another one.
    ///
    /// # Arguments
    /// 
    /// `message` - The message to decode.
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
/// let result: Vec<u8> = otp::apply_pad(&message, &pad);

/// assert_eq!(0x1F, result[0]);
/// assert_eq!(0x2E, result[1]);
/// assert_eq!(0x3D, result[2]);
/// ```
pub fn apply_pad(message: &Vec<u8>, pad: &Vec<u8>) -> Vec<u8> {
    let mut final_vec: Vec<u8> = Vec::new();
    for i in 0..cmp::min(message.len(), pad.len()) {
        final_vec.push((message[i] ^ pad[i]) & 0x7F);
    }
    return final_vec;
}

/// Converts a hex `str` to a `Vec<u8>`.
///
/// # Examples
///
/// ```
/// let vec: Vec<u8> = otp::hex_str_to_u8_vec("07AB");
/// assert_eq!(0x07, vec[0]);
/// assert_eq!(0xAB, vec[1]);
/// ```
pub fn hex_str_to_u8_vec(string: &str) -> Vec<u8> {
    if (string.len() % 2) != 0{
        panic!("input must have an even number of hex characters");
    }
    let mut tmp: Vec<u8> = Vec::new();
    for i in 0..string.len()/2 {
        tmp.push(u8::from_str_radix(string[i*2..i*2+2].to_string().as_str(), 16).expect("The input strings are not hex encoded"));
    }
    return tmp;
}

/// Converts a `Vec<u8>` into a `String`.
///
/// # Examples
///
/// ```
/// let vec: Vec<u8> = [0x7B, 0x41, 0x62, 0x7D].to_vec();
/// let string: String = otp::u8_vec_to_string(&vec);
/// assert_eq!("{Ab}", string.as_str());
/// ```
pub fn u8_vec_to_string(message: &Vec<u8>) -> String {
    let mut string: String = String::new();
    for int in message {
        string.push(*int as char);
    }
    return string;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u8_vec_to_str_small_example() {
        let vec: Vec<u8> = [0x7B, 0x41, 0x62, 0x7D].to_vec();
        let string: String = u8_vec_to_string(&vec);
        assert_eq!("{Ab}", string.as_str());
    }

    #[test]
    fn u8_vec_to_str_empty_example() {
        let vec: Vec<u8> = Vec::new();
        let string: String = u8_vec_to_string(&vec);
        assert_eq!("", string.as_str());
    }

    #[test]
    fn hex_str_to_u8_vec_empty () {
        let got: Vec<u8> = hex_str_to_u8_vec("");
        let want: Vec<u8> = [].to_vec();
        assert_eq!(want, got);
    }

    #[test]
    fn hex_str_to_u8_vec_small () {
        let got: Vec<u8> = hex_str_to_u8_vec("07AB");
        let want: Vec<u8> = [0x07, 0xAB].to_vec();
        assert_eq!(want, got);
    }

    #[test]
    #[should_panic(expected = "input must have an even number of hex characters")]
    fn hex_str_to_u8_vec_odd_num_chars () {
        hex_str_to_u8_vec("07ABC");
    }

    #[test]
    #[should_panic(expected = "not hex encoded")]
    fn hex_str_to_u8_vec_malformed_hex () {
        hex_str_to_u8_vec("0123XY");
    }

}