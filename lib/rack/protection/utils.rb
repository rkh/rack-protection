require 'securerandom'
require 'base64'

module Rack
  module Protection
    module Utils

      def random_token(length = 32)
        SecureRandom.base64(length)
      end
      module_function :random_token

      # Creates a masked version of the authenticity token that varies
      # on each request. The masking is used to mitigate SSL attacks
      # like BREACH.
      def mask_token(token)
        token = decode_token(token)
        one_time_pad = SecureRandom.random_bytes(token.length)
        encrypted_token = xor_byte_strings(one_time_pad, token)
        masked_token = one_time_pad + encrypted_token
        encode_token masked_token
      end
      module_function :mask_token

      # Essentially the inverse of +mask_token+.
      def unmask_decoded_token(masked_token)
        # Split the token into the one-time pad and the encrypted
        # value and decrypt it
        token_length = masked_token.length / 2
        one_time_pad = masked_token[0...token_length]
        encrypted_token = masked_token[token_length..-1]
        xor_byte_strings(one_time_pad, encrypted_token)
      end
      module_function :unmask_decoded_token

      def encode_token(token)
        Base64.strict_encode64(token)
      end
      module_function :encode_token

      def decode_token(token)
        Base64.strict_decode64(token)
      end
      module_function :decode_token

      def xor_byte_strings(s1, s2)
        s1.bytes.zip(s2.bytes).map { |(c1,c2)| c1 ^ c2 }.pack('c*')
      end
      module_function :xor_byte_strings

    end
  end
end
