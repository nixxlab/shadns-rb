require 'base64'

###### OpenSSH keys parser
module OpenSSH
  def self.parse_public_key file_data
    result = {}
    file_type, key_data, result[:comments] = file_data.strip.gsub('  ', ' ').split(' ')
    openssh_data = Base64.decode64(key_data)
    key_type, offset = self.get_32bit_prefixed_string(openssh_data, 0)
    result[:type] = key_type.split('-').last
    result[:data], offset = self.get_32bit_prefixed_string(openssh_data, offset)
    return result
  end

  def self.parse_key_pair file_data
    openssh_data = Base64.decode64(file_data.gsub(/[\n]*--.+--[\n]*/, '').gsub("\n", ''))
    result = {}
    if openssh_data[..14] == "openssh-key-v1\x00" && openssh_data[-4..] == "\x01\x02\x03\x04"
        cipher_name, offset = self.get_32bit_prefixed_string(openssh_data, 15)
        kdf_name, offset = self.get_32bit_prefixed_string(openssh_data, offset)
        kdf, offset = self.get_32bit_prefixed_string(openssh_data, offset)
        offset += 4 # number of keys, hard-coded to 1 (no length)
        public_key_section_size, offset = self.get_32bit_integer(openssh_data, offset)
        public_key_type, offset = self.get_32bit_prefixed_string(openssh_data, offset)
        result[:public], offset = self.get_32bit_prefixed_string(openssh_data, offset)
        private_key_section_size, offset = self.get_32bit_integer(openssh_data, offset)
        random1, offset = self.get_32bit_integer(openssh_data, offset)
        random2, offset = self.get_32bit_integer(openssh_data, offset)
        private_key_type, offset = self.get_32bit_prefixed_string(openssh_data, offset)
        result[:type] = private_key_type.split('-').last
        public_key_again, offset = self.get_32bit_prefixed_string(openssh_data, offset)
        result[:private], offset = self.get_32bit_prefixed_string(openssh_data, offset)
        comment, offset = self.get_32bit_prefixed_string(openssh_data, offset)
    else
        return false
    end

    return result
  end

  def self.get_32bit_integer buffer, offset
  [ buffer[offset .. offset + 3].unpack('N').first, offset + 4 ]
  end

  def self.get_32bit_prefixed_string buffer, offset
    length, string_offset = get_32bit_integer(buffer, offset)
    end_offset = string_offset + length
    [ buffer[string_offset .. end_offset - 1], end_offset ]
  end
end