module Base36
  ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
  BASE = ALPHABET.size

  def self.from_int int
    raise ArgumentError, 'Value passed is not an Integer.' unless int.is_a?(Integer)

    str = ''
    while int >= BASE
      mod = int % BASE
      str = ALPHABET[mod, 1] + str
      int = (int - mod) / BASE
    end
    ALPHABET[int,1] + str
  end

  # From ASCII-8BIT or BINARY
  def self.from_str str, include_leading_zeroes = true
    raise ArgumentError, 'Value passed is not a String.' unless str.is_a?(String)
    raise ArgumentError, 'Value passed is not binary.' unless str.encoding == Encoding::BINARY

    if str.empty?
      return from_int(0) 
    elsif include_leading_zeroes
      nzeroes = str.bytes.find_index{|b| b != 0} || str.length - 1
      prefix = ALPHABET[0] * nzeroes
    else
      prefix = ''
    end

    prefix + from_int(str.unpack('H*')[0].to_i(16))
  end

  def self.to_int str
    int = 0
    str.gsub('-', '').reverse.split(//).each_with_index do |char,index|
      raise ArgumentError, 'Value passed not a valid Base36 String.' if (char_index = ALPHABET.index(char)).nil?
      int += char_index * (BASE ** index)
    end
    int
  end

  def self.to_str str
    clean_string = str.gsub('-', '')
    nzeroes = clean_string.chars.find_index{|c| c != ALPHABET[0]} || clean_string.length-1
    prefix = nzeroes < 0 ? '' : '00' * nzeroes
    [prefix + to_int(clean_string).to_s(16)].pack('H*')
  end
end