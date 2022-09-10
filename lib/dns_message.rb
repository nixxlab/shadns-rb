# DNS Message:
#   head:
#     id
#     request_type
#     opcode
#     is_authoritative_response
#     is_truncated
#     recursion_desired
#     recursion_available
#     must_be_zero
#     answer_authenticated
#     non_authenticated_data
#     response_code
#     query_size
#     answer_size
#     authority_size
#     additional_size
#   query:
#     {name, type, class}
#   answer:
#     {name, type, class, ttl, data}
#   authority:
#     {name, type, class, ttl, data}
#   additional:
#     {name, type, class, ttl, data}

module DnsMessage
  RECORD_CLASSES = {
    IN: 1,
  }

  RECORD_TYPES = {
    A: 1,
    TXT: 16,
    SIG: 24,
    KEY: 25,
    AAAA: 26,
  }

  REQUEST_TYPES = {
    REQUEST: 0,
    RESPONSE: 1,
  }

  RESPONSE_CODES = {
    NOERROR: 0,
    FORMERR: 1,
    SERVFAIL: 2,
    NXDOMAIN: 3,
    NOTIMP: 4,
    REFUSED: 5,
    YXDOMAIN: 6,
    XRRSET: 7,
    NOTAUTH: 8,
    NOTZONE: 9,
  }

  def self.compile_head message
    flags1 = (
      (message[:head][:recursion_desired] ? 1 : 0) +
      ((message[:head][:is_truncated] ? 1 : 0) << 1) +
      ((message[:head][:is_authoritative_response] ? 1 : 0) << 2) +
      (message[:head][:opcode] << 3) +
      (message[:head][:request_type] << 7)
    )

    flags2 = (
      message[:head][:response_code] +
      (message[:head][:non_authenticated_data] << 4) +
      (message[:head][:answer_authenticated] << 5) +
      (message[:head][:must_be_zero] << 6) +
      ((message[:head][:recursion_available] ? 1 : 0) << 7)
    )

    return [ message[:head][:id] ].pack('n') + [flags1, flags2].pack('CC') + [
      message[:query].size,
      message[:answer].size,
      message[:authority].size,
      message[:additional].size,
    ].pack('nnnn')
  end

  def self.compile_message message
    result = self.compile_head(message)

    result += message[:query].map{|record|
      self.compile_query_record(record)
    }.join

    [:answer, :authority, :additional].each do |section_name|
      result += message[section_name].map{|record|
        self.compile_record(record)
      }.join
    end

    return result
  end

  def self.compile_query_record record
    puts "compile query record #{record.inspect}"
    return self.compile_splitted_string(record[:name]) + [ record[:type], record[:class] ].pack('nn')
  end

  def self.compile_record record
    result = record[:offset] ? [49152 + record[:offset]].pack('n') : self.compile_splitted_string(record[:name])
    result += [ 
      record[:type], 
      record[:class], 
      record[:ttl], 
      record[:data].size 
    ].pack('nnNn')
    result += record[:data]

    return result
  end

  def self.compile_splitted_string parts
    return parts.map { |part| part.size.chr + part }.join + 0.chr
  end
  
  def self.parse_head(buffer)
    id, flags1, flags2, query_size, answer_size, authority_size, additional_size = buffer.unpack('nCCnnnn')
    result = {
      id: id,
      request_type: flags1[7],
      opcode: flags1[3..6],
      is_authoritative_response: flags1[2] == 1,
      is_truncated: flags1[1] == 1,
      recursion_desired: flags1[0] == 1,
      recursion_available: flags2[7] == 1,
      must_be_zero: flags2[6],
      answer_authenticated: flags2[5],
      non_authenticated_data: flags2[4],
      response_code: flags2[0..3],
      query_size: query_size,
      answer_size: answer_size,
      authority_size: authority_size,
      additional_size: additional_size,
    }

    return [result, 12]
  end

  def self.parse_message buffer
    buffer.force_encoding("BINARY")
    result = {
      head: {},
      query: [],
      answer: [],
      authority: [],
      additional: [],
    }

    result[:head], offset = self.parse_head(buffer)

    result[:head][:query_size].times.each do
      item, offset = self.parse_query_record(buffer, offset)
      result[:query] << item
    end
    result[:head].delete(:query_size)

    {
      answer: :answer_size,
      authority: :authority_size,
      additional: :additional_size
    }.each do |section_name, size_column|
      result[:head][size_column].times.each do
        item, offset = self.parse_record(buffer, offset)
        result[section_name] << item
      end
      result[:head].delete(size_column)
    end

    return result
  end

  def self.parse_query_record(buffer, offset)
    result = { offset: offset }
    result[:name], offset = self.parse_splitted_string(buffer, offset)
    # offset += 2 + result[:name].join(' ').size # + prefix byte + string size + zero byte
    result[:type], result[:class] = buffer[offset..offset+4].unpack('nnN')
    offset += 4 # + query type (A) + query class (IN)

    [ result, offset ]
  end

  def self.parse_record(buffer, offset)
    result = {}

    # Check for compressed pointer instead of full domain name
    if buffer[offset].ord ^ 0b11000000 == 0
      result[:offset] = buffer[offset+1].ord + ((buffer[offset].ord ^ 0b11000000) << 8)
      offset += 2 # size of compressed item offset value
    # Full name
    else
      result[:name], offset = self.parse_splitted_string(buffer, offset)
      # offset += 2 + result[:name].join(' ').size # + prefix byte + string size + zero byte
    end

    result[:type], result[:class], result[:ttl], data_size = buffer[offset..offset+10].unpack('nnNn')
    offset += 10 # + query type (A) + query class (IN) + ttl + RDATA size
    result[:data] = data_size > 0 ? buffer[offset..(offset + data_size - 1)] : ''
    offset += data_size

    [ result, offset ]
  end

  def self.parse_splitted_string(buffer, offset)
    part_size = buffer[offset].ord
    return [ [], offset + 1 ] if part_size == 0

    part = buffer[(offset + 1)..(offset + part_size)]
    next_offset = offset + part_size + 1

    next_parts, offset = self.parse_splitted_string(buffer, next_offset)
    if next_parts.empty?
      return [ [ part ], offset ]
    else
      return [ [ part ] + next_parts, offset ]
    end
  end
end