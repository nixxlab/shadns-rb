module ExtendedHash
  def self.symbolize data
    if data.is_a?(Hash)
      return Hash[data.map{|k,v|
        [k.to_sym, self.symbolize(v)]
      }]
    elsif data.is_a?(Array)
      data.map{|v| self.symbolize(v)}
    else
      return data
    end
  end
end