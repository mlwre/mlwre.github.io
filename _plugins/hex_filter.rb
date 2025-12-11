module Jekyll
  module HexFilter
    def to_hex(input)
      year = input.to_i
      year.to_s(16).downcase
    end
  end
end

Liquid::Template.register_filter(Jekyll::HexFilter)

