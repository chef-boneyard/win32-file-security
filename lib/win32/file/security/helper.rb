class String
  unless instance_methods.include?(:wincode)
    # Convenience method for converting strings to UTF-16LE for wide character
    # functions that require it.
    def wincode
      unless encoding == Encoding::UTF_16LE
        (self.tr(File::SEPARATOR, File::ALT_SEPARATOR) + 0.chr).encode('UTF-16LE')
      end
    end
  end

  unless instance_methods.include?(:wstrip)
    # Read a wide character string up until the first double null, and delete
    # any remaining null characters.
    def wstrip
      unless encoding == Encoding::UTF_16LE
        self.force_encoding('UTF-16LE')
      end

      self.encode('UTF-8',:invalid=>:replace,:undef=>:replace).split("\x00")[0].encode(Encoding.default_external)
    end
  end
end
