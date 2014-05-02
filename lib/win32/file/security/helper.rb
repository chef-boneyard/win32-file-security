class String
  # Convenience method for converting strings to UTF-16LE for wide character
  # functions that require it.
  def wincode
    (self.tr(File::SEPARATOR, File::ALT_SEPARATOR) + 0.chr).encode('UTF-16LE')
  end

  # Read a wide character string up until the first double null, and delete
  # any remaining null characters.
  def wstrip
    self.force_encoding('UTF-16LE').encode('UTF-8',:invalid=>:replace,:undef=>:replace).split("\x00")[0].encode(Encoding.default_external)
  end
end
