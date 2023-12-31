begin
  require "openssl"
rescue LoadError
end
require "test/unit"

if defined?(OpenSSL)

class OpenSSL::TestX509Name < Test::Unit::TestCase
# Fixes :in `register': oid exists (OpenSSL::ASN1::ASN1Error) - OpenSSL 1.1 and newer forbids this
#  OpenSSL::ASN1::ObjectId.register(
#    "1.2.840.113549.1.9.1", "emailAddress", "emailAddress")
#  OpenSSL::ASN1::ObjectId.register(
#    "2.5.4.5", "serialNumber", "serialNumber")

  def setup
    @obj_type_tmpl = Hash.new(OpenSSL::ASN1::PRINTABLESTRING)
    @obj_type_tmpl.update(OpenSSL::X509::Name::OBJECT_TYPE_TEMPLATE)
  end

  def teardown
  end

  def test_s_new
    dn = [ ["C", "JP"], ["O", "example"], ["CN", "www.example.jp"] ]
    name = OpenSSL::X509::Name.new(dn)
    ary = name.to_a
    assert_equal("/C=JP/O=example/CN=www.example.jp", name.to_s)
    assert_equal("C", ary[0][0])
    assert_equal("O", ary[1][0])
    assert_equal("CN", ary[2][0])
    assert_equal("JP", ary[0][1])
    assert_equal("example", ary[1][1])
    assert_equal("www.example.jp", ary[2][1])
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[0][2])
    assert_equal(OpenSSL::ASN1::UTF8STRING, ary[1][2])
    assert_equal(OpenSSL::ASN1::UTF8STRING, ary[2][2])

    dn = [
      ["countryName", "JP"],
      ["organizationName", "example"],
      ["commonName", "www.example.jp"]
    ]
    name = OpenSSL::X509::Name.new(dn)
    ary = name.to_a
    assert_equal("/C=JP/O=example/CN=www.example.jp", name.to_s)
    assert_equal("C", ary[0][0])
    assert_equal("O", ary[1][0])
    assert_equal("CN", ary[2][0])
    assert_equal("JP", ary[0][1])
    assert_equal("example", ary[1][1])
    assert_equal("www.example.jp", ary[2][1])
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[0][2])
    assert_equal(OpenSSL::ASN1::UTF8STRING, ary[1][2])
    assert_equal(OpenSSL::ASN1::UTF8STRING, ary[2][2])

    name = OpenSSL::X509::Name.new(dn, @obj_type_tmpl)
    ary = name.to_a
    assert_equal("/C=JP/O=example/CN=www.example.jp", name.to_s)
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[0][2])
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[1][2])
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[2][2])

    dn = [
      ["countryName", "JP", OpenSSL::ASN1::PRINTABLESTRING],
      ["organizationName", "example", OpenSSL::ASN1::PRINTABLESTRING],
      ["commonName", "www.example.jp", OpenSSL::ASN1::PRINTABLESTRING]
    ]
    name = OpenSSL::X509::Name.new(dn)
    ary = name.to_a
    assert_equal("/C=JP/O=example/CN=www.example.jp", name.to_s)
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[0][2])
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[1][2])
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[2][2])

    dn = [
      ["DC", "org"],
      ["DC", "ruby-lang"],
      ["CN", "GOTOU Yuuzou"],
      ["emailAddress", "gotoyuzo@ruby-lang.org"],
      ["serialNumber", "123"],
    ]
    name = OpenSSL::X509::Name.new(dn)
    ary = name.to_a
    assert_equal("/DC=org/DC=ruby-lang/CN=GOTOU Yuuzou/emailAddress=gotoyuzo@ruby-lang.org/serialNumber=123", name.to_s)
    assert_equal("DC", ary[0][0])
    assert_equal("DC", ary[1][0])
    assert_equal("CN", ary[2][0])
    assert_equal("emailAddress", ary[3][0])
    assert_equal("serialNumber", ary[4][0])
    assert_equal("org", ary[0][1])
    assert_equal("ruby-lang", ary[1][1])
    assert_equal("GOTOU Yuuzou", ary[2][1])
    assert_equal("gotoyuzo@ruby-lang.org", ary[3][1])
    assert_equal("123", ary[4][1])
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[0][2])
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[1][2])
    assert_equal(OpenSSL::ASN1::UTF8STRING, ary[2][2])
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[3][2])
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[4][2])

    name_from_der = OpenSSL::X509::Name.new(name.to_der)
    assert_equal(name_from_der.to_s, name.to_s)
    assert_equal(name_from_der.to_a, name.to_a)
    assert_equal(name_from_der.to_der, name.to_der)
  end

  def test_s_parse
    dn = "/DC=org/DC=ruby-lang/CN=www.ruby-lang.org"
    name = OpenSSL::X509::Name.parse(dn)
    assert_equal(dn, name.to_s)
    ary = name.to_a
    assert_equal("DC", ary[0][0])
    assert_equal("DC", ary[1][0])
    assert_equal("CN", ary[2][0])
    assert_equal("org", ary[0][1])
    assert_equal("ruby-lang", ary[1][1])
    assert_equal("www.ruby-lang.org", ary[2][1])
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[0][2])
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[1][2])
    assert_equal(OpenSSL::ASN1::UTF8STRING, ary[2][2])

    dn2 = "DC=org, DC=ruby-lang, CN=www.ruby-lang.org"
    name = OpenSSL::X509::Name.parse(dn)
    ary = name.to_a
    assert_equal(dn, name.to_s)
    assert_equal("org", ary[0][1])
    assert_equal("ruby-lang", ary[1][1])
    assert_equal("www.ruby-lang.org", ary[2][1])

    name = OpenSSL::X509::Name.parse(dn, @obj_type_tmpl)
    ary = name.to_a
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[0][2])
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[1][2])
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[2][2])
  end

  def test_s_parse_rfc2253
    scanner = OpenSSL::X509::Name::RFC2253DN.method(:scan)

    assert_equal([["C", "JP"]], scanner.call("C=JP"))
    assert_equal([
        ["DC", "org"],
        ["DC", "ruby-lang"],
        ["CN", "GOTOU Yuuzou"],
        ["emailAddress", "gotoyuzo@ruby-lang.org"],
      ],
      scanner.call(
        "emailAddress=gotoyuzo@ruby-lang.org,CN=GOTOU Yuuzou,"+
        "DC=ruby-lang,DC=org")
    )

    u8 = OpenSSL::ASN1::UTF8STRING
    assert_equal([
        ["DC", "org"],
        ["DC", "ruby-lang"],
        ["O", ",=+<>#;"],
        ["O", ",=+<>#;"],
        ["OU", ""],
        ["OU", ""],
        ["L", "aaa=\"bbb, ccc\""],
        ["L", "aaa=\"bbb, ccc\""],
        ["CN", "\345\276\214\350\227\244\350\243\225\350\224\265"],
        ["CN", "\345\276\214\350\227\244\350\243\225\350\224\265"],
        ["CN", "\345\276\214\350\227\244\350\243\225\350\224\265"],
        ["CN", "\345\276\214\350\227\244\350\243\225\350\224\265", u8],
        ["2.5.4.3", "GOTOU, Yuuzou"],
        ["2.5.4.3", "GOTOU, Yuuzou"],
        ["2.5.4.3", "GOTOU, Yuuzou"],
        ["2.5.4.3", "GOTOU, Yuuzou"],
        ["CN", "GOTOU \"gotoyuzo\" Yuuzou"],
        ["CN", "GOTOU \"gotoyuzo\" Yuuzou"],
        ["1.2.840.113549.1.9.1", "gotoyuzo@ruby-lang.org"],
        ["emailAddress", "gotoyuzo@ruby-lang.org"],
      ],
      scanner.call(
        "emailAddress=gotoyuzo@ruby-lang.org," +
        "1.2.840.113549.1.9.1=gotoyuzo@ruby-lang.org," +
        'CN=GOTOU \"gotoyuzo\" Yuuzou,' +
        'CN="GOTOU \"gotoyuzo\" Yuuzou",' +
        '2.5.4.3=GOTOU\,\20Yuuzou,' +
        '2.5.4.3=GOTOU\, Yuuzou,' +
        '2.5.4.3="GOTOU, Yuuzou",' +
        '2.5.4.3="GOTOU\, Yuuzou",' +
        "CN=#0C0CE5BE8CE897A4E8A395E894B5," +
        'CN=\E5\BE\8C\E8\97\A4\E8\A3\95\E8\94\B5,' +
        "CN=\"\xE5\xBE\x8C\xE8\x97\xA4\xE8\xA3\x95\xE8\x94\xB5\"," +
        "CN=\xE5\xBE\x8C\xE8\x97\xA4\xE8\xA3\x95\xE8\x94\xB5," +
        'L=aaa\=\"bbb\, ccc\",' +
        'L="aaa=\"bbb, ccc\"",' +
        'OU=,' +
        'OU="",' +
        'O=\,\=\+\<\>\#\;,' +
        'O=",=+<>#;",' +
        "DC=ruby-lang," +
        "DC=org")
    )

    [
      "DC=org+DC=jp",
      "DC=org,DC=ruby-lang+DC=rubyist,DC=www"
    ].each{|dn|
      ex = scanner.call(dn) rescue $!
      dn_r = Regexp.escape(dn)
      assert_match(/^multi-valued RDN is not supported: #{dn_r}/, ex.message)
    }

    [
      ["DC=org,DC=exapmle,CN", "CN"],
      ["DC=org,DC=example,", ""],
      ["DC=org,DC=exapmle,CN=www.example.org;", "CN=www.example.org;"],
      ["DC=org,DC=exapmle,CN=#www.example.org", "CN=#www.example.org"],
      ["DC=org,DC=exapmle,CN=#777777.example.org", "CN=#777777.example.org"],
      ["DC=org,DC=exapmle,CN=\"www.example\".org", "CN=\"www.example\".org"],
      ["DC=org,DC=exapmle,CN=www.\"example.org\"", "CN=www.\"example.org\""],
      ["DC=org,DC=exapmle,CN=www.\"example\".org", "CN=www.\"example\".org"],
    ].each{|dn, msg|
      ex = scanner.call(dn) rescue $!
      assert_match(/^malformed RDN: .*=>#{Regexp.escape(msg)}/, ex.message)
    }

    dn = "CN=www.ruby-lang.org,DC=ruby-lang,DC=org"
    name = OpenSSL::X509::Name.parse_rfc2253(dn)
    assert_equal(dn, name.to_s(OpenSSL::X509::Name::RFC2253))
    ary = name.to_a
    assert_equal("DC", ary[0][0])
    assert_equal("DC", ary[1][0])
    assert_equal("CN", ary[2][0])
    assert_equal("org", ary[0][1])
    assert_equal("ruby-lang", ary[1][1])
    assert_equal("www.ruby-lang.org", ary[2][1])
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[0][2])
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[1][2])
    assert_equal(OpenSSL::ASN1::UTF8STRING, ary[2][2])
  end

  def test_add_entry
    dn = [
      ["DC", "org"],
      ["DC", "ruby-lang"],
      ["CN", "GOTOU Yuuzou"],
      ["emailAddress", "gotoyuzo@ruby-lang.org"],
      ["serialNumber", "123"],
    ]
    name = OpenSSL::X509::Name.new
    dn.each{|attr| name.add_entry(*attr) }
    ary = name.to_a
    assert_equal("/DC=org/DC=ruby-lang/CN=GOTOU Yuuzou/emailAddress=gotoyuzo@ruby-lang.org/serialNumber=123", name.to_s)
    assert_equal("DC", ary[0][0])
    assert_equal("DC", ary[1][0])
    assert_equal("CN", ary[2][0])
    assert_equal("emailAddress", ary[3][0])
    assert_equal("serialNumber", ary[4][0])
    assert_equal("org", ary[0][1])
    assert_equal("ruby-lang", ary[1][1])
    assert_equal("GOTOU Yuuzou", ary[2][1])
    assert_equal("gotoyuzo@ruby-lang.org", ary[3][1])
    assert_equal("123", ary[4][1])
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[0][2])
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[1][2])
    assert_equal(OpenSSL::ASN1::UTF8STRING, ary[2][2])
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[3][2])
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[4][2])
  end
end

end
