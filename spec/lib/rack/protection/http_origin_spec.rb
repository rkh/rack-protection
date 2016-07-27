describe Rack::Protection::HttpOrigin do
  it_behaves_like "any rack application"

  before(:each) do
    mock_app do
      use Rack::Protection::HttpOrigin
      run DummyApp
    end
  end

  %w(GET HEAD POST PUT DELETE).each do |method|
    it "accepts #{method} requests with no Origin" do
      expect(send(method.downcase, '/')).to be_ok
    end
  end

  %w(GET HEAD).each do |method|
    it "accepts #{method} requests with non-whitelisted Origin" do
      expect(send(method.downcase, '/', {}, 'HTTP_ORIGIN' => 'http://malicious.com')).to be_ok
    end
  end

  %w(POST PUT DELETE).each do |method|
    it "denies #{method} requests with non-whitelisted Origin" do
      expect(send(method.downcase, '/', {}, 'HTTP_ORIGIN' => 'http://malicious.com')).not_to be_ok
    end

    it "accepts #{} requests with 'null' Origin" do
      expect(send(method.downcase, '/', {}, 'HTTP_ORIGIN' => 'null')).to be_ok
    end

    it "accepts #{method} requests with whitelisted Origin" do
      mock_app do
        use Rack::Protection::HttpOrigin, :origin_whitelist => ['http://www.friend.com']
        run DummyApp
      end
      expect(send(method.downcase, '/', {}, 'HTTP_ORIGIN' => 'http://www.friend.com')).to be_ok
    end
  end
end
