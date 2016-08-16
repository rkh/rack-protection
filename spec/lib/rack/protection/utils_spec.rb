describe Rack::Protection::Utils do
  let(:token) { subject.random_token }

  describe "#random_token" do
    it "outputs a base64 encoded 32 character string by default" do
      expect(Base64.strict_decode64(token).length).to eq(32)
    end

    it "outputs a base64 encoded string of the specified length" do
      token = subject.random_token(64)
      expect(Base64.strict_decode64(token).length).to eq(64)
    end
  end

  describe "#mask_token" do
    it "generates unique masked values for a token" do
      first_masked_token =  subject.mask_token(token)
      second_masked_token = subject.mask_token(token)
      expect(first_masked_token).not_to eq(second_masked_token)
    end
  end

  describe "#unmask_decoded_token" do
    it "unmasks a token to its original decoded value" do
      masked_token = subject.decode_token(subject.mask_token(token))
      unmasked_token = subject.unmask_decoded_token(masked_token)
      expect(unmasked_token).to eq(subject.decode_token(token))
    end
  end
end
