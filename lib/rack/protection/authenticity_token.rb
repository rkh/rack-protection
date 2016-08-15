require 'rack/protection'
require 'rack/protection/utils'

module Rack
  module Protection
    ##
    # Prevented attack::   CSRF
    # Supported browsers:: all
    # More infos::         http://en.wikipedia.org/wiki/Cross-site_request_forgery
    #
    # Only accepts unsafe HTTP requests if a given access token matches the token
    # included in the session.
    #
    # Compatible with Rails and rack-csrf.
    #
    # Options:
    #
    # authenticity_param: Defines the param's name that should contain the token on a request.
    #
    class AuthenticityToken < Base
      default_options :authenticity_param => 'authenticity_token',
                      :authenticity_token_length => 32,
                      :allow_if => nil

      def self.token(session)
        Utils.mask_token(session[:csrf])
      end

      def accepts?(env)
        session = session env
        session[:csrf] ||= Utils.random_token(token_length)

        safe?(env) ||
          valid_token?(session, env['HTTP_X_CSRF_TOKEN']) ||
          valid_token?(session, Request.new(env).params[options[:authenticity_param]]) ||
          ( options[:allow_if] && options[:allow_if].call(env) )
      end

      private

      def token_length
        options[:authenticity_token_length]
      end

      # Checks the client's masked token to see if it matches the
      # session token.
      def valid_token?(session, token)
        return false if token.nil? || token.empty?

        begin
          token = Utils.decode_token(token)
        rescue ArgumentError # encoded_masked_token is invalid Base64
          return false
        end

        # See if it's actually a masked token or not. We should be able
        # to handle any unmasked tokens that we've issued without error.

        if unmasked_token?(token)
          compare_with_real_token token, session

        elsif masked_token?(token)
          token = Utils.unmask_decoded_token(token)

          compare_with_real_token token, session

        else
          false # Token is malformed
        end
      end

      def unmasked_token?(token)
        token.length == token_length
      end

      def masked_token?(token)
        token.length == token_length * 2
      end

      def compare_with_real_token(token, session)
        secure_compare(token, real_token(session))
      end

      def real_token(session)
        Utils.decode_token(session[:csrf])
      end
    end
  end
end
