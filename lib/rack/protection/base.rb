require 'rack/protection'
require 'digest'
require 'logger'
require 'uri'

module Rack
  module Protection
    class Base
      DEFAULT_OPTIONS = {
        :reaction    => :default_reaction, :logging   => true,
        :message     => 'Forbidden',       :encryptor => Digest::SHA1,
        :session_key => 'rack.session',    :status    => 403
      }

      attr_reader :app, :options

      def self.default_options(options)
        define_method(:default_options) { super().merge(options) }
      end

      def self.default_reaction(reaction)
        alias_method(:default_reaction, reaction)
      end

      def default_options
        DEFAULT_OPTIONS
      end

      def initialize(app, options = {})
        @app, @options = app, default_options.merge(options)
      end

      def safe?(env)
        %w[GET HEAD OPTIONS TRACE].include? env['REQUEST_METHOD']
      end

      def accepts?(env)
        raise NotImplementedError, "#{self.class} implementation pending"
      end

      def call(env)
        unless accepts? env
          warn env, "attack prevented by #{self.class}"
          result = react env
        end
        result or app.call(env)
      end

      def react(env)
        result = send(options[:reaction], env)
        result if Array === result and result.size == 3
      end

      def warn(env, message)
        return unless options[:logging]
        l = options[:logger] || env['rack.logger'] || ::Logger.new(env['rack.errors'])
        l.warn(message)
      end

      def deny(env)
        [options[:status], {'Content-Type' => 'text/plain'}, [options[:message]]]
      end

      def session?(env)
        env.include? options[:session_key]
      end

      def session(env)
        return env[options[:session_key]] if session? env
        fail "you need to set up a session middleware *before* #{self.class}"
      end

      def drop_session(env)
        session(env).clear if session? env
      end

      def referrer(env)
        ref = env['HTTP_REFERER']
        URI.parse(ref).host || Request.new(env).host if ref and not ref.empty?
      end

      def random_string(secure = defined? SecureRandom)
        secure ? SecureRandom.hex(32) : "%032x" % rand(2**128-1)
      rescue NotImpelentedError
        random_string false
      end

      def default_reaction(env)
        fail "no default reaction given for #{self.class}"
      end

      def encrypt(value)
        options[:encryptor].hexdigest value.to_s
      end
    end
  end
end
