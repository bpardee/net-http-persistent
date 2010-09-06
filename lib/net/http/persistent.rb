require 'net/http'
require 'net/http/faster'
require 'uri'
require 'gene_pool'

##
# Persistent connections for Net::HTTP
#
# Net::HTTP::Persistent maintains persistent connections across all the
# servers you wish to talk to.  For each host:port you communicate with a
# single persistent connection is created.
#
# Multiple Net::HTTP::Persistent objects will share the same set of
# connections which will be checked out of a pool.
#
# You can shut down the HTTP connections when done by calling #shutdown.  You
# should name your Net::HTTP::Persistent object if you intend to call this
# method.
#
# Example:
#
#   uri = URI.parse 'http://example.com/awesome/web/service'
#   http = Net::HTTP::Persistent.new
#   stuff = http.request uri # performs a GET
#
#   # perform a POST
#   post_uri = uri + 'create'
#   post = Net::HTTP::Post.new post_uri.path
#   post.set_form_data 'some' => 'cool data'
#   http.request post_uri, post # URI is always required

class Net::HTTP::Persistent

  ##
  # The version of Net::HTTP::Persistent use are using

  VERSION = '1.3'

  ##
  # Error class for errors raised by Net::HTTP::Persistent.  Various
  # SystemCallErrors are re-raised with a human-readable message under this
  # class.

  class Error < StandardError; end

  ##
  # An SSL certificate authority.  Setting this will set verify_mode to
  # VERIFY_PEER.

  attr_accessor :ca_file

  ##
  # This client's OpenSSL::X509::Certificate

  attr_accessor :certificate

  ##
  # Sends debug_output to this IO via Net::HTTP#set_debug_output.
  #
  # Never use this method in production code, it causes a serious security
  # hole.

  attr_accessor :debug_output

  ##
  # Retry even for non-idempotent (POST) requests.

  attr_accessor :force_retry

  ##
  # Headers that are added to every request

  attr_accessor :headers

  ##
  # Maps host:port to an HTTP version.  This allows us to enable version
  # specific features.

  attr_reader :http_versions

  ##
  # The value sent in the Keep-Alive header.  Defaults to 30.  Not needed for
  # HTTP/1.1 servers.
  #
  # This may not work correctly for HTTP/1.0 servers
  #
  # This method may be removed in a future version as RFC 2616 does not
  # require this header.

  attr_accessor :keep_alive

  ##
  # Logger for message logging.

  attr_accessor :logger

  ##
  # A name for this connection.  Allows you to keep your connections apart
  # from everybody else's.

  attr_reader :name

  ##
  # Seconds to wait until a connection is opened.  See Net::HTTP#open_timeout

  attr_accessor :open_timeout

  ##
  # The maximum size of the connection pool

  attr_reader :pool_size

  ##
  # This client's SSL private key

  attr_accessor :private_key

  ##
  # The URL through which requests will be proxied

  attr_reader :proxy_uri

  ##
  # Seconds to wait until reading one block.  See Net::HTTP#read_timeout

  attr_accessor :read_timeout

  ##
  # SSL verification callback.  Used when ca_file is set.

  attr_accessor :verify_callback

  ##
  # HTTPS verify mode.  Defaults to OpenSSL::SSL::VERIFY_NONE which ignores
  # certificate problems.
  #
  # You can use +verify_mode+ to override any default values.

  attr_accessor :verify_mode

  ##
  # The threshold in seconds for checking out a connection at which a warning 
  # will be logged via the logger

  attr_accessor :warn_timeout

  ##
  # Creates a new Net::HTTP::Persistent.
  #
  # Set +name+ to keep your connections apart from everybody else's.  Not
  # required currently, but highly recommended.  Your library name should be
  # good enough.  This parameter will be required in a future version.
  #
  # +proxy+ may be set to a URI::HTTP or :ENV to pick up proxy options from
  # the environment.  See proxy_from_env for details.
  #
  # In order to use a URI for the proxy you'll need to do some extra work
  # beyond URI.parse:
  #
  #   proxy = URI.parse 'http://proxy.example'
  #   proxy.user     = 'AzureDiamond'
  #   proxy.password = 'hunter2'

  def initialize(options={})
    @name = options[:name]
    proxy = options[:proxy]

    @proxy_uri = case proxy
                 when :ENV      then proxy_from_env
                 when URI::HTTP then proxy
                 when nil       then # ignore
                 else raise ArgumentError, 'proxy must be :ENV or a URI::HTTP'
                 end

    if @proxy_uri then
      @proxy_args = [
        @proxy_uri.host,
        @proxy_uri.port,
        @proxy_uri.user,
        @proxy_uri.password,
      ]

      @proxy_connection_id = [nil, *@proxy_args].join ':'
    end

    @ca_file         = options[:ca_file]
    @certificate     = options[:certificate]
    @debug_output    = options[:debug_output]
    @force_retry     = options[:force_retry]
    @headers         = options[:header]          || {}
    @http_versions   = {}
    @keep_alive      = options[:keep_alive]      || 30
    @logger          = options[:logger]
    @open_timeout    = options[:open_timeout]
    @pool_size       = options[:pool_size]       || 1
    @private_key     = options[:private_key]
    @read_timeout    = options[:read_timeout]
    @verify_callback = options[:verify_callback]
    @verify_mode     = options[:verify_mode]
    @warn_timeout    = options[:warn_timeout]    || 0.5
    
    # Hash containing connection pools based on key of host:port
    @pool_hash = {}
    
    # Hash containing the request counts based on the connection
    @count_hash = Hash.new(0)
  end

  ##
  # Makes a request on +uri+.  If +req+ is nil a Net::HTTP::Get is performed
  # against +uri+.
  #
  # If a block is passed #request behaves like Net::HTTP#request (the body of
  # the response will not have been read).
  #
  # +req+ must be a Net::HTTPRequest subclass (see Net::HTTP for a list).
  #
  # If there is an error and the request is idempontent according to RFC 2616
  # it will be retried automatically.

  def request uri, req = nil, &block
    retried      = false
    bad_response = false

    req = Net::HTTP::Get.new uri.request_uri unless req

    headers.each do |pair|
      req.add_field(*pair)
    end

    req.add_field 'Connection', 'keep-alive'
    req.add_field 'Keep-Alive', @keep_alive

    pool = pool_for uri
    pool.with_connection do |connection|
      begin
        count = @count_hash[connection.object_id] += 1
        response = connection.request req, &block
        @http_versions["#{uri.host}:#{uri.port}"] ||= response.http_version
        return response

      rescue  Timeout::Error => e
        due_to = "(due to #{e.message} - #{e.class})"
        message = error_message connection
        @logger.info "Removing connection #{due_to} #{message}" if @logger
        remove pool, connection
        raise
        
      rescue Net::HTTPBadResponse => e
        message = error_message connection
        if bad_response or not (idempotent? req or @force_retry)
          @logger.info "Removing connection because of too many bad responses #{message}" if @logger
          remove pool, connection
          raise Error, "too many bad responses #{message}"
        else
          bad_response = true
          @logger.info "Renewing connection because of too many bad responses #{message}" if @logger
          connection = renew pool, connection
          retry
        end

      rescue IOError, EOFError, Errno::ECONNABORTED, Errno::ECONNRESET, Errno::EPIPE => e
        due_to = "(due to #{e.message} - #{e.class})"
        message = error_message connection
        if retried or not (idempotent? req or @force_retry)
          @logger.info "Removing connection #{due_to} #{message}" if @logger
          remove pool, connection
          raise Error, "too many connection resets #{due_to} #{message}"
        else
          retried = true
          @logger.info "Renewing connection #{due_to} #{message}" if @logger
          connection = renew pool, connection
          retry
        end
      end
    end
  end

  ##
  # Returns the HTTP protocol version for +uri+

  def http_version uri
    @http_versions["#{uri.host}:#{uri.port}"]
  end

  ##
  # Shuts down all connections.

  def shutdown
    raise 'Shutdown not implemented'
    # TBD - need to think about this one
    @count_hash = nil
  end

  #######
  private
  #######

  ##
  # Returns an error message containing the number of requests performed on
  # this connection

  def error_message connection
    requests = @count_hash[connection] || 0
    "after #{requests} requests on #{connection.object_id}"
  end

  ##
  # URI::escape wrapper

  def escape str
    URI.escape str if str
  end

  ##
  # Finishes the Net::HTTP +connection+

  def finish connection
    @count_hash.delete(connection.object_id)
    connection.finish
  rescue IOError
  end

  ##
  # Is +req+ idempotent according to RFC 2616?

  def idempotent? req
    case req
    when Net::HTTP::Delete, Net::HTTP::Get, Net::HTTP::Head,
         Net::HTTP::Options, Net::HTTP::Put, Net::HTTP::Trace then
      true
    end
  end

  ##
  # Adds "http://" to the String +uri+ if it is missing.

  def normalize_uri uri
    (uri =~ /^https?:/) ? uri : "http://#{uri}"
  end

  ##
  # Get the connection pool associated with this +uri+
  def pool_for uri
    net_http_args = [uri.host, uri.port]
    connection_id = net_http_args.join ':'

    if @proxy_uri then
      connection_id << @proxy_connection_id
      net_http_args.concat @proxy_args
    end
    @pool_hash[connection_id] ||= GenePool.new(:name         => connection_id,
                                               :pool_size    => @pool_size,
                                               :warn_timeout => @warn_timeout,
                                               :logger       => @logger) do
      begin
        connection = Net::HTTP.new(*net_http_args)
        connection.set_debug_output @debug_output if @debug_output
        connection.open_timeout = @open_timeout if @open_timeout
        connection.read_timeout = @read_timeout if @read_timeout

        ssl connection if uri.scheme == 'https'

        connection.start
        connection
      rescue Errno::ECONNREFUSED
        raise Error, "connection refused: #{connection.address}:#{connection.port}"
      rescue Errno::EHOSTDOWN
        raise Error, "host down: #{connection.address}:#{connection.port}"
      end
    end
  end

  ##
  # Creates a URI for an HTTP proxy server from ENV variables.
  #
  # If +HTTP_PROXY+ is set a proxy will be returned.
  #
  # If +HTTP_PROXY_USER+ or +HTTP_PROXY_PASS+ are set the URI is given the
  # indicated user and password unless HTTP_PROXY contains either of these in
  # the URI.
  #
  # For Windows users lowercase ENV variables are preferred over uppercase ENV
  # variables.

  def proxy_from_env
    env_proxy = ENV['http_proxy'] || ENV['HTTP_PROXY']

    return nil if env_proxy.nil? or env_proxy.empty?

    uri = URI.parse(normalize_uri(env_proxy))

    unless uri.user or uri.password then
      uri.user     = escape ENV['http_proxy_user'] || ENV['HTTP_PROXY_USER']
      uri.password = escape ENV['http_proxy_pass'] || ENV['HTTP_PROXY_PASS']
    end

    uri
  end

  ##
  # Finishes then removes the Net::HTTP +connection+

  def remove pool, connection
    finish connection
    pool.remove(connection)
  end

  ##
  # Finishes then renews the Net::HTTP +connection+.  It may be unnecessary 
  # to completely recreate the connection but connections that get timed out
  # in JRuby leave the ssl context in a frozen object state.

  def renew pool, connection
    finish connection
    connection = pool.renew(connection)
  end

  ##
  # Enables SSL on +connection+

  def ssl connection
    require 'net/https'
    connection.use_ssl = true

    # suppress warning but allow override
    connection.verify_mode = OpenSSL::SSL::VERIFY_NONE unless @verify_mode

    if @ca_file then
      connection.ca_file = @ca_file
      connection.verify_mode = OpenSSL::SSL::VERIFY_PEER
      connection.verify_callback = @verify_callback if @verify_callback
    end

    if @certificate and @private_key then
      connection.cert = @certificate
      connection.key  = @private_key
    end

    connection.verify_mode = @verify_mode if @verify_mode
  end
  
end

