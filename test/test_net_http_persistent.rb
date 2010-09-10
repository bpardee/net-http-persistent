require 'rubygems'
require 'minitest/autorun'
require 'net/http/persistent'
require 'openssl'
require 'stringio'
require 'ostruct'
require 'logger'

CMD_SUCCESS      = 'success'
CMD_SLEEP        = 'sleep'
CMD_BAD_RESPONSE = 'bad_response'
CMD_EOF_ERROR    = 'eof_error'
CMD_CONNRESET    = 'connreset'
CMD_ECHO         = 'echo'

PASS = 'pass'
FAIL = 'fail'

DUMMY_OPEN_TIMEOUT_FOR_HOSTDOWN    = 9000
DUMMY_OPEN_TIMEOUT_FOR_CONNREFUSED = 9001

$debug = false

class Net::HTTP
  def connect
    raise Errno::EHOSTDOWN    if open_timeout == DUMMY_OPEN_TIMEOUT_FOR_HOSTDOWN
    raise Errno::ECONNREFUSED if open_timeout == DUMMY_OPEN_TIMEOUT_FOR_CONNREFUSED
  end

  def successful_response
    r = Net::HTTPResponse.allocate
    def r.http_version() '1.1' end
    def r.read_body() :read_body end
    yield r if block_given?
    r
  end

  def request(req, &block)
    $count += 1
    puts "path=#{req.path} count=#{$count}" if $debug
    args = req.path[1..-1].split('/')
    cmd = args.shift
    i = $count % args.size if args.size > 0
    puts "i=#{i}" if $debug
    if cmd == CMD_ECHO
      res = successful_response(&block)
      eval "def res.body() \"#{req.body}\" end"
      return res
    elsif cmd == CMD_SUCCESS || args[i] == PASS
      return successful_response(&block)
    end
    case cmd
    when CMD_SLEEP
      sleep args[i].to_i
      return successful_response(&block)
    when CMD_BAD_RESPONSE
      raise Net::HTTPBadResponse.new('Dummy bad response') 
    when CMD_EOF_ERROR
      raise EOFError.new('Dummy EOF error') 
    when CMD_CONNRESET
      raise Errno::ECONNRESET
    else
      return successful_response(&block)
    end 
  end
end

class Net::HTTP::Persistent
  attr_reader :pool_hash
  
  # Make private methods public
  send(:public, *(self.private_instance_methods - Object.private_instance_methods))
end

class TestNetHttpPersistent < MiniTest::Unit::TestCase

  def uri_for(*args)
    URI.parse("http://example.com/#{args.join('/')}")
  end
  
  def request_command(req, *args)
    puts "uri=#{uri_for(args)}" if $debug
    @http.request(uri_for(args), req)
  end
  
  def http_and_io(options={})
    io = StringIO.new
    logger = Logger.new(io)
    logger.level = Logger::INFO
    default_options = {:name => 'TestNetHTTPPersistent', :logger => logger, :pool_size => 1}
    http = Net::HTTP::Persistent.new(default_options.merge(options))
    [http, io]
  end

  def setup
    $count = -1
    @http, @io = http_and_io
    @uri  = uri_for CMD_SUCCESS

    ENV.delete 'http_proxy'
    ENV.delete 'HTTP_PROXY'
    ENV.delete 'http_proxy_user'
    ENV.delete 'HTTP_PROXY_USER'
    ENV.delete 'http_proxy_pass'
    ENV.delete 'HTTP_PROXY_PASS'
  end

  def teardown
  end

  def test_initialize
    assert_nil @http.proxy_uri
  end

  def test_initialize_name
    http = Net::HTTP::Persistent.new(:name => 'name')
    assert_equal 'name', http.name
  end

  def test_initialize_env
    ENV['HTTP_PROXY'] = 'proxy.example'
    http = Net::HTTP::Persistent.new(:proxy => :ENV)

    assert_equal URI.parse('http://proxy.example'), http.proxy_uri
  end

  def test_initialize_uri
    proxy_uri = URI.parse 'http://proxy.example'

    http = Net::HTTP::Persistent.new(:proxy => proxy_uri)

    assert_equal proxy_uri, http.proxy_uri
  end

  def test_connection
    @http.open_timeout = 123
    @http.read_timeout = 321
    pool = @http.pool_for @uri
    assert_same pool, @http.pool_hash['example.com:80']
    pool.with_connection do |c|
      assert c.started?
      refute c.proxy?

      assert_equal 123, c.open_timeout
      assert_equal 321, c.read_timeout
      
      assert_equal 'example.com', c.address
      assert_equal 80, c.port
    end
  end

  def test_connection_for_cached
    c1, c2 = nil, nil
    pool = @http.pool_for @uri
    assert_same pool, @http.pool_hash['example.com:80']
    pool.with_connection do |c|
      c1 = c
      assert c.started?
    end
    pool.with_connection do |c|
      c2 = c
      assert c.started?
    end
    assert_same c1,c2
  end

  def test_connection_for_debug_output
    io = StringIO.new
    @http.debug_output = io

    pool = @http.pool_for @uri
    assert_same pool, @http.pool_hash['example.com:80']
    pool.with_connection do |c|
      assert c.started?
      assert_equal io, c.instance_variable_get(:@debug_output)
      assert_equal 'example.com', c.address
      assert_equal 80, c.port
    end
  end

  def test_connection_for_hostdown
    @http.open_timeout = DUMMY_OPEN_TIMEOUT_FOR_HOSTDOWN
    e = assert_raises Net::HTTP::Persistent::Error do
      request_command(nil, CMD_SUCCESS)
    end

    assert_match %r%host down%, e.message
  end

  def test_connection_for_connrefused
    @http.open_timeout = DUMMY_OPEN_TIMEOUT_FOR_CONNREFUSED
    e = assert_raises Net::HTTP::Persistent::Error do
      request_command(nil, CMD_SUCCESS)
    end

    assert_match %r%connection refused%, e.message
  end

  def test_connection_for_proxy
    uri = URI.parse 'http://proxy.example'
    uri.user     = 'johndoe'
    uri.password = 'muffins'

    http = Net::HTTP::Persistent.new(:proxy => uri)
    pool = http.pool_for(@uri)
    assert_same pool, http.pool_hash['example.com:80:proxy.example:80:johndoe:muffins']
    pool.with_connection do |c|
      assert c.started?
      assert c.proxy?
    end
  end

  def test_error_message
    6.times do
      request_command nil, CMD_EOF_ERROR, PASS, PASS, PASS, PASS, FAIL, PASS, PASS
    end

    assert_match "after 5 requests on", @io.string
  end

  def test_escape
    assert_nil @http.escape nil

    assert_equal '%20', @http.escape(' ')
  end

  def test_finish
    c = Object.new
    def c.finish; @finished = true end
    def c.finished?; @finished end
    def c.start; @started = true end
    def c.started?; @started end

    @http.finish c

    refute c.started?
    assert c.finished?
  end

  def test_finish_io_error
    c = Object.new
    def c.finish; @finished = true; raise IOError end
    def c.finished?; @finished end
    def c.start; @started = true end
    def c.started?; @started end

    @http.finish c

    refute c.started?
    assert c.finished?
  end
    
  def test_http_version
    assert_nil @http.http_version @uri
  
    request_command nil, CMD_SUCCESS
  
    assert_equal '1.1', @http.http_version(@uri)
  end
  
  def test_idempotent_eh
    assert @http.idempotent? Net::HTTP::Delete.new '/'
    assert @http.idempotent? Net::HTTP::Get.new '/'
    assert @http.idempotent? Net::HTTP::Head.new '/'
    assert @http.idempotent? Net::HTTP::Options.new '/'
    assert @http.idempotent? Net::HTTP::Put.new '/'
    assert @http.idempotent? Net::HTTP::Trace.new '/'
  
    refute @http.idempotent? Net::HTTP::Post.new '/'
  end
  
  def test_normalize_uri
    assert_equal 'http://example',  @http.normalize_uri('example')
    assert_equal 'http://example',  @http.normalize_uri('http://example')
    assert_equal 'https://example', @http.normalize_uri('https://example')
  end
  
  def test_proxy_from_env
    ENV['HTTP_PROXY']      = 'proxy.example'
    ENV['HTTP_PROXY_USER'] = 'johndoe'
    ENV['HTTP_PROXY_PASS'] = 'muffins'
  
    uri = @http.proxy_from_env
  
    expected = URI.parse 'http://proxy.example'
    expected.user     = 'johndoe'
    expected.password = 'muffins'
  
    assert_equal expected, uri
  end
  
  def test_proxy_from_env_lower
    ENV['http_proxy']      = 'proxy.example'
    ENV['http_proxy_user'] = 'johndoe'
    ENV['http_proxy_pass'] = 'muffins'
  
    uri = @http.proxy_from_env
  
    expected = URI.parse 'http://proxy.example'
    expected.user     = 'johndoe'
    expected.password = 'muffins'
  
    assert_equal expected, uri
  end
  
  def test_proxy_from_env_nil
    uri = @http.proxy_from_env
  
    assert_nil uri
  
    ENV['HTTP_PROXY'] = ''
  
    uri = @http.proxy_from_env
  
    assert_nil uri
  end
  
  def test_remove
    http, io = http_and_io(:pool_size => 3)
    request_command(nil, CMD_SUCCESS)
    pool = http.pool_for(@uri)
    2.times do
      conns = []
      pool.with_connection do |c1|
        pool.with_connection do |c2|
          conns << c2
          pool.with_connection do |c3|
            conns << c3
            begin
              Timeout.timeout(2) do
                pool.with_connection { |c4| }
                flunk('should NOT have been able to get 4th connection')
              end
            rescue  Timeout::Error => e
              pass('successfully failed to get a connection')
            end
            http.remove(pool, c1)
            Timeout.timeout(1) do
              begin
                pool.with_connection do |c4|
                  conns << c4
                end
              rescue  Timeout::Error => e
                flunk('should have been able to get 4th connection')
              end
            end
          end
        end
      end
      pool.with_connection do |c1|
        pool.with_connection do |c2|
          pool.with_connection do |c3|
            assert_equal conns, [c1,c2,c3]
          end
        end
      end
      # Do it a 2nd time with finish returning an IOError
      c1 = conns[0]
      def c1.finish
        super
        raise IOError
      end
    end
  end

  def test_renew
    http, io = http_and_io(:pool_size => 3)
    request_command(nil, CMD_SUCCESS)
    pool = http.pool_for(@uri)
    2.times do
      conns = []
      pool.with_connection do |c1|
        pool.with_connection do |c2|
          conns << c2
          pool.with_connection do |c3|
            conns << c3
            new_c1 = http.renew(pool, c1)
            refute_equal(c1, new_c1)
            conns.unshift(new_c1)
          end
        end
      end
      pool.with_connection do |c1|
        pool.with_connection do |c2|
          pool.with_connection do |c3|
            assert_equal conns, [c1,c2,c3]
          end
        end
      end
      # Do it a 2nd time with finish returning an IOError
      c1 = conns[0]
      def c1.finish
        super
        raise IOError
      end
    end
  end
  
  def test_renew_with_exception
    http, io = http_and_io(:pool_size => 2)
    pool = http.pool_for(@uri)
    [[DUMMY_OPEN_TIMEOUT_FOR_HOSTDOWN, %r%host down%], [DUMMY_OPEN_TIMEOUT_FOR_CONNREFUSED, %r%connection refused%]].each do |pair|
      dummy_open_timeout = pair.first
      error_message = pair.last
      pool.with_connection do |c|
        old_c = c
        http.open_timeout = dummy_open_timeout
        e = assert_raises Net::HTTP::Persistent::Error do
          new_c = http.renew pool, c
        end
        assert_match error_message, e.message
      
        # Make sure our pool is still in good shape
        http.open_timeout = 5   # Any valid timeout will do
        pool.with_connection do |c1|
          refute_equal old_c, c1
          pool.with_connection do |c2|
            refute_equal old_c, c2
          end
        end
      end
    end
  end
   
  def test_request
    @http.headers['user-agent'] = 'test ua'
    req = Net::HTTP::Get.new(@uri.request_uri)
    res = @http.request(@uri, req)
  
    assert_kind_of Net::HTTPResponse, res
  
    assert_kind_of Net::HTTP::Get, req
    assert_equal @uri.path,    req.path
    assert_equal 'keep-alive', req['connection']
    assert_equal '30',         req['keep-alive']
    assert_match %r%test ua%,  req['user-agent']
  end
  
  def test_request_block
    @http.headers['user-agent'] = 'test ua'
    body = nil
    
    req = Net::HTTP::Get.new(@uri.request_uri)
    res = @http.request(@uri, req) do |r|
      body = r.read_body
    end
  
    assert_kind_of Net::HTTPResponse, res
    refute_nil body
  
    assert_kind_of Net::HTTP::Get, req
    assert_equal @uri.path,    req.path
    assert_equal 'keep-alive', req['connection']
    assert_equal '30',         req['keep-alive']
    assert_match %r%test ua%,  req['user-agent']
  end

  def test_request_bad_response
    e = assert_raises Net::HTTP::Persistent::Error do
      request_command nil, CMD_BAD_RESPONSE, FAIL, FAIL
    end
    assert_match %r%too many bad responses%, e.message
    assert_match %r%Renewing connection because of bad response%, @io.string
    assert_match %r%Removing connection because of too many bad responses%, @io.string

    res = request_command nil, CMD_SUCCESS
    assert_kind_of Net::HTTPResponse, res
  end

  def test_request_connreset
    e = assert_raises Net::HTTP::Persistent::Error do
      request_command nil, CMD_CONNRESET, FAIL, FAIL
    end
  
    assert_match %r%too many connection resets%, e.message
    assert_match %r%Renewing connection %, @io.string
    assert_match %r%Removing connection %, @io.string

    res = request_command nil, CMD_SUCCESS
    assert_kind_of Net::HTTPResponse, res
  end
  
  def test_request_bad_response_retry
    res = request_command nil, CMD_BAD_RESPONSE, FAIL, PASS
    assert_match %r%Renewing connection because of bad response%, @io.string
    assert_kind_of Net::HTTPResponse, res
  end
 
  def test_request_connreset_retry
    res = request_command nil, CMD_CONNRESET, FAIL, PASS
    assert_match %r%Renewing connection %, @io.string
    assert_kind_of Net::HTTPResponse, res
  end

  def test_request_bad_response_post
    uri = uri_for CMD_BAD_RESPONSE, FAIL, PASS
    post = Net::HTTP::Post.new(uri.request_uri)
    e = assert_raises Net::HTTP::Persistent::Error do
      request_command post, CMD_BAD_RESPONSE, FAIL, PASS
    end
    assert_match %r%too many bad responses%, e.message
    assert_match %r%Removing connection because of too many bad responses%, @io.string

    res = request_command nil, CMD_SUCCESS
    assert_kind_of Net::HTTPResponse, res
  end

  
  def test_request_connreset_post
    uri = uri_for CMD_CONNRESET, FAIL, PASS
    post = Net::HTTP::Post.new(uri.request_uri)
    e = assert_raises Net::HTTP::Persistent::Error do
      request_command post, CMD_CONNRESET, FAIL, PASS
    end
    assert_match %r%too many connection resets%, e.message
    assert_match %r%Removing connection %, @io.string

    res = request_command nil, CMD_SUCCESS
    assert_kind_of Net::HTTPResponse, res
  end
  
  def test_request_bad_response_post_force_retry
    @http.force_retry = true
    uri = uri_for CMD_BAD_RESPONSE, FAIL, PASS
    post = Net::HTTP::Post.new(uri.request_uri)
    res = request_command post, CMD_BAD_RESPONSE, FAIL, PASS
    assert_match %r%Renewing connection because of bad response%, @io.string
    assert_kind_of Net::HTTPResponse, res
  end
    
  def test_request_connreset_post_force_retry
    @http.force_retry = true
    uri = uri_for CMD_CONNRESET, FAIL, PASS
    post = Net::HTTP::Post.new(uri.request_uri)
    res = request_command post, CMD_CONNRESET, FAIL, PASS
    assert_match %r%Renewing connection %, @io.string
    assert_kind_of Net::HTTPResponse, res
  end
  
  def test_request_post
    uri = uri_for CMD_ECHO
    post = Net::HTTP::Post.new(uri.request_uri)
    post.body = 'hello Net::HTTP::Persistent'
    res = request_command post, CMD_ECHO
    assert_kind_of Net::HTTPResponse, res
    assert_equal post.body, res.body
  end
  
  # def test_shutdown
  #   c = connection
  #   cs = conns
  #   rs = reqs
  # 
  #   orig = @http
  #   @http = Net::HTTP::Persistent.new 'name'
  #   c2 = connection
  # 
  #   orig.shutdown
  # 
  #   assert c.finished?
  #   refute c2.finished?
  # 
  #   refute_same cs, conns
  #   refute_same rs, reqs
  # end
  # 
  # def test_shutdown_not_started
  #   c = Object.new
  #   def c.finish() raise IOError end
  # 
  #   conns["#{@uri.host}:#{@uri.port}"] = c
  # 
  #   @http.shutdown
  # 
  #   assert_nil Thread.current[@http.connection_key]
  #   assert_nil Thread.current[@http.request_key]
  # end
  # 
  # def test_shutdown_no_connections
  #   @http.shutdown
  # 
  #   assert_nil Thread.current[@http.connection_key]
  #   assert_nil Thread.current[@http.request_key]
  # end
  
  def test_ssl
    @http.verify_callback = :callback
    c = Net::HTTP.new 'localhost', 80
  
    @http.ssl c
  
    assert c.use_ssl?
    assert_equal OpenSSL::SSL::VERIFY_NONE, c.verify_mode
    assert_nil c.verify_callback
  end
  
  def test_ssl_ca_file
    @http.ca_file = 'ca_file'
    @http.verify_callback = :callback
    c = Net::HTTP.new 'localhost', 80
  
    @http.ssl c
  
    assert c.use_ssl?
    assert_equal OpenSSL::SSL::VERIFY_PEER, c.verify_mode
    assert_equal :callback, c.verify_callback
  end
  
  def test_ssl_certificate
    @http.certificate = :cert
    @http.private_key = :key
    c = Net::HTTP.new 'localhost', 80
  
    @http.ssl c
  
    assert c.use_ssl?
    assert_equal :cert, c.cert
    assert_equal :key,  c.key
  end
  
  def test_ssl_verify_mode
    @http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    c = Net::HTTP.new 'localhost', 80
  
    @http.ssl c
  
    assert c.use_ssl?
    assert_equal OpenSSL::SSL::VERIFY_NONE, c.verify_mode
  end
end

