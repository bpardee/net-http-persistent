= net_http_persistent

* http://seattlerb.rubyforge.org/net-http-persistent

== DESCRIPTION:

Persistent connections using Net::HTTP plus a speed fix for 1.8.  It's
thread-safe too!

== FORK DESCRIPTION

This is an experimental branch that implements a connection pool of 
Net::HTTP objects instead of a connection/thread.  C/T is fine if
you're only using your http threads to make connections but if you 
use them in child threads then I suspect you will have a thread memory
leak.  Also, I want to see if I get less connection resets if the
most recently used connection is always returned.

Also added a :force_retry option that if set to true will retry POST
requests as well as idempotent requests.

This branch is currently incompatible with the master branch in the 
following ways:

* It doesn't allow you to recreate the Net::HTTP::Persistent object
  on the fly.  This is possible in the master version since all the 
  data is kept in thread local storage.  For this version, you should
  probably create a class instance of the object and use that in your
  instance methods.

* It uses a hash in the initialize method.  This was easier for me
  as I use a HashWithIndifferentAccess created from a YAML file to 
  define my options.  This should probably be modified to check the
  arguments to achieve backwards compatibility.

* The method shutdown is unimplemented as I wasn't sure how I should
  implement it and I don't need it as I do a graceful shutdown from 
  nginx to finish up my connections.

For connection issues, I completely recreate a new Net::HTTP instance.
I was running into an issue which I suspect is a JRuby bug where an
SSL connection that times out would leave the ssl context in a frozen
state which would then make that connection unusable so each time that
thread handled a connection a 500 error with the exception "TypeError:
can't modify frozen".  I think Joseph West's fork resolves this issue
but I'm paranoid so I recreate the object.

Compatibility with the master version could probably be achieved by
creating a Strategy wrapper class for GenePool and a separate strategy
class with the connection/thread implementation.

== FEATURES/PROBLEMS:

* Supports SSL
* Thread-safe
* Pure ruby
* Timeout-less speed boost for 1.8 (by Aaron Patterson)

== INSTALL:

  gem install bpardee-net-http-persistent

== EXAMPLE USAGE:

  class MyHttpClient
    @@http ||= Net::HTTP::Persistent.new(
      :name         => 'MyHttpClient',
      :logger       => Rails.logger,
      :pool_size    => 10,
      :warn_timeout => 0.25,
      :force_retry  => true
    )

    def send_get_message
      uri = URI.parse('https://www.example.com/echo/foo')
      response = @@http.request(uri)
      ... Handle response as you would a normal Net::HTTPResponse ...
    end

    def send_post_message
      uri = URI.parse('https://www.example.com/echo/foo')
      request = Net::HTTP::Post.new(uri.request_uri)
      ... Modify request as needed ...
      response = @@http.request(uri, request)
      ... Handle response as you would a normal Net::HTTPResponse ...
    end
  end

== LICENSE:

(The MIT License)

Copyright (c) 2010 Eric Hodel, Aaron Patterson

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
