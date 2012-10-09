#custom includes
include "backends.vcl";
include "acl.vcl";

       	# recieving sub
       	sub vcl_recv {

### parse accept encoding rulesets to normalize
        if (req.http.Accept-Encoding) {
                if (req.url ~ "\.(jpg|jpeg|png|gif|gz|tgz|bz2|tbz|mp3|ogg|swf|mp4|flv)$") {
                        # don'tcompress already compressed files
                        remove req.http.Accept-Encoding;
                } elsif (req.http.Accept-Encoding ~ "gzip") {
                        set req.http.Accept-Encoding = "gzip";
                } elsif (req.http.Accept-Encoding ~ "deflate") {
                        set req.http.Accept-Encoding = "deflate";
                } else {
                        # unkown algorithm
                        remove req.http.Accept-Encoding;
                }
        }

#Define where my blog goes
if (req.http.host ~ "^(www\.)?k0nsl\.org$") {
        set req.backend = server1;
        return (lookup);
}

#Client on dedicated IP
if (req.http.host ~ "^(www\.)?forbundet\.info$") {
        set req.backend = server2;
        #I'm not caching it until everything is top-notch (send to pipe instead of pass)
        return (pipe);
        #return (lookup);
}

#Client on shared IP
if (req.http.host ~ "^(www\.)?jubbads\.com$") {
        set req.backend = server1;
        #I'm not caching this either until all is working 100%
        return (pipe);
        #return (lookup);
}

# always pass through posted requests and those with basic auth
#if ( req.request == "POST" || req.http.Authorization ) {
#return (pass);
#}
  #send this to pipe (append X-Forwarded-For)
  if (req.request == "POST")
  {
    return(pipe);
  }

    # don't cache authenticated sessions
    if (req.http.Cookie && req.http.Cookie ~ "(wordpress_|PHPSESSID)") {
        return(lookup);
    }

  # CloudFlare
  remove req.http.X-Forwarded-For;
  if (req.http.CF-Connecting-IP) {
    set req.http.X-Forwarded-For = req.http.CF-Connecting-IP;
  } else {
    set req.http.X-Forwarded-For = client.ip;
  }
               	if (!(req.url ~ "wp-(login|admin)")) {
                       	unset req.http.cookie;
               	}
### do not cache these rules:

        if (req.request != "GET" && req.request != "HEAD") {
                return (pipe);
        }
        if (req.http.Authenticate || req.http.Authorization) {
                return (pass);
        }

### don't cache authenticated sessions
        if (req.http.Cookie && req.http.Cookie ~ "authtoken=") {
                return ( pipe);
        }

### if there is a purge make sure its coming from anything in ACL "purge"

	if (req.request == "PURGE") {
	    if (!client.ip ~ purge) {
                error 405 "Not allowed.";
                }
                return (lookup);
        }

### if it passes all these tests, do a lookup anyway;
        return (lookup);

### end of vcl_recv
       	}

       	# Drop any cookies Wordpress tries to send back to the client.
       	sub vcl_fetch {
               	if (!(req.url ~ "wp-(login|admin)")) {
                       	unset beresp.http.set-cookie;
                        ## Remove the http.Server header
                        unset beresp.http.Server;
                        set beresp.http.Server = "k0nslified (cache.k0nsl.org)/1.1b";
               	}

    # These status codes should always pass through and never cache.
    if (beresp.status == 404 || beresp.status == 503 || beresp.status == 500) {
        set beresp.http.X-Cacheable = "NO: beresp.status";
        set beresp.http.X-Cacheable-status = beresp.status;
        return (hit_for_pass);
     }
       	}

sub vcl_deliver {
        remove resp.http.X-Varnish;
        remove resp.http.Via;
        remove resp.http.Age;
    return (deliver);
}

sub vcl_error {
    set obj.http.Content-Type = "text/html; charset=utf-8";
    if (obj.status == 404) {
        synthetic {"
            <!-- 404 -->
            <div style="position:fixed;top:0;left:0;width:100%;height:100%;z-index:-1;">
    <img alt="" src="http://k0nsl.org/static/me-gusta-me-culpa_k0nsl.png" style="width:100%;height:100%" /></div>
        "};
    } else if (obj.status == 500) {
        synthetic {"
            <!-- 500 -->
            <div style="position:fixed;top:0;left:0;width:100%;height:100%;z-index:-1;">
    <img alt="" src="http://k0nsl.org/static/me-gusta-me-culpa_k0nsl.png" style="width:100%;height:100%" /></div>
        "};
    } else if (obj.status == 503) {
        synthetic {"
            <!-- 503 -->
            <div style="position:fixed;top:0;left:0;width:100%;height:100%;z-index:-1;">
    <img alt="" src="http://k0nsl.org/static/me-gusta-me-culpa_k0nsl.png" style="width:100%;height:100%" /></div>
        "};

    } else {
        synthetic {"
            <!-- generic -->
            <div style="position:fixed;top:0;left:0;width:100%;height:100%;z-index:-1;">
    <img alt="" src="http://k0nsl.org/static/me-gusta-me-culpa_k0nsl.png" style="width:100%;height:100%" /></div>
        "};
    }
}

#sub vcl_pipe {
  # http://www.varnish-cache.org/ticket/451
  # This forces every pipe request to be the first one.
#  set bereq.http.connection = "close";
#}

#Append X-Forwarded-For
sub vcl_pipe {
  set bereq.http.Connection = "close";
  set bereq.http.X-Forwarded-For = req.http.X-Forwarded-For;
  if (bereq.http.x-forwarded-for) {
    set bereq.http.X-Forwarded-For = bereq.http.X-Forwarded-For + ", " + client.ip;
  } else {
    set bereq.http.X-Forwarded-For = client.ip;
  }
  return (pipe);
}
